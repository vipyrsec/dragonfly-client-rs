use std::{
    collections::HashMap,
    error::Error as StdError,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use color_eyre::{
    eyre::{bail, ensure, Context},
    Result,
};
use reqwest::{blocking::Client, Url};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::{tempdir, tempfile, TempDir};
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::{
    app_config::APP_CONFIG,
    client::{
        build_api_http_client, build_download_http_client, download_distribution_with_timeout,
        fetch_opengrep_jobs, fetch_opengrep_rules, send_opengrep_result, Job, OpenGrepFinding,
        OpenGrepRulesResponse, OpenGrepScanResult, SubmitOpenGrepResultsError,
        SubmitOpenGrepResultsSuccess,
    },
    utils::create_inspector_url,
};

const STAGING_ORIGIN: &str = "https://dragonfly-staging.vipyrsec.com";
const MAX_FINDINGS: usize = 500;
const MAX_OPENGREP_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const SCAN_DEADLINE: Duration = Duration::from_secs(60);
const RULE_INSPECTION_DEADLINE: Duration = Duration::from_secs(10);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Deserialize)]
struct Position {
    line: u64,
}

#[derive(Debug, Deserialize)]
struct FindingMetadata {
    evidence: String,
    confidence: String,
    execution_context: String,
}

#[derive(Debug, Deserialize)]
struct FindingExtra {
    message: String,
    severity: String,
    metadata: FindingMetadata,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    check_id: String,
    path: PathBuf,
    start: Position,
    end: Position,
    extra: FindingExtra,
}

#[derive(Debug, Deserialize)]
struct OpenGrepDocument {
    results: Vec<RawFinding>,
    #[serde(default)]
    errors: Vec<Value>,
    #[serde(default)]
    skipped_rules: Vec<Value>,
}

#[derive(Debug)]
struct ScanTimeout(&'static str);

impl std::fmt::Display for ScanTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl StdError for ScanTimeout {}

#[derive(Debug)]
struct OpenGrepRun {
    findings: Vec<OpenGrepFinding>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct ScanJobOutcome {
    findings: Vec<OpenGrepFinding>,
    partial_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    digest: [u8; 32],
    extension: Option<OsString>,
}

#[derive(Debug, Default)]
struct PackageScanCache {
    findings_by_file: HashMap<FileIdentity, Vec<OpenGrepFinding>>,
}

#[derive(Debug)]
struct RetainedFile {
    identity: FileIdentity,
    path: String,
}

#[derive(Debug)]
struct ReusedFile {
    findings: Vec<OpenGrepFinding>,
    path: String,
}

#[derive(Debug)]
struct TargetPlan {
    retained: Vec<RetainedFile>,
    local_aliases: Vec<(String, String)>,
    reused: Vec<ReusedFile>,
}

impl TargetPlan {
    fn deduplicated_files(&self) -> usize {
        self.local_aliases.len() + self.reused.len()
    }
}

pub struct OpenGrepClient {
    api_client: Client,
    download_client: Client,
    base_url: String,
    binary: PathBuf,
    rules_directory: TempDir,
    content_reuse_safe: bool,
    pub rules_hash: String,
}

impl OpenGrepClient {
    /// Build a staging-pinned shadow client and load its initial corpus.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin fence, HTTP clients, rule retrieval,
    /// or safe rule materialization fails.
    pub fn new(binary: PathBuf) -> Result<Self> {
        validate_staging_origin(&APP_CONFIG.base_url)?;
        let api_client = build_api_http_client(
            &APP_CONFIG.cf_access_client_id,
            &APP_CONFIG.cf_access_client_secret,
        )?;
        let download_client = build_download_http_client()?;
        let response = fetch_opengrep_rules(&api_client, &APP_CONFIG.base_url)?;
        let rules_hash = response.hash.clone();
        let rules_directory = materialize_rules(&response)?;
        let content_reuse_safe = rules_allow_content_reuse(&binary, rules_directory.path())?;
        Ok(Self {
            api_client,
            download_client,
            base_url: APP_CONFIG.base_url.trim_end_matches('/').to_owned(),
            binary,
            rules_directory,
            content_reuse_safe,
            rules_hash,
        })
    }

    /// Replace the local `OpenGrep` corpus from Mainframe.
    ///
    /// # Errors
    ///
    /// Returns an error when retrieval or safe materialization fails.
    pub fn refresh_rules(&mut self) -> Result<()> {
        let response = fetch_opengrep_rules(&self.api_client, &self.base_url)?;
        let rules_directory = materialize_rules(&response)?;
        let content_reuse_safe = rules_allow_content_reuse(&self.binary, rules_directory.path())?;
        self.rules_hash = response.hash;
        self.rules_directory = rules_directory;
        self.content_reuse_safe = content_reuse_safe;
        Ok(())
    }

    /// Lease up to `count` `OpenGrep` shadow jobs.
    ///
    /// # Errors
    ///
    /// Returns an HTTP or response-deserialization error.
    pub fn get_jobs(&self, count: usize) -> reqwest::Result<Vec<Job>> {
        fetch_opengrep_jobs(&self.api_client, &self.base_url, count)
    }

    /// Scan one job and convert every failure into a bounded result payload.
    #[must_use]
    pub fn run_job(&self, job: &Job) -> OpenGrepScanResult {
        let started_at = Instant::now();
        let result = self.scan_job(job);
        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(outcome) => OpenGrepScanResult::Success(SubmitOpenGrepResultsSuccess {
                name: job.name.clone(),
                version: job.version.clone(),
                attempt: job.attempt,
                assignment_id: job.assignment_id.clone(),
                commit: job.hash.clone(),
                duration_ms,
                findings: outcome.findings,
                partial_reason: outcome.partial_reason,
            }),
            Err(error) => OpenGrepScanResult::Error(SubmitOpenGrepResultsError {
                name: job.name.clone(),
                version: job.version.clone(),
                attempt: job.attempt,
                assignment_id: job.assignment_id.clone(),
                duration_ms,
                reason: truncate(&format!("{error:#}"), 2048),
            }),
        }
    }

    /// Submit one completed `OpenGrep` shadow result.
    ///
    /// # Errors
    ///
    /// Returns an HTTP or serialization error.
    pub fn submit_result(&self, result: &OpenGrepScanResult) -> reqwest::Result<()> {
        send_opengrep_result(&self.api_client, &self.base_url, result)
    }

    fn scan_job(&self, job: &Job) -> Result<ScanJobOutcome> {
        ensure!(
            job.distributions.len() <= APP_CONFIG.max_distributions,
            "package contains {} distributions, exceeding the {}-distribution limit",
            job.distributions.len(),
            APP_CONFIG.max_distributions
        );
        let mut findings = Vec::new();
        let mut warnings = Vec::new();
        let mut package_cache = PackageScanCache::default();
        for distribution in &job.distributions {
            let distribution_started_at = Instant::now();
            let download_url: Url = distribution.parse()?;
            let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);
            let directory = match download_distribution_with_timeout(
                &self.download_client,
                download_url,
                Some(SCAN_DEADLINE),
            ) {
                Ok(directory) => directory,
                Err(error) if is_timeout_error(&error) => {
                    warnings.push(format!(
                        "Timed out downloading or extracting distribution {distribution}"
                    ));
                    break;
                }
                Err(error) => return Err(error),
            };
            let distribution_deadline = distribution_started_at + SCAN_DEADLINE;
            let Some(target_plan) = prepare_distribution_target(
                directory.path(),
                &package_cache,
                self.content_reuse_safe,
                distribution_deadline,
            )?
            else {
                warnings.push(format!("Timed out preparing distribution {distribution}"));
                break;
            };
            let deduplicated_files = target_plan.deduplicated_files();
            if deduplicated_files > 0 {
                info!(
                    package = %job.name,
                    version = %job.version,
                    deduplicated_files,
                    "Reused file results before OpenGrep scan"
                );
            }
            let reused_findings = synthesize_reused_findings(&target_plan, &inspector_url)?;
            let Some(remaining) = SCAN_DEADLINE.checked_sub(distribution_started_at.elapsed())
            else {
                append_findings(&mut findings, reused_findings)?;
                warnings.push(format!("Timed out preparing distribution {distribution}"));
                break;
            };
            if target_plan.retained.is_empty() {
                append_findings(&mut findings, reused_findings)?;
                continue;
            }
            let distribution_run = match run_opengrep(
                &self.binary,
                self.rules_directory.path(),
                directory.path(),
                &inspector_url,
                remaining,
            ) {
                Ok(run) => run,
                Err(error) if is_timeout_error(&error) => {
                    append_findings(&mut findings, reused_findings)?;
                    warnings.push(format!("Timed out scanning distribution {distribution}"));
                    break;
                }
                Err(error) => return Err(error),
            };
            let alias_findings = synthesize_local_alias_findings(
                &target_plan,
                &distribution_run.findings,
                &inspector_url,
            )?;
            if distribution_run.warnings.is_empty() {
                cache_completed_file_results(
                    &target_plan,
                    &distribution_run.findings,
                    &mut package_cache,
                );
            }
            append_findings(&mut findings, distribution_run.findings)?;
            append_findings(&mut findings, reused_findings)?;
            append_findings(&mut findings, alias_findings)?;
            warnings.extend(distribution_run.warnings);
        }
        let partial_reason = (!warnings.is_empty()).then(|| truncate(&warnings.join("; "), 2048));
        Ok(ScanJobOutcome {
            findings,
            partial_reason,
        })
    }
}

fn append_findings(
    findings: &mut Vec<OpenGrepFinding>,
    additional: Vec<OpenGrepFinding>,
) -> Result<()> {
    ensure!(
        findings.len().saturating_add(additional.len()) <= MAX_FINDINGS,
        "OpenGrep produced more than {MAX_FINDINGS} findings"
    );
    findings.extend(additional);
    Ok(())
}

/// Require the exact staging API origin without paths, credentials, or queries.
///
/// # Errors
///
/// Returns an error when the URL is invalid or is not the staging origin.
pub fn validate_staging_origin(base_url: &str) -> Result<()> {
    let parsed = Url::parse(base_url)?;
    let expected = Url::parse(STAGING_ORIGIN)?;
    ensure!(
        parsed.scheme() == expected.scheme()
            && parsed.host_str() == expected.host_str()
            && parsed.port_or_known_default() == expected.port_or_known_default()
            && parsed.path().trim_end_matches('/').is_empty()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "OpenGrep shadow worker requires the staging API origin"
    );
    Ok(())
}

fn materialize_rules(response: &OpenGrepRulesResponse) -> Result<TempDir> {
    ensure!(!response.rules.is_empty(), "OpenGrep rule corpus is empty");
    let directory = tempdir()?;
    for (relative_path, contents) in &response.rules {
        let relative_path = safe_relative_path(relative_path)?;
        let destination = directory.path().join(relative_path);
        let parent = destination
            .parent()
            .ok_or_else(|| color_eyre::eyre::eyre!("OpenGrep rule path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(destination, contents)?;
    }
    Ok(directory)
}

fn rules_allow_content_reuse(binary: &Path, rules_directory: &Path) -> Result<bool> {
    let mut stdout_file = tempfile()?;
    let mut stderr_file = tempfile()?;
    let mut child = Command::new(binary)
        .args([
            "show",
            "dump-config",
            rules_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("rule path is not UTF-8"))?,
        ])
        .env("HOME", "/tmp")
        .env("XDG_CACHE_HOME", "/tmp")
        .env("OPENGREP_ENABLE_VERSION_CHECK", "0")
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()
        .wrap_err("failed to inspect OpenGrep rules")?;
    let status = wait_for_child(
        &mut child,
        &stdout_file,
        &stderr_file,
        RULE_INSPECTION_DEADLINE,
        "OpenGrep rule inspection exceeded its deadline",
    )?;
    let stderr = read_bounded(&mut stderr_file)?;
    ensure!(
        status.success(),
        "OpenGrep rule inspection exited with {status}: {}",
        truncate(&stderr, 1024)
    );
    let parsed_rules = read_bounded(&mut stdout_file)?;
    let rule_count = parsed_rules.matches("Rule.id = (").count();
    ensure!(rule_count > 0, "OpenGrep rule inspection returned no rules");
    Ok(rule_count == parsed_rules.matches("paths = None;").count())
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(!path.as_os_str().is_empty(), "path must not be empty");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "path must contain only normal relative components"
    );
    Ok(path.to_path_buf())
}

fn run_opengrep(
    binary: &Path,
    rules_directory: &Path,
    target_directory: &Path,
    inspector_base: &Url,
    deadline: Duration,
) -> Result<OpenGrepRun> {
    let mut stdout_file = tempfile()?;
    let mut stderr_file = tempfile()?;
    let mut child = Command::new(binary)
        .args([
            "scan",
            "--config",
            rules_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("rule path is not UTF-8"))?,
            "--json",
            "--no-git-ignore",
            "--jobs",
            "1",
            "--timeout",
            "5",
            "--max-target-bytes",
            &APP_CONFIG.max_scan_size.to_string(),
            target_directory
                .to_str()
                .ok_or_else(|| color_eyre::eyre::eyre!("target path is not UTF-8"))?,
        ])
        .env("HOME", "/tmp")
        .env("XDG_CACHE_HOME", "/tmp")
        .env("OPENGREP_ENABLE_VERSION_CHECK", "0")
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()
        .wrap_err("failed to start OpenGrep")?;

    let status = wait_for_child(
        &mut child,
        &stdout_file,
        &stderr_file,
        deadline,
        "OpenGrep exceeded the remaining distribution deadline",
    )?;

    let stderr = read_bounded(&mut stderr_file)?;
    ensure!(
        status.success(),
        "OpenGrep exited with {status}: {}",
        truncate(&stderr, 1024)
    );
    let stdout = read_bounded(&mut stdout_file)?;
    let document: OpenGrepDocument =
        serde_json::from_str(&stdout).wrap_err("OpenGrep returned invalid JSON")?;
    let unexpected_errors: Vec<&Value> = document
        .errors
        .iter()
        .filter(|error| !is_recoverable_scan_warning(error))
        .collect();
    ensure!(
        unexpected_errors.is_empty(),
        "OpenGrep reported scan errors: {}",
        serde_json::to_string(&unexpected_errors)?
    );
    let warnings = document
        .errors
        .iter()
        .filter(|error| is_recoverable_scan_warning(error))
        .map(describe_recoverable_scan_warning)
        .collect::<Vec<_>>();
    if !warnings.is_empty() {
        warn!(
            recoverable_scan_warnings = warnings.len(),
            "OpenGrep reported recoverable scan warnings; preserving valid findings"
        );
    }
    ensure!(
        document.skipped_rules.is_empty(),
        "OpenGrep skipped rules: {}",
        serde_json::to_string(&document.skipped_rules)?
    );

    let findings = document
        .results
        .into_iter()
        .map(|finding| normalize_finding(finding, target_directory, inspector_base))
        .collect::<Result<Vec<_>>>()?;
    Ok(OpenGrepRun { findings, warnings })
}

fn wait_for_child(
    child: &mut Child,
    stdout_file: &File,
    stderr_file: &File,
    deadline: Duration,
    timeout_message: &'static str,
) -> Result<ExitStatus> {
    let started_at = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let output_too_large = stdout_file.metadata()?.len() > MAX_OPENGREP_OUTPUT_BYTES
            || stderr_file.metadata()?.len() > MAX_OPENGREP_OUTPUT_BYTES;
        if output_too_large {
            child.kill()?;
            child.wait()?;
            bail!("OpenGrep output exceeded {MAX_OPENGREP_OUTPUT_BYTES} bytes");
        }
        if started_at.elapsed() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(ScanTimeout(timeout_message).into());
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

fn is_recoverable_scan_warning(error: &Value) -> bool {
    if error.get("level").and_then(Value::as_str) != Some("warn") {
        return false;
    }
    error.get("type").and_then(Value::as_str) == Some("Timeout")
        || error
            .get("type")
            .and_then(Value::as_array)
            .and_then(|kind| kind.first())
            .and_then(Value::as_str)
            == Some("PartialParsing")
}

fn describe_recoverable_scan_warning(error: &Value) -> String {
    if error.get("type").and_then(Value::as_str) == Some("Timeout") {
        return error.get("rule_id").and_then(Value::as_str).map_or_else(
            || "OpenGrep rule timed out".to_owned(),
            |rule_id| {
                let rule_id = rule_id
                    .rsplit_once('.')
                    .map_or(rule_id, |(_, identifier)| identifier);
                format!("OpenGrep rule {} timed out", truncate(rule_id, 200))
            },
        );
    }
    let path = error
        .get("path")
        .and_then(Value::as_str)
        .map_or("a target file", |path| {
            path.rsplit('/').next().unwrap_or(path)
        });
    format!("OpenGrep partially parsed {}", truncate(path, 256))
}

fn is_timeout_error(error: &color_eyre::Report) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<ScanTimeout>().is_some()
            || source
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
            || source
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
    })
}

fn prepare_target(
    target_directory: &Path,
    cache: &PackageScanCache,
    content_reuse_safe: bool,
    deadline: Instant,
) -> Result<TargetPlan> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(target_directory).follow_links(false) {
        ensure_scan_time_remaining(deadline)?;
        let entry = entry?;
        if entry.file_type().is_file() {
            paths.push(entry.into_path());
        }
    }
    paths.sort_unstable();

    let mut retained_by_identity: HashMap<FileIdentity, String> = HashMap::new();
    let mut retained = Vec::new();
    let mut local_aliases = Vec::new();
    let mut reused = Vec::new();
    for path in paths {
        ensure_scan_time_remaining(deadline)?;
        if path.metadata()?.len() > APP_CONFIG.max_scan_size {
            continue;
        }
        let relative_path = relative_target_path(&path, target_directory)?;
        let identity = hash_file(&path, deadline)?;
        if let Some(cached_findings) = cache
            .findings_by_file
            .get(&identity)
            .filter(|_| content_reuse_safe)
        {
            fs::remove_file(path)?;
            reused.push(ReusedFile {
                findings: cached_findings.clone(),
                path: relative_path,
            });
            continue;
        }
        if let Some(canonical_path) = retained_by_identity
            .get(&identity)
            .filter(|_| content_reuse_safe)
        {
            fs::remove_file(path)?;
            local_aliases.push((relative_path, canonical_path.clone()));
            continue;
        }
        retained_by_identity.insert(identity.clone(), relative_path.clone());
        retained.push(RetainedFile {
            identity,
            path: relative_path,
        });
    }
    Ok(TargetPlan {
        retained,
        local_aliases,
        reused,
    })
}

fn prepare_distribution_target(
    target_directory: &Path,
    cache: &PackageScanCache,
    content_reuse_safe: bool,
    deadline: Instant,
) -> Result<Option<TargetPlan>> {
    match prepare_target(target_directory, cache, content_reuse_safe, deadline) {
        Ok(plan) => Ok(Some(plan)),
        Err(error) if is_timeout_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn hash_file(path: &Path, deadline: Instant) -> Result<FileIdentity> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        ensure_scan_time_remaining(deadline)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(FileIdentity {
        digest: hasher.finalize().into(),
        extension: path.extension().map(OsString::from),
    })
}

fn ensure_scan_time_remaining(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(ScanTimeout("OpenGrep preparation exceeded the distribution deadline").into());
    }
    Ok(())
}

fn cache_completed_file_results(
    target_plan: &TargetPlan,
    findings: &[OpenGrepFinding],
    cache: &mut PackageScanCache,
) {
    for file in &target_plan.retained {
        let file_findings = findings
            .iter()
            .filter(|finding| finding.path == file.path)
            .cloned()
            .collect();
        cache
            .findings_by_file
            .insert(file.identity.clone(), file_findings);
    }
}

fn synthesize_reused_findings(
    target_plan: &TargetPlan,
    inspector_base: &Url,
) -> Result<Vec<OpenGrepFinding>> {
    target_plan
        .reused
        .iter()
        .flat_map(|file| {
            file.findings
                .iter()
                .map(|finding| rewrite_finding_location(finding, &file.path, inspector_base))
        })
        .collect()
}

fn synthesize_local_alias_findings(
    target_plan: &TargetPlan,
    findings: &[OpenGrepFinding],
    inspector_base: &Url,
) -> Result<Vec<OpenGrepFinding>> {
    target_plan
        .local_aliases
        .iter()
        .flat_map(|(alias_path, canonical_path)| {
            findings
                .iter()
                .filter(move |finding| finding.path == *canonical_path)
                .map(|finding| rewrite_finding_location(finding, alias_path, inspector_base))
        })
        .collect()
}

fn rewrite_finding_location(
    finding: &OpenGrepFinding,
    path: &str,
    inspector_base: &Url,
) -> Result<OpenGrepFinding> {
    ensure!(path.len() <= 1024, "finding path exceeds 1024 characters");
    let mut finding = finding.clone();
    path.clone_into(&mut finding.path);
    finding.inspector_url = build_inspector_url(inspector_base, path)?;
    Ok(finding)
}

fn read_bounded(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_OPENGREP_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_OPENGREP_OUTPUT_BYTES,
        "OpenGrep output exceeded {MAX_OPENGREP_OUTPUT_BYTES} bytes"
    );
    Ok(String::from_utf8(bytes)?)
}

fn normalize_finding(
    finding: RawFinding,
    target_directory: &Path,
    inspector_base: &Url,
) -> Result<OpenGrepFinding> {
    let path = relative_target_path(&finding.path, target_directory)?;
    ensure!(
        finding.extra.message.len() <= 1024,
        "finding message exceeds 1024 characters"
    );
    let inspector_url = build_inspector_url(inspector_base, &path)?;
    let rule_id = finding
        .check_id
        .rsplit_once('.')
        .map_or(finding.check_id.as_str(), |(_, identifier)| identifier)
        .to_owned();
    Ok(OpenGrepFinding {
        rule_id,
        path,
        start_line: finding.start.line,
        end_line: finding.end.line,
        message: finding.extra.message,
        severity: finding.extra.severity,
        evidence: finding.extra.metadata.evidence,
        confidence: finding.extra.metadata.confidence,
        execution_context: finding.extra.metadata.execution_context,
        inspector_url,
    })
}

fn relative_target_path(path: &Path, target_directory: &Path) -> Result<String> {
    let relative_path = if path.is_absolute() {
        path.strip_prefix(target_directory)?.to_path_buf()
    } else {
        path.to_path_buf()
    };
    let relative_path = safe_relative_path(
        relative_path
            .to_str()
            .ok_or_else(|| color_eyre::eyre::eyre!("finding path is not UTF-8"))?,
    )?;
    let path = relative_path.to_string_lossy().replace('\\', "/");
    ensure!(path.len() <= 1024, "finding path exceeds 1024 characters");
    Ok(path)
}

fn build_inspector_url(inspector_base: &Url, path: &str) -> Result<String> {
    let inspector_url = format!("{}{}", inspector_base.as_str(), path);
    ensure!(
        inspector_url.len() <= 2048,
        "finding inspector URL exceeds 2048 characters"
    );
    Ok(inspector_url)
}

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        append_findings, cache_completed_file_results, is_timeout_error, materialize_rules,
        prepare_target, rules_allow_content_reuse, run_opengrep, safe_relative_path,
        synthesize_local_alias_findings, synthesize_reused_findings, validate_staging_origin,
        PackageScanCache, MAX_FINDINGS, SCAN_DEADLINE,
    };
    use crate::client::{OpenGrepFinding, OpenGrepRulesResponse};
    use reqwest::Url;
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    use tempfile::tempdir;

    #[test]
    fn shadow_origin_is_pinned_to_staging() {
        validate_staging_origin("https://dragonfly-staging.vipyrsec.com").unwrap();
        validate_staging_origin("https://dragonfly-staging.vipyrsec.com/").unwrap();

        for rejected in [
            "https://dragonfly.vipyrsec.com",
            "http://dragonfly-staging.vipyrsec.com",
            "https://dragonfly-staging.vipyrsec.com/other",
            "https://dragonfly-staging.vipyrsec.com?redirect=production",
        ] {
            assert!(validate_staging_origin(rejected).is_err());
        }
    }

    #[test]
    fn rule_paths_cannot_escape_the_temporary_directory() {
        for rejected in [
            "",
            "/absolute.yml",
            "../outside.yml",
            "python/../outside.yml",
        ] {
            assert!(safe_relative_path(rejected).is_err());
        }
        assert_eq!(
            safe_relative_path("python/payload.yml").unwrap(),
            Path::new("python/payload.yml")
        );
    }

    #[test]
    fn rules_are_materialized_with_their_relative_paths() {
        let response = OpenGrepRulesResponse {
            hash: "commit".to_owned(),
            rules: HashMap::from([("python/payload.yml".to_owned(), "rules: []".to_owned())]),
        };

        let directory = materialize_rules(&response).unwrap();

        assert_eq!(
            std::fs::read_to_string(directory.path().join("python/payload.yml")).unwrap(),
            "rules: []"
        );
    }

    #[test]
    fn installed_opengrep_structurally_detects_path_scoped_rules() {
        let Some(binary) = std::env::var_os("OPENGREP_BIN").map(PathBuf::from) else {
            return;
        };
        let rules = tempdir().unwrap();
        let rule_path = rules.path().join("rule.yml");
        std::fs::write(
            &rule_path,
            "rules:\n  - id: content-only\n    message: test\n    languages: [python]\n    severity: ERROR\n    pattern: exec(...)\n",
        )
        .unwrap();
        assert!(rules_allow_content_reuse(&binary, rules.path()).unwrap());

        std::fs::write(
            rule_path,
            "rules:\n  - id: path-scoped\n    message: test\n    languages: [python]\n    severity: ERROR\n    'paths' : {include: [src/**]}\n    pattern: exec(...)\n",
        )
        .unwrap();
        assert!(!rules_allow_content_reuse(&binary, rules.path()).unwrap());
    }

    #[test]
    fn installed_opengrep_matches_the_expected_json_contract() {
        let Some(binary) = std::env::var_os("OPENGREP_BIN").map(PathBuf::from) else {
            return;
        };
        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        std::fs::write(
            rules.path().join("rule.yml"),
            r"
rules:
  - id: python-test-exec
    message: Dynamic execution.
    languages: [python]
    severity: ERROR
    metadata:
      evidence: composition
      confidence: high
      execution_context: import_time
    pattern: exec(...)
",
        )
        .unwrap();
        std::fs::write(target.path().join("sample.py"), "exec('safe fixture')\n").unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule_id, "python-test-exec");
        assert_eq!(run.findings[0].path, "sample.py");
        assert_eq!(run.findings[0].execution_context, "import_time");
        assert!(run.warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn partial_parse_warnings_preserve_valid_findings() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("partial-opengrep");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
for argument in "$@"; do
  if [ "$argument" = "--strict" ]; then
    exit 2
  fi
done
printf '%s' '{
  "results": [{
    "check_id": "python-test-exec",
    "path": "sample.py",
    "start": {"line": 1},
    "end": {"line": 1},
    "extra": {
      "message": "Dynamic execution.",
      "severity": "ERROR",
      "metadata": {
        "evidence": "composition",
        "confidence": "high",
        "execution_context": "import_time"
      }
    }
  }],
  "errors": [{
    "code": 3,
    "level": "warn",
    "message": "Syntax error",
    "path": "other.py",
    "type": ["PartialParsing", []]
  }],
  "skipped_rules": []
}'
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule_id, "python-test-exec");
        assert_eq!(run.warnings.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rule_timeouts_preserve_valid_findings() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("errored-opengrep");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
printf '%s' '{
  "results": [{
    "check_id": "python-test-exec",
    "path": "sample.py",
    "start": {"line": 1},
    "end": {"line": 1},
    "extra": {
      "message": "Dynamic execution.",
      "severity": "ERROR",
      "metadata": {
        "evidence": "composition",
        "confidence": "high",
        "execution_context": "import_time"
      }
    }
  }],
  "errors": [{
    "code": 2,
    "level": "warn",
    "message": "Rule timed out",
    "type": "Timeout"
  }],
  "skipped_rules": []
}'
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let run = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.warnings.len(), 1);
        assert_eq!(run.warnings[0], "OpenGrep rule timed out");
    }

    #[test]
    fn package_cache_reuses_findings_for_duplicate_content() {
        let first_target = tempdir().unwrap();
        let nested = first_target.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(first_target.path().join("first.py"), "print('same')\n").unwrap();
        std::fs::write(nested.join("duplicate.py"), "print('same')\n").unwrap();
        let first_inspector = Url::parse("https://inspector.example/first/").unwrap();
        let mut cache = PackageScanCache::default();

        let first_plan = prepare_target(
            first_target.path(),
            &cache,
            true,
            Instant::now() + SCAN_DEADLINE,
        )
        .unwrap();
        assert_eq!(first_plan.deduplicated_files(), 1);
        assert!(first_target.path().join("first.py").exists());
        assert!(!nested.join("duplicate.py").exists());
        let first_finding = OpenGrepFinding {
            rule_id: "python-test-exec".to_owned(),
            path: "first.py".to_owned(),
            start_line: 1,
            end_line: 1,
            message: "Dynamic execution.".to_owned(),
            severity: "ERROR".to_owned(),
            evidence: "composition".to_owned(),
            confidence: "high".to_owned(),
            execution_context: "import_time".to_owned(),
            inspector_url: "https://inspector.example/first/first.py".to_owned(),
        };
        let alias_findings = synthesize_local_alias_findings(
            &first_plan,
            std::slice::from_ref(&first_finding),
            &first_inspector,
        )
        .unwrap();
        assert_eq!(alias_findings[0].path, "nested/duplicate.py");
        cache_completed_file_results(
            &first_plan,
            std::slice::from_ref(&first_finding),
            &mut cache,
        );

        let second_target = tempdir().unwrap();
        std::fs::write(second_target.path().join("other.py"), "print('same')\n").unwrap();
        std::fs::write(second_target.path().join("other.txt"), "print('same')\n").unwrap();
        let second_plan = prepare_target(
            second_target.path(),
            &cache,
            true,
            Instant::now() + SCAN_DEADLINE,
        )
        .unwrap();
        let second_inspector = Url::parse("https://inspector.example/second/").unwrap();
        let reused = synthesize_reused_findings(&second_plan, &second_inspector).unwrap();

        assert_eq!(second_plan.deduplicated_files(), 1);
        assert!(!second_target.path().join("other.py").exists());
        assert!(second_target.path().join("other.txt").exists());
        assert_eq!(reused.len(), 1);
        assert_eq!(reused[0].rule_id, "python-test-exec");
        assert_eq!(reused[0].path, "other.py");
        assert_eq!(
            reused[0].inspector_url,
            "https://inspector.example/second/other.py"
        );

        let mut bounded = vec![reused[0].clone(); MAX_FINDINGS];
        assert!(append_findings(&mut bounded, reused).is_err());
        assert_eq!(bounded.len(), MAX_FINDINGS);
    }

    #[test]
    fn path_scoped_corpus_preserves_duplicate_files() {
        let target = tempdir().unwrap();
        std::fs::write(target.path().join("first.py"), "print('same')\n").unwrap();
        std::fs::write(target.path().join("second.py"), "print('same')\n").unwrap();

        let plan = prepare_target(
            target.path(),
            &PackageScanCache::default(),
            false,
            Instant::now() + SCAN_DEADLINE,
        )
        .unwrap();

        assert_eq!(plan.retained.len(), 2);
        assert_eq!(plan.deduplicated_files(), 0);
        assert!(target.path().join("first.py").exists());
        assert!(target.path().join("second.py").exists());
    }

    #[test]
    fn target_preparation_observes_the_distribution_deadline() {
        let target = tempdir().unwrap();
        std::fs::write(target.path().join("sample.py"), "print('sample')\n").unwrap();

        let error = prepare_target(
            target.path(),
            &PackageScanCache::default(),
            true,
            Instant::now(),
        )
        .unwrap_err();

        assert!(is_timeout_error(&error));
        assert!(target.path().join("sample.py").exists());
    }

    #[cfg(unix)]
    #[test]
    fn opengrep_is_killed_while_its_output_exceeds_the_limit() {
        use std::os::unix::fs::PermissionsExt;

        let rules = tempdir().unwrap();
        let target = tempdir().unwrap();
        let binary = target.path().join("oversized-opengrep");
        std::fs::write(
            &binary,
            "#!/bin/sh\ndd if=/dev/zero bs=1048576 count=5 2>/dev/null\nsleep 5\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&binary, permissions).unwrap();
        let inspector = Url::parse("https://inspector.example/packages/sample/").unwrap();

        let error = run_opengrep(
            &binary,
            rules.path(),
            target.path(),
            &inspector,
            Duration::from_secs(2),
        )
        .unwrap_err();

        assert!(error.to_string().contains("output exceeded"));
    }
}
