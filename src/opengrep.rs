use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
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
use tempfile::{tempdir, tempfile, TempDir};

use crate::{
    app_config::APP_CONFIG,
    client::{
        build_api_http_client, build_download_http_client, download_distribution,
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

pub struct OpenGrepClient {
    api_client: Client,
    download_client: Client,
    base_url: String,
    binary: PathBuf,
    rules_directory: TempDir,
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
        Ok(Self {
            api_client,
            download_client,
            base_url: APP_CONFIG.base_url.trim_end_matches('/').to_owned(),
            binary,
            rules_directory,
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
        self.rules_hash = response.hash;
        self.rules_directory = rules_directory;
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
            Ok(findings) => OpenGrepScanResult::Success(SubmitOpenGrepResultsSuccess {
                name: job.name.clone(),
                version: job.version.clone(),
                attempt: job.attempt,
                assignment_id: job.assignment_id.clone(),
                commit: job.hash.clone(),
                duration_ms,
                findings,
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

    fn scan_job(&self, job: &Job) -> Result<Vec<OpenGrepFinding>> {
        ensure!(
            job.distributions.len() <= APP_CONFIG.max_distributions,
            "package contains {} distributions, exceeding the {}-distribution limit",
            job.distributions.len(),
            APP_CONFIG.max_distributions
        );
        let mut findings = Vec::new();
        for distribution in &job.distributions {
            let download_url: Url = distribution.parse()?;
            let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);
            let directory = download_distribution(&self.download_client, download_url)?;
            let mut distribution_findings = run_opengrep(
                &self.binary,
                self.rules_directory.path(),
                directory.path(),
                &inspector_url,
            )?;
            findings.append(&mut distribution_findings);
            ensure!(
                findings.len() <= MAX_FINDINGS,
                "OpenGrep produced more than {MAX_FINDINGS} findings"
            );
        }
        Ok(findings)
    }
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
) -> Result<Vec<OpenGrepFinding>> {
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
            "--strict",
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

    let started_at = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started_at.elapsed() >= SCAN_DEADLINE {
            child.kill()?;
            child.wait()?;
            bail!("OpenGrep exceeded the 60-second distribution deadline");
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    };

    let stderr = read_bounded(&mut stderr_file)?;
    ensure!(
        status.success(),
        "OpenGrep exited with {status}: {}",
        truncate(&stderr, 1024)
    );
    let stdout = read_bounded(&mut stdout_file)?;
    let document: OpenGrepDocument =
        serde_json::from_str(&stdout).wrap_err("OpenGrep returned invalid JSON")?;
    ensure!(
        document.errors.is_empty(),
        "OpenGrep reported scan errors: {}",
        serde_json::to_string(&document.errors)?
    );
    ensure!(
        document.skipped_rules.is_empty(),
        "OpenGrep skipped rules: {}",
        serde_json::to_string(&document.skipped_rules)?
    );

    document
        .results
        .into_iter()
        .map(|finding| normalize_finding(finding, target_directory, inspector_base))
        .collect()
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
    let relative_path = if finding.path.is_absolute() {
        finding.path.strip_prefix(target_directory)?.to_path_buf()
    } else {
        finding.path
    };
    let relative_path = safe_relative_path(
        relative_path
            .to_str()
            .ok_or_else(|| color_eyre::eyre::eyre!("finding path is not UTF-8"))?,
    )?;
    let path = relative_path.to_string_lossy().replace('\\', "/");
    ensure!(path.len() <= 1024, "finding path exceeds 1024 characters");
    ensure!(
        finding.extra.message.len() <= 1024,
        "finding message exceeds 1024 characters"
    );
    let inspector_url = format!("{}{}", inspector_base.as_str(), path);
    ensure!(
        inspector_url.len() <= 2048,
        "finding inspector URL exceeds 2048 characters"
    );
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

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::{materialize_rules, run_opengrep, safe_relative_path, validate_staging_origin};
    use crate::client::OpenGrepRulesResponse;
    use reqwest::Url;
    use std::{collections::HashMap, path::Path, path::PathBuf};
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

        let findings = run_opengrep(&binary, rules.path(), target.path(), &inspector).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python-test-exec");
        assert_eq!(findings[0].path, "sample.py");
        assert_eq!(findings[0].execution_context, "import_time");
    }
}
