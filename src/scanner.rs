use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};

use reqwest::{blocking::Client, Url};
use yara::Rules;

use crate::{
    api::{fetch_tarball, fetch_zipfile},
    api_models::{Job, SubmitJobResultsSuccess},
    common::{TarballType, ZipType},
    error::DragonflyError,
    exts::RuleExt,
    utils::create_inspector_url,
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct RuleScore {
    pub name: String,
    pub score: i64,
}

/// The results of scanning a single file. Contains the file path and the rules it matched
#[derive(Debug)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub rules: Vec<RuleScore>,
}

impl FileScanResult {
    fn new(path: PathBuf, rules: Vec<RuleScore>) -> Self {
        Self { path, rules }
    }

    /// Returns the total score of all matched rules.
    fn calculate_score(&self) -> i64 {
        self.rules.iter().map(|i| i.score).sum()
    }
}

/// Scan an archive format using Yara rules.
trait Scan {
    fn scan(&mut self, rules: &Rules) -> Result<Vec<FileScanResult>, DragonflyError>;
}

impl Scan for TarballType {
    /// Scan a tarball against the given rule set
    fn scan(&mut self, rules: &Rules) -> Result<Vec<FileScanResult>, DragonflyError> {
        let file_scan_results = self
            .entries()?
            .filter_map(Result::ok)
            .map(|mut tarfile| {
                let path = tarfile.path()?.to_path_buf();
                scan_file(&mut tarfile, &path, rules)
            })
            .filter_map(Result::ok)
            .collect();

        Ok(file_scan_results)
    }
}

impl Scan for ZipType {
    /// Scan a zipfile against the given rule set
    fn scan(&mut self, rules: &Rules) -> Result<Vec<FileScanResult>, DragonflyError> {
        let mut file_scan_results = Vec::new();
        for idx in 0..self.len() {
            let mut file = self.by_index(idx)?;
            let path = PathBuf::from(file.name());
            let scan_results = scan_file(&mut file, &path, rules)?;
            file_scan_results.push(scan_results);
        }

        Ok(file_scan_results)
    }
}

/// A distribution consisting of an archive and an inspector url.
struct Distribution {
    file: Box<dyn Scan>,
    inspector_url: Url,
}

impl Distribution {
    fn scan(&mut self, rules: &Rules) -> Result<DistributionScanResults, DragonflyError> {
        let results = self.file.scan(rules)?;

        Ok(DistributionScanResults::new(
            results,
            self.inspector_url.clone(),
        ))
    }
}

/// Struct representing the results of a scanned distribution
#[derive(Debug)]
pub struct DistributionScanResults {
    /// The scan results for each file in this distribution
    file_scan_results: Vec<FileScanResult>,

    /// The inspector URL pointing to this distribution's base
    inspector_url: Url,
}

impl DistributionScanResults {
    /// Create a new `DistributionScanResults` based off the results of its files, the base
    /// inspector URL for this distribution, and the commit hash used to scan.
    pub fn new(file_scan_results: Vec<FileScanResult>, inspector_url: Url) -> Self {
        Self {
            file_scan_results,
            inspector_url,
        }
    }

    /// Get the "most malicious file" in the distribution.
    ///
    /// This file with the greatest score is considered the most malicious. If multiple
    /// files have the same score, an arbitrary file is picked.
    pub fn get_most_malicious_file(&self) -> Option<&FileScanResult> {
        self.file_scan_results
            .iter()
            .max_by_key(|i| i.calculate_score())
    }

    /// Get all **unique** `RuleScore` objects that were matched for this distribution
    fn get_matched_rules(&self) -> HashSet<&RuleScore> {
        let mut rules: HashSet<&RuleScore> = HashSet::new();
        for file_scan_result in &self.file_scan_results {
            for rule in &file_scan_result.rules {
                rules.insert(rule);
            }
        }

        rules
    }

    /// Calculate the total score of this distribution, without counting duplicates twice
    pub fn get_total_score(&self) -> i64 {
        self.get_matched_rules().iter().map(|rule| rule.score).sum()
    }

    /// Get a vector of the **unique** rule identifiers this distribution matched
    pub fn get_matched_rule_identifiers(&self) -> Vec<&str> {
        self.get_matched_rules()
            .iter()
            .map(|rule| rule.name.as_str())
            .collect()
    }

    /// Return the inspector URL of the most malicious file, or `None` if there is no most malicious
    /// file
    pub fn inspector_url(&self) -> Option<String> {
        self.get_most_malicious_file().map(|file| {
            format!(
                "{}{}",
                self.inspector_url.as_str(),
                file.path.to_string_lossy().as_ref()
            )
        })
    }
}

pub struct PackageScanResults {
    pub name: String,
    pub version: String,
    pub distribution_scan_results: Vec<DistributionScanResults>,
    pub commit_hash: String,
}

impl PackageScanResults {
    pub fn new(
        name: String,
        version: String,
        distribution_scan_results: Vec<DistributionScanResults>,
        commit_hash: String,
    ) -> Self {
        Self {
            name,
            version,
            distribution_scan_results,
            commit_hash,
        }
    }

    /// Format the package scan results into something that can be sent over the API
    pub fn build_body(&self) -> SubmitJobResultsSuccess {
        let highest_score_distribution = self
            .distribution_scan_results
            .iter()
            .max_by_key(|distrib| distrib.get_total_score());

        let score = highest_score_distribution
            .map(DistributionScanResults::get_total_score)
            .unwrap_or_default();

        let inspector_url =
            highest_score_distribution.and_then(DistributionScanResults::inspector_url);

        // collect all rule identifiers into a HashSet to dedup, then convert to Vec
        let rules_matched = self
            .distribution_scan_results
            .iter()
            .flat_map(DistributionScanResults::get_matched_rule_identifiers)
            .map(std::string::ToString::to_string)
            .collect::<HashSet<String>>()
            .into_iter()
            .collect();

        SubmitJobResultsSuccess {
            name: self.name.clone(),
            version: self.version.clone(),
            score,
            inspector_url,
            rules_matched,
            commit: self.commit_hash.clone(),
        }
    }
}

/// Scan all the distributions of the given job against the given ruleset
///
/// Uses the provided HTTP client to download each distribution.
pub fn scan_all_distributions(
    http_client: &Client,
    rules: &Rules,
    job: &Job,
) -> Result<Vec<DistributionScanResults>, DragonflyError> {
    let mut distribution_scan_results = Vec::with_capacity(job.distributions.len());
    for distribution in &job.distributions {
        let download_url: Url = distribution.parse().unwrap();
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let mut dist = Distribution {
            file: if distribution.ends_with(".tar.gz") {
                Box::new(fetch_tarball(http_client, &download_url)?)
            } else {
                Box::new(fetch_zipfile(http_client, &download_url)?)
            },
            inspector_url,
        };
        let distribution_scan_result = dist.scan(rules)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}

/// Scan a file given it implements `Read`.
///
/// # Arguments
/// * `path` - The path corresponding to this file
/// * `rules` - The compiled rule set to scan this file against
fn scan_file(
    file: &mut impl Read,
    path: &Path,
    rules: &Rules,
) -> Result<FileScanResult, DragonflyError> {
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let rules = rules
        .scan_mem(&buffer, 10)?
        .into_iter()
        .filter(|rule| {
            let filetypes = rule.get_filetypes();
            filetypes.is_empty()
                || filetypes
                    .iter()
                    .any(|filetype| path.to_string_lossy().ends_with(filetype))
        })
        .map(RuleScore::from)
        .collect();

    Ok(FileScanResult::new(path.to_path_buf(), rules))
}
