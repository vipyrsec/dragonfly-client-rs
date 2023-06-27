use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};

use reqwest::{blocking::Client, Url};
use yara::{MetadataValue, Rule, Rules};

use crate::{
    api::{fetch_tarball, fetch_zipfile},
    api_models::Job,
    common::{TarballType, ZipType},
    error::DragonflyError,
    utils::create_inspector_url,
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct RuleScore {
    pub name: String,
    pub score: Option<i64>,
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

    /// Calculate the "maliciousness" index of this file
    fn calculate_score(&self) -> i64 {
        self.rules.iter().map(|i| i.score.unwrap_or(0)).sum()
    }
}

enum Distribution {
    Tar {
        file: TarballType,
        inspector_url: Url,
    },

    Zip {
        file: ZipType,
        inspector_url: Url,
    },
}

impl Distribution {
    /// Scan this distribution against the given rules
    fn scan(&mut self, rules: &Rules) -> Result<DistributionScanResults, DragonflyError> {
        match self {
            Self::Tar {
                file,
                inspector_url,
            } => scan_tarball(file, rules)
                .map(|files| DistributionScanResults::new(files, inspector_url.clone())),

            Self::Zip {
                file,
                inspector_url,
            } => scan_zip(file, rules)
                .map(|files| DistributionScanResults::new(files, inspector_url.clone())),
        }
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
    /// Create a new `DistributionScanResults` based off the results of it's files and the base
    /// inspector URL
    pub fn new(file_scan_results: Vec<FileScanResult>, inspector_url: Url) -> Self {
        Self {
            file_scan_results,
            inspector_url,
        }
    }

    /// Get the "most malicious file" in the distribution. This is calculated based off the file
    /// with the highest score in this distribution
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
        self.get_matched_rules()
            .iter()
            .map(|rule| rule.score.unwrap_or(0))
            .sum()
    }

    /// Get a vector over the identifiers of the all **unique** rules this distribution matched
    pub fn get_matched_rule_identifiers(&self) -> Vec<&str> {
        self.get_matched_rules()
            .iter()
            .map(|rule| rule.name.as_str())
            .collect()
    }

    /// Return the inspector URL of the most malicious file, or None if there is no most malicious
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

trait RuleExt<'a> {
    /// Get the value of a metadata by key. `None` if that key/value pair doesn't exist
    fn get_metadata_value(&'a self, key: &str) -> Option<&'a MetadataValue>;

    /// Get a vector over the `filetype` metadata value. None if none are defined.
    fn get_rule_weight(&'a self) -> Option<i64>;

    /// Get the weight of this rule. None if not defined.
    fn get_filetypes(&'a self) -> Option<Vec<&'a str>>;
}

impl<'a> RuleExt<'a> for Rule<'a> {
    fn get_metadata_value(&self, key: &str) -> Option<&'a MetadataValue> {
        self.metadatas
            .iter()
            .find(|metadata| metadata.identifier == key)
            .map(|metadata| &metadata.value)
    }

    fn get_filetypes(&'a self) -> Option<Vec<&'a str>> {
        if let Some(MetadataValue::String(string)) = self.get_metadata_value("filetype") {
            Some(string.split(' ').collect())
        } else {
            None
        }
    }

    fn get_rule_weight(&self) -> Option<i64> {
        if let Some(MetadataValue::Integer(integer)) = self.get_metadata_value("weight") {
            Some(*integer)
        } else {
            None
        }
    }
}

impl From<Rule<'_>> for RuleScore {
    fn from(rule: Rule) -> Self {
        Self {
            name: rule.identifier.to_owned(),
            score: rule.get_rule_weight(),
        }
    }
}

/// Scan a file given it implements Read. Also takes the path of the file and the rules to scan it
/// against
fn scan_file(
    file: &mut impl Read,
    path: &Path,
    rules: &Rules,
) -> Result<FileScanResult, DragonflyError> {
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let rules: Vec<RuleScore> = rules
        .scan_mem(&buffer, 10)?
        .into_iter()
        .filter(|rule| {
            rule.get_filetypes()
                .filter(|filetypes| filetypes.iter().any(|filetype| path.ends_with(filetype)))
                .is_some()
        })
        .map(RuleScore::from)
        .collect();

    Ok(FileScanResult::new(path.to_path_buf(), rules))
}

/// Scan a zipfile against the given rule set
pub fn scan_zip(zip: &mut ZipType, rules: &Rules) -> Result<Vec<FileScanResult>, DragonflyError> {
    let mut file_scan_results = Vec::new();
    for idx in 0..zip.len() {
        let mut file = zip.by_index(idx)?;
        let path = PathBuf::from(file.name());
        let scan_results = scan_file(&mut file, &path, rules)?;
        file_scan_results.push(scan_results);
    }

    Ok(file_scan_results)
}

/// Scan a tarball against the given rule set
pub fn scan_tarball(
    tar: &mut TarballType,
    rules: &Rules,
) -> Result<Vec<FileScanResult>, DragonflyError> {
    let file_scan_results = tar
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

/// Scan all the distributions of the given job against the given ruleset, returning the
/// results of each distribution. Uses the provided HTTP client to download each
/// distribution
pub fn scan_all_distributions(
    http_client: &Client,
    rules: &Rules,
    job: &Job,
) -> Result<Vec<DistributionScanResults>, DragonflyError> {
    let mut distribution_scan_results = Vec::new();
    for distribution in &job.distributions {
        let download_url: Url = distribution.parse().unwrap();
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let mut dist = if distribution.ends_with(".tar.gz") {
            let file = fetch_tarball(http_client, &download_url)?;
            Distribution::Tar {
                file,
                inspector_url,
            }
        } else {
            let file = fetch_zipfile(http_client, &download_url)?;
            Distribution::Zip {
                file,
                inspector_url,
            }
        };

        let distribution_scan_result = dist.scan(rules)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}
