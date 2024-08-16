use std::{collections::HashSet, path::Path};

use color_eyre::Result;
use reqwest::{blocking::Client, Url};
use tempfile::TempDir;
use walkdir::WalkDir;
use yara::Rules;

use crate::client::DistributionScanResult;
use crate::{
    client::{download_tarball, download_zipfile, FileScanResult, Job, SubmitJobResultsSuccess},
    exts::RuleExt,
    utils::create_inspector_url,
};

/// A distribution consisting of an archive and an inspector url.
struct Distribution {
    dir: TempDir,
    inspector_url: Url,
    download_url: Url,
}

impl Distribution {
    fn scan(&mut self, rules: &Rules) -> Result<DistributionScanResults> {
        let mut file_scan_results: Vec<FileScanResult> = Vec::new();
        for entry in WalkDir::new(self.dir.path()) {
            let entry = entry?;
            let file_scan_result = scan_file(entry.path(), rules)?;
            file_scan_results.push(file_scan_result);
        }

        Ok(DistributionScanResults::new(
            file_scan_results,
            self.inspector_url.clone(),
            &self.download_url,
        ))
    }
}

/// Struct representing the results of a scanned distribution
#[derive(Debug)]
pub struct DistributionScanResults {
    /// The scan results for each file in this distribution
    distro_scan_results: DistributionScanResult,

    /// The inspector URL pointing to this distribution's base
    inspector_url: Url,
}

impl DistributionScanResults {
    /// Create a new `DistributionScanResults` based off the results of its files and the base
    /// inspector URL for this distribution.
    pub fn new(
        file_scan_results: Vec<FileScanResult>,
        inspector_url: Url,
        download_url: &Url,
    ) -> Self {
        Self {
            inspector_url,
            distro_scan_results: DistributionScanResult::new(
                download_url.to_string(),
                file_scan_results,
            ),
        }
    }

    pub fn get_total_score(&self) -> i64 {
        self.distro_scan_results
            .files
            .iter()
            .map(FileScanResult::calculate_score)
            .sum()
    }

    /// Get the "most malicious file" in the distribution.
    ///
    /// This file with the greatest score is considered the most malicious. If multiple
    /// files have the same score, an arbitrary file is picked.
    pub fn get_most_malicious_file(&self) -> Option<&FileScanResult> {
        self.distro_scan_results
            .files
            .iter()
            .max_by_key(|i| i.calculate_score())
    }

    /// Get all **unique** `RuleMatch` objects that were matched for this distribution
    fn get_matched_rules(&self) -> HashSet<(&str, i64)> {
        let mut rules = HashSet::new();
        for file_scan_result in &self.distro_scan_results.files {
            for match_ in &file_scan_result.matches {
                rules.insert((match_.identifier.as_str(), match_.score()));
            }
        }

        rules
    }

    /// Get a vector of the **unique** rule identifiers this distribution matched
    pub fn get_matched_rule_identifiers(&self) -> Vec<&str> {
        self.get_matched_rules()
            .iter()
            .map(|&rule| rule.0)
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
    pub fn build_body(self) -> SubmitJobResultsSuccess {
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
            name: self.name,
            version: self.version,
            score,
            inspector_url,
            rules_matched,
            commit: self.commit_hash,
            distributions: self
                .distribution_scan_results
                .into_iter()
                .map(|dsr| dsr.distro_scan_results)
                .filter(|dsr| !dsr.files.is_empty())
                .collect(),
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
) -> Result<Vec<DistributionScanResults>> {
    let mut distribution_scan_results = Vec::with_capacity(job.distributions.len());
    for distribution in &job.distributions {
        let download_url: Url = distribution.parse().unwrap();
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let dir = if distribution.ends_with(".tar.gz") {
            download_tarball(http_client, &download_url)
        } else {
            download_zipfile(http_client, &download_url)
        }?;

        let mut dist = Distribution {
            dir,
            inspector_url,
            download_url,
        };
        let distribution_scan_result = dist.scan(rules)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}

/// Scan a file given it's path, and compiled rules.
///
/// # Arguments
/// * `path` - The path of the file to scan.
/// * `rules` - The compiled rule set to scan this file against
fn scan_file(path: &Path, rules: &Rules) -> Result<FileScanResult> {
    let rules = rules
        .scan_file(path, 10)?
        .into_iter()
        .filter(|rule| {
            let filetypes = rule.get_filetypes();
            filetypes.is_empty()
                || filetypes
                    .iter()
                    .any(|filetype| path.to_string_lossy().ends_with(filetype))
        })
        .collect();

    Ok(FileScanResult::new(path.to_path_buf(), rules))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::{collections::HashSet, path::PathBuf};
    use yara::Compiler;

    use super::{scan_file, DistributionScanResults, PackageScanResults};
    use crate::client::{
        DistributionScanResult, Match, MetadataValue, PatternMatch, Range, RuleMatch,
        ScanResultSerializer, SubmitJobResultsError, SubmitJobResultsSuccess,
    };
    use crate::test::make_file_scan_result;

    #[test]
    fn test_scan_result_success_serialization() {
        let success = SubmitJobResultsSuccess {
            name: "test".into(),
            version: "1.0.0".into(),
            score: 10,
            inspector_url: Some("inspector url".into()),
            rules_matched: vec!["abc".into(), "def".into()],
            commit: "commit hash".into(),
            distributions: Vec::new(),
        };

        let scan_result: ScanResultSerializer = Ok(success).into();
        let actual = serde_json::to_string(&scan_result).unwrap();
        let expected = r#"{"name":"test","version":"1.0.0","score":10,"inspector_url":"inspector url","rules_matched":["abc","def"],"commit":"commit hash","distributions":[]}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_scan_result_error_serialization() {
        let error = SubmitJobResultsError {
            name: "test".into(),
            version: "1.0.0".into(),
            reason: "Package too large".into(),
        };

        let scan_result: ScanResultSerializer = Err(error).into();
        let actual = serde_json::to_string(&scan_result).unwrap();
        let expected = r#"{"name":"test","version":"1.0.0","reason":"Package too large"}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_get_most_malicious_file() {
        let file_scan_results = vec![
            make_file_scan_result("/a", &[("rule1", 5)]),
            make_file_scan_result("/b", &[("rule2", 7)]),
            make_file_scan_result("/c", &[("rule3", 4)]),
        ];

        let distribution_scan_results = DistributionScanResults {
            distro_scan_results: DistributionScanResult::new("e".into(), file_scan_results),
            inspector_url: reqwest::Url::parse("https://example.net").unwrap(),
        };

        assert_eq!(
            "rule2",
            distribution_scan_results
                .get_most_malicious_file()
                .unwrap()
                .matches[0]
                .identifier
        )
    }

    #[test]
    fn test_get_matched_rules() {
        let file_scan_results = vec![
            make_file_scan_result("/a", &[("rule1", 5), ("rule2", 7)]),
            make_file_scan_result("/b", &[("rule2", 7), ("rule3", 9)]),
            make_file_scan_result("/c", &[("rule3", 9), ("rule4", 6)]),
        ];

        let distribution_scan_results = DistributionScanResults {
            distro_scan_results: DistributionScanResult::new("e".into(), file_scan_results),
            inspector_url: reqwest::Url::parse("https://example.net").unwrap(),
        };

        let matched_rules: HashSet<(&str, i64)> = distribution_scan_results
            .get_matched_rules()
            .into_iter()
            .collect();

        let expected_rules =
            HashSet::from([("rule1", 5), ("rule2", 7), ("rule3", 9), ("rule4", 6)]);

        assert_eq!(matched_rules, expected_rules);
    }

    #[test]
    fn test_get_matched_rule_identifiers() {
        let file_scan_results = vec![
            make_file_scan_result("/a", &[("rule1", 5), ("rule2", 7)]),
            make_file_scan_result("/b", &[("rule2", 7), ("rule3", 9)]),
            make_file_scan_result("/c", &[("rule3", 9), ("rule4", 6)]),
        ];

        let distribution_scan_results = DistributionScanResults {
            distro_scan_results: DistributionScanResult::new("e".into(), file_scan_results),
            inspector_url: reqwest::Url::parse("https://example.net").unwrap(),
        };

        let matched_rule_identifiers = distribution_scan_results.get_matched_rule_identifiers();

        let expected_rule_identifiers = vec!["rule1", "rule2", "rule3", "rule4"];

        assert_eq!(
            HashSet::<_>::from_iter(matched_rule_identifiers),
            HashSet::<_>::from_iter(expected_rule_identifiers)
        );
    }

    #[test]
    fn test_build_package_scan_results_body() {
        let file_scan_results1 = vec![
            make_file_scan_result("/a", &[("rule1", 5)]),
            make_file_scan_result("/b", &[("rule2", 7)]),
        ];
        let distribution_scan_results1 = DistributionScanResults {
            distro_scan_results: DistributionScanResult::new("e".into(), file_scan_results1),
            inspector_url: reqwest::Url::parse("https://example.net/distrib1.tar.gz").unwrap(),
        };

        let file_scan_results2 = vec![
            make_file_scan_result("/c", &[("rule3", 2)]),
            make_file_scan_result("/d", &[("rule4", 9)]),
        ];
        let distribution_scan_results2 = DistributionScanResults {
            distro_scan_results: DistributionScanResult::new("e".into(), file_scan_results2),
            inspector_url: reqwest::Url::parse("https://example.net/distrib2.whl").unwrap(),
        };

        let package_scan_results = PackageScanResults {
            name: String::from("remmy"),
            version: String::from("4.20.69"),
            distribution_scan_results: vec![distribution_scan_results1, distribution_scan_results2],
            commit_hash: String::from("abc"),
        };

        let body = package_scan_results.build_body();

        assert_eq!(
            body.inspector_url,
            Some(String::from("https://example.net/distrib1.tar.gz/b"))
        );
        assert_eq!(body.score, 12);
        assert_eq!(
            HashSet::from([
                "rule1".into(),
                "rule2".into(),
                "rule3".into(),
                "rule4".into()
            ]),
            HashSet::from_iter(body.rules_matched)
        );
    }

    #[test]
    fn test_scan_file() {
        let rules = r#"
            rule contains_rust {
                meta:
                    weight = 5
                strings:
                    $rust = "rust" nocase
                condition:
                    $rust
            }
        "#;

        let compiler = Compiler::new().unwrap().add_rules_str(rules).unwrap();

        let rules = compiler.compile_rules().unwrap();

        let result = scan_file(&PathBuf::default(), &rules).unwrap();

        assert_eq!(result.path, PathBuf::default());
        assert_eq!(
            RuleMatch {
                identifier: "contains_rust".to_string(),
                patterns: vec![PatternMatch {
                    identifier: "$rust".to_string(),
                    matches: vec![Match {
                        data: vec![b'R', b'u', b's', b't'],
                        range: Range { start: 7, end: 10 }
                    }]
                }],
                metadata: vec![("weight".to_string(), MetadataValue::Integer(5))]
                    .into_iter()
                    .collect::<HashMap<_, _>>(),
            },
            result.matches[0],
        );

        assert_eq!(result.calculate_score(), 5);
    }
}
