use std::path::PathBuf;
use std::{collections::HashSet, path::Path};

use color_eyre::{eyre::ensure, Result};
use reqwest::{blocking::Client, Url};
use tempfile::TempDir;
use walkdir::WalkDir;
use yara::Rules;

use crate::{
    client::{download_distribution, Job, SubmitJobResultsSuccess},
    exts::RuleExt,
    utils::create_inspector_url,
    APP_CONFIG,
};

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
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

/// A distribution consisting of an archive and an inspector url.
struct Distribution {
    dir: TempDir,
    inspector_url: Url,
}

impl Distribution {
    fn scan(&mut self, rules: &Rules, max_scan_size: u64) -> Result<DistributionScanResults> {
        let mut results = DistributionScanResults::empty(self.inspector_url.clone());
        for entry in WalkDir::new(self.dir.path())
            .into_iter()
            .filter_map(|dirent| dirent.into_iter().find(|de| de.file_type().is_file()))
        {
            let file_scan_result = self.scan_file(entry.path(), rules, max_scan_size)?;
            results.record(file_scan_result);
        }

        Ok(results)
    }

    /// Scan a file given it's path, and compiled rules.
    ///
    /// # Arguments
    /// * `path` - The path of the file to scan.
    /// * `rules` - The compiled rule set to scan this file against
    fn scan_file(&self, path: &Path, rules: &Rules, max_scan_size: u64) -> Result<FileScanResult> {
        let file_size = path.metadata()?.len();
        ensure!(
            file_size <= max_scan_size,
            "file {} is {file_size} bytes, exceeding the {max_scan_size}-byte scan limit",
            path.display()
        );
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
            .map(RuleScore::from)
            .collect();

        Ok(FileScanResult::new(
            self.relative_to_archive_root(path)?,
            rules,
        ))
    }

    /// Make the path relative to the archive root
    fn relative_to_archive_root(&self, path: &Path) -> Result<PathBuf> {
        Ok(path.strip_prefix(self.dir.path())?.to_path_buf())
    }
}

/// Struct representing the results of a scanned distribution
#[derive(Debug)]
pub struct DistributionScanResults {
    /// The highest-scoring file in this distribution.
    most_malicious_file: Option<FileScanResult>,

    /// The unique rules matched across the distribution.
    matched_rules: HashSet<RuleScore>,

    /// The inspector URL pointing to this distribution's base
    inspector_url: Url,
}

impl DistributionScanResults {
    /// Create a new `DistributionScanResults` based off the results of its files and the base
    /// inspector URL for this distribution.
    #[cfg(test)]
    fn new(file_scan_results: Vec<FileScanResult>, inspector_url: Url) -> Self {
        let mut results = Self::empty(inspector_url);
        for file_scan_result in file_scan_results {
            results.record(file_scan_result);
        }
        results
    }

    fn empty(inspector_url: Url) -> Self {
        Self {
            most_malicious_file: None,
            matched_rules: HashSet::new(),
            inspector_url,
        }
    }

    fn record(&mut self, file_scan_result: FileScanResult) {
        self.matched_rules
            .extend(file_scan_result.rules.iter().cloned());
        let should_replace = self
            .most_malicious_file
            .as_ref()
            .is_none_or(|current| file_scan_result.calculate_score() >= current.calculate_score());
        if should_replace {
            self.most_malicious_file = Some(file_scan_result);
        }
    }

    /// Get the "most malicious file" in the distribution.
    ///
    /// This file with the greatest score is considered the most malicious. If multiple
    /// files have the same score, an arbitrary file is picked.
    #[must_use]
    pub fn get_most_malicious_file(&self) -> Option<&FileScanResult> {
        self.most_malicious_file.as_ref()
    }

    /// Get all **unique** `RuleScore` objects that were matched for this distribution
    #[cfg(test)]
    fn get_matched_rules(&self) -> HashSet<&RuleScore> {
        self.matched_rules.iter().collect()
    }

    /// Calculate the distribution score, counting each matched rule once.
    #[must_use]
    pub fn get_total_score(&self) -> i64 {
        self.matched_rules.iter().map(|rule| rule.score).sum()
    }

    /// Get a vector of the **unique** rule identifiers this distribution matched
    #[cfg(test)]
    fn get_matched_rule_identifiers(&self) -> Vec<&str> {
        self.matched_rules
            .iter()
            .map(|rule| rule.name.as_str())
            .collect()
    }

    /// Return the inspector URL of the most malicious file, or `None` if there is no most malicious
    /// file
    #[must_use]
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
    pub attempt: u64,
    pub assignment_id: String,
    pub distribution_scan_results: Vec<DistributionScanResults>,
    pub commit_hash: String,
}

impl PackageScanResults {
    #[must_use]
    pub fn new(
        name: String,
        version: String,
        attempt: u64,
        assignment_id: String,
        distribution_scan_results: Vec<DistributionScanResults>,
        commit_hash: String,
    ) -> Self {
        Self {
            name,
            version,
            attempt,
            assignment_id,
            distribution_scan_results,
            commit_hash,
        }
    }

    /// Format the package scan results into something that can be sent over the API
    pub fn build_body(&self) -> SubmitJobResultsSuccess {
        let highest_score_distribution = self
            .distribution_scan_results
            .iter()
            .max_by_key(|distribution| distribution.get_total_score());

        let score = highest_score_distribution
            .map(DistributionScanResults::get_total_score)
            .unwrap_or_default();

        let inspector_url =
            highest_score_distribution.and_then(DistributionScanResults::inspector_url);

        let mut rules_matched = self
            .distribution_scan_results
            .iter()
            .flat_map(|distribution| &distribution.matched_rules)
            .map(|rule| rule.name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        rules_matched.sort_unstable();

        SubmitJobResultsSuccess {
            name: self.name.clone(),
            version: self.version.clone(),
            attempt: self.attempt,
            assignment_id: self.assignment_id.clone(),
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
///
/// # Errors
///
/// Returns an error for malformed URLs, download or archive failures, YARA
/// failures, or any configured resource-limit violation.
pub fn scan_all_distributions(
    http_client: &Client,
    rules: &Rules,
    job: &Job,
) -> Result<Vec<DistributionScanResults>> {
    ensure!(
        job.distributions.len() <= APP_CONFIG.max_distributions,
        "package contains {} distributions, exceeding the {}-distribution limit",
        job.distributions.len(),
        APP_CONFIG.max_distributions
    );
    let mut distribution_scan_results = Vec::with_capacity(job.distributions.len());
    for distribution in &job.distributions {
        let download_url: Url = distribution.parse()?;
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let dir = download_distribution(http_client, download_url.clone())?;

        let mut dist = Distribution { dir, inspector_url };
        let distribution_scan_result = dist.scan(rules, APP_CONFIG.max_scan_size)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}

#[cfg(test)]
mod tests {
    use super::{DistributionScanResults, PackageScanResults};
    use crate::{
        client::{Job, ScanResultSerializer, SubmitJobResultsError, SubmitJobResultsSuccess},
        scanner::{FileScanResult, RuleScore},
    };
    use std::io::Write;
    use std::{collections::HashSet, path::PathBuf};
    use tempfile::{tempdir, tempdir_in};
    use yara::Compiler;

    #[test]
    fn test_scan_result_success_serialization() {
        let success = SubmitJobResultsSuccess {
            name: "test".into(),
            version: "1.0.0".into(),
            attempt: 2,
            assignment_id: "4e3702e8-27a3-46e6-b51c-4779a94fa4ab".into(),
            score: 10,
            inspector_url: Some("inspector url".into()),
            rules_matched: vec!["abc".into(), "def".into()],
            commit: "commit hash".into(),
        };

        let scan_result: ScanResultSerializer = Ok(success).into();
        let actual = serde_json::to_string(&scan_result).unwrap();
        let expected = r#"{"name":"test","version":"1.0.0","attempt":2,"assignment_id":"4e3702e8-27a3-46e6-b51c-4779a94fa4ab","score":10,"inspector_url":"inspector url","rules_matched":["abc","def"],"commit":"commit hash"}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_scan_result_error_serialization() {
        let error = SubmitJobResultsError {
            name: "test".into(),
            version: "1.0.0".into(),
            attempt: 3,
            assignment_id: "a58c83d7-0864-48da-b3d1-e7ae59ac9572".into(),
            reason: "Package too large".into(),
        };

        let scan_result: ScanResultSerializer = Err(error).into();
        let actual = serde_json::to_string(&scan_result).unwrap();
        let expected = r#"{"name":"test","version":"1.0.0","attempt":3,"assignment_id":"a58c83d7-0864-48da-b3d1-e7ae59ac9572","reason":"Package too large"}"#;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_file_score() {
        let rules = vec![
            RuleScore {
                name: String::from("rule1"),
                score: 5,
            },
            RuleScore {
                name: String::from("rule2"),
                score: 7,
            },
        ];

        let file_scan_result = FileScanResult {
            path: PathBuf::default(),
            rules,
        };
        assert_eq!(file_scan_result.calculate_score(), 12);
    }

    #[test]
    fn test_get_most_malicious_file() {
        let file_scan_results = vec![
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule1"),
                    score: 5,
                }],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule2"),
                    score: 7,
                }],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule3"),
                    score: 4,
                }],
            },
        ];

        let distribution_scan_results = DistributionScanResults::new(
            file_scan_results,
            reqwest::Url::parse("https://example.net").unwrap(),
        );

        assert_eq!(
            distribution_scan_results
                .get_most_malicious_file()
                .unwrap()
                .rules[0]
                .name,
            "rule2"
        );
    }

    #[test]
    fn distribution_results_retain_only_the_highest_scoring_file() {
        let file_scan_results = (0..100)
            .map(|index| FileScanResult {
                path: PathBuf::from(format!("file-{index}")),
                rules: Vec::new(),
            })
            .collect();

        let results = DistributionScanResults::new(
            file_scan_results,
            reqwest::Url::parse("https://example.net").unwrap(),
        );

        assert!(results.matched_rules.is_empty());
        assert_eq!(
            results.get_most_malicious_file().unwrap().path,
            PathBuf::from("file-99")
        );
    }

    #[test]
    fn package_distribution_count_is_bounded_before_downloads() {
        let rules = Compiler::new()
            .unwrap()
            .add_rules_str("rule never { condition: false }")
            .unwrap()
            .compile_rules()
            .unwrap();
        let job = Job {
            hash: String::new(),
            name: "large-package".into(),
            version: "1.0.0".into(),
            distributions: vec![
                "https://example.com/distribution.whl".into();
                crate::APP_CONFIG.max_distributions + 1
            ],
            attempt: 1,
            assignment_id: "d4d10b9b-f0ea-44dc-9d21-33c0ae9ed3c0".into(),
        };

        let error = super::scan_all_distributions(&reqwest::blocking::Client::new(), &rules, &job)
            .unwrap_err();

        assert!(error.to_string().contains("distribution limit"));
    }

    #[test]
    fn test_get_matched_rules() {
        let file_scan_results = vec![
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule1"),
                        score: 5,
                    },
                    RuleScore {
                        name: String::from("rule2"),
                        score: 7,
                    },
                ],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule2"),
                        score: 7,
                    },
                    RuleScore {
                        name: String::from("rule3"),
                        score: 9,
                    },
                ],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule3"),
                        score: 9,
                    },
                    RuleScore {
                        name: String::from("rule4"),
                        score: 6,
                    },
                ],
            },
        ];

        let distribution_scan_results = DistributionScanResults::new(
            file_scan_results,
            reqwest::Url::parse("https://example.net").unwrap(),
        );

        let matched_rules: HashSet<RuleScore> = distribution_scan_results
            .get_matched_rules()
            .into_iter()
            .cloned()
            .collect();

        let expected_rules = HashSet::from([
            RuleScore {
                name: String::from("rule1"),
                score: 5,
            },
            RuleScore {
                name: String::from("rule2"),
                score: 7,
            },
            RuleScore {
                name: String::from("rule3"),
                score: 9,
            },
            RuleScore {
                name: String::from("rule4"),
                score: 6,
            },
        ]);

        assert_eq!(matched_rules, expected_rules);
    }

    #[test]
    fn test_get_matched_rule_identifiers() {
        let file_scan_results = vec![
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule1"),
                        score: 5,
                    },
                    RuleScore {
                        name: String::from("rule2"),
                        score: 7,
                    },
                ],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule2"),
                        score: 7,
                    },
                    RuleScore {
                        name: String::from("rule3"),
                        score: 9,
                    },
                ],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule3"),
                        score: 9,
                    },
                    RuleScore {
                        name: String::from("rule4"),
                        score: 6,
                    },
                ],
            },
        ];

        let distribution_scan_results = DistributionScanResults::new(
            file_scan_results,
            reqwest::Url::parse("https://example.net").unwrap(),
        );

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
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule1"),
                    score: 5,
                }],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule2"),
                    score: 7,
                }],
            },
        ];
        let distribution_scan_results1 = DistributionScanResults::new(
            file_scan_results1,
            reqwest::Url::parse("https://example.net/distrib1.tar.gz").unwrap(),
        );

        let file_scan_results2 = vec![
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![
                    RuleScore {
                        name: String::from("rule2"),
                        score: 7,
                    },
                    RuleScore {
                        name: String::from("rule3"),
                        score: 2,
                    },
                ],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule4"),
                    score: 9,
                }],
            },
        ];
        let distribution_scan_results2 = DistributionScanResults::new(
            file_scan_results2,
            reqwest::Url::parse("https://example.net/distrib2.whl").unwrap(),
        );

        let package_scan_results = PackageScanResults {
            name: String::from("remmy"),
            version: String::from("4.20.69"),
            attempt: 2,
            assignment_id: String::from("e42e7f1e-1de7-443e-ad34-3ebdff663605"),
            distribution_scan_results: vec![distribution_scan_results1, distribution_scan_results2],
            commit_hash: String::from("abc"),
        };

        let body = package_scan_results.build_body();

        assert_eq!(
            body.inspector_url,
            Some(String::from("https://example.net/distrib2.whl"))
        );
        assert_eq!(body.score, 18);
        assert_eq!(body.attempt, 2);
        assert_eq!(body.assignment_id, "e42e7f1e-1de7-443e-ad34-3ebdff663605");
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

        let tempdir = tempdir().unwrap();
        let archive_root = tempfile::Builder::new().tempdir_in(tempdir.path()).unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new_in(archive_root.path()).unwrap();

        writeln!(&mut tmpfile, "I hate Rust >:(").unwrap();

        let distro = super::Distribution {
            dir: tempdir,
            inspector_url: "https://example.com".parse().unwrap(),
        };

        let result = distro.scan_file(tmpfile.path(), &rules, 1024).unwrap();

        assert_eq!(
            result.rules[0],
            RuleScore {
                name: "contains_rust".into(),
                score: 5
            }
        );
        assert_eq!(result.calculate_score(), 5);
    }

    #[test]
    fn scan_file_rejects_files_over_the_limit_before_yara() {
        let rules = Compiler::new()
            .unwrap()
            .add_rules_str("rule never { condition: false }")
            .unwrap()
            .compile_rules()
            .unwrap();
        let tempdir = tempdir().unwrap();
        let mut tmpfile = tempfile::NamedTempFile::new_in(tempdir.path()).unwrap();
        tmpfile.write_all(b"12345").unwrap();
        let distro = super::Distribution {
            dir: tempdir,
            inspector_url: "https://example.com".parse().unwrap(),
        };

        let error = distro.scan_file(tmpfile.path(), &rules, 4).unwrap_err();

        assert!(error.to_string().contains("4-byte scan limit"));
    }

    #[test]
    fn test_relative_to_archive_root() {
        let tempdir = tempdir().unwrap();

        let input_path = &tempdir.path().join("name-version").join("README.md");
        let expected_path = PathBuf::from("name-version/README.md");

        let distro = super::Distribution {
            dir: tempdir,
            inspector_url: "https://example.com".parse().unwrap(),
        };

        let result = distro.relative_to_archive_root(input_path).unwrap();

        assert_eq!(expected_path, result);
    }

    #[test]
    fn scan_skips_directories() {
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
        let tempdir = tempdir().unwrap();
        let _subtempdir = tempdir_in(tempdir.path()).unwrap();
        let mut tempfile = tempfile::NamedTempFile::new_in(tempdir.path()).unwrap();
        writeln!(&mut tempfile, "rust").unwrap();

        let mut distro = super::Distribution {
            dir: tempdir,
            inspector_url: "https://example.com".parse().unwrap(),
        };

        let results = distro.scan(&rules, 1024).unwrap();

        assert_eq!(results.get_most_malicious_file().unwrap().rules.len(), 1);
    }
}
