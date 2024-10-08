use std::path::PathBuf;
use std::{collections::HashSet, path::Path};

use color_eyre::Result;
use reqwest::{blocking::Client, Url};
use tempfile::TempDir;
use walkdir::WalkDir;
use yara::Rules;

use crate::{
    client::{download_distribution, Job, SubmitJobResultsSuccess},
    exts::RuleExt,
    utils::create_inspector_url,
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
    fn scan(&mut self, rules: &Rules) -> Result<DistributionScanResults> {
        let mut file_scan_results: Vec<FileScanResult> = Vec::new();
        for entry in WalkDir::new(self.dir.path())
            .into_iter()
            .filter_map(|dirent| dirent.into_iter().find(|de| de.file_type().is_file()))
        {
            let file_scan_result = self.scan_file(entry.path(), rules)?;
            file_scan_results.push(file_scan_result);
        }

        Ok(DistributionScanResults::new(
            file_scan_results,
            self.inspector_url.clone(),
        ))
    }

    /// Scan a file given it's path, and compiled rules.
    ///
    /// # Arguments
    /// * `path` - The path of the file to scan.
    /// * `rules` - The compiled rule set to scan this file against
    fn scan_file(&self, path: &Path, rules: &Rules) -> Result<FileScanResult> {
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
    /// The scan results for each file in this distribution
    file_scan_results: Vec<FileScanResult>,

    /// The inspector URL pointing to this distribution's base
    inspector_url: Url,
}

impl DistributionScanResults {
    /// Create a new `DistributionScanResults` based off the results of its files and the base
    /// inspector URL for this distribution.
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
) -> Result<Vec<DistributionScanResults>> {
    let mut distribution_scan_results = Vec::with_capacity(job.distributions.len());
    for distribution in &job.distributions {
        let download_url: Url = distribution.parse().unwrap();
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let dir = download_distribution(http_client, download_url.clone())?;

        let mut dist = Distribution { dir, inspector_url };
        let distribution_scan_result = dist.scan(rules)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}

#[cfg(test)]
mod tests {
    use super::{DistributionScanResults, PackageScanResults};
    use crate::{
        client::{ScanResultSerializer, SubmitJobResultsError, SubmitJobResultsSuccess},
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
            score: 10,
            inspector_url: Some("inspector url".into()),
            rules_matched: vec!["abc".into(), "def".into()],
            commit: "commit hash".into(),
        };

        let scan_result: ScanResultSerializer = Ok(success).into();
        let actual = serde_json::to_string(&scan_result).unwrap();
        let expected = r#"{"name":"test","version":"1.0.0","score":10,"inspector_url":"inspector url","rules_matched":["abc","def"],"commit":"commit hash"}"#;

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

        let distribution_scan_results = DistributionScanResults {
            file_scan_results,
            inspector_url: reqwest::Url::parse("https://example.net").unwrap(),
        };

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

        let distribution_scan_results = DistributionScanResults {
            file_scan_results,
            inspector_url: reqwest::Url::parse("https://example.net").unwrap(),
        };

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

        let distribution_scan_results = DistributionScanResults {
            file_scan_results,
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
        let distribution_scan_results1 = DistributionScanResults {
            file_scan_results: file_scan_results1,
            inspector_url: reqwest::Url::parse("https://example.net/distrib1.tar.gz").unwrap(),
        };

        let file_scan_results2 = vec![
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule3"),
                    score: 2,
                }],
            },
            FileScanResult {
                path: PathBuf::default(),
                rules: vec![RuleScore {
                    name: String::from("rule4"),
                    score: 9,
                }],
            },
        ];
        let distribution_scan_results2 = DistributionScanResults {
            file_scan_results: file_scan_results2,
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
            Some(String::from("https://example.net/distrib1.tar.gz"))
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

        let tempdir = tempdir().unwrap();
        let archive_root = tempfile::Builder::new().tempdir_in(tempdir.path()).unwrap();

        let mut tmpfile = tempfile::NamedTempFile::new_in(archive_root.path()).unwrap();

        writeln!(&mut tmpfile, "I hate Rust >:(").unwrap();

        let distro = super::Distribution {
            dir: tempdir,
            inspector_url: "https://example.com".parse().unwrap(),
        };

        let result = distro.scan_file(tmpfile.path(), &rules).unwrap();

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

        let results = distro.scan(&rules).unwrap();

        assert_eq!(results.file_scan_results.len(), 1);
    }
}
