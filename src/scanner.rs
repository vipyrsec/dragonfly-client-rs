use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};

use reqwest::{blocking::Client, Url};
use yara_x::Rules;

use crate::{
    client::{fetch_tarball, fetch_zipfile, Job, SubmitJobResultsSuccess, TarballType, ZipType},
    error::DragonflyError,
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
    rules: &yara_x::Rules,
) -> Result<FileScanResult, DragonflyError> {
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut scanner = yara_x::Scanner::new(rules);

    let rules = scanner
        .scan(buffer.as_slice())?
        .matching_rules()
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::PathBuf};
    use yara_x::Compiler;

    use super::{scan_file, DistributionScanResults, PackageScanResults};
    use crate::scanner::{FileScanResult, RuleScore};

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
        )
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

        assert_eq!(matched_rules, expected_rules)
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
        )
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

        let mut compiler = Compiler::new();
        compiler.add_source(rules).unwrap();
        let rules = compiler.build();

        let result =
            scan_file(&mut "I love Rust!".as_bytes(), &PathBuf::default(), &rules).unwrap();

        assert_eq!(result.path, PathBuf::default());
        assert_eq!(
            result.rules[0],
            RuleScore {
                name: "contains_rust".into(),
                score: 5
            }
        );
        assert_eq!(result.calculate_score(), 5);
    }
}
