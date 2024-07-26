use core::fmt;
use std::{
    collections::HashSet,
    fmt::write,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use color_eyre::{eyre::eyre, Result};
use flate2::read::GzDecoder;
use reqwest::{blocking::Client, Url};
use tracing::{debug, warn};
use yara::Rules;
use zip::read::read_zipfile_from_stream;

use crate::{
    app_config::APP_CONFIG,
    client::{fetch_tarball, fetch_zipfile, Job},
    exts::RuleExt,
    utils::create_inspector_url,
};

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct RuleScore {
    pub name: String,
    pub score: i64,
}

/// The results of scanning a single file. Contains the file path and the rules it matched
#[derive(Debug, PartialEq)]
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

/// Struct representing the results of a scanned distribution
#[derive(Debug)]
pub struct DistributionScanResults {
    /// The scan results for each file in this distribution
    file_scan_results: Vec<FileScanResult>,

    /// Inspector URL pointing to the base of this distribution
    base_inspector_url: String,
}

impl DistributionScanResults {
    /// Create a new `DistributionScanResults` based off the results of its files and the base
    /// inspector URL for this distribution.
    pub fn new(file_scan_results: Vec<FileScanResult>, base_inspector_url: String) -> Self {
        Self {
            file_scan_results,
            base_inspector_url,
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
            let it = file
                .path
                .components()
                .filter(|c| !matches!(c, Component::RootDir))
                .map(|c| c.as_os_str().to_string_lossy());
            let mut url: Url = self.base_inspector_url.parse().unwrap();
            url.path_segments_mut().unwrap().pop_if_empty().extend(it);
            url.to_string()
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
        let base_inspector_url =
            create_inspector_url(&job.name, &job.version, &download_url).to_string();

        let distribution_scan_result: DistributionScanResults = if distribution.ends_with(".tar.gz")
        {
            let mut tar = fetch_tarball(http_client, &download_url)?;
            let file_scan_results = scan_targz(&mut tar, rules)?;
            DistributionScanResults::new(file_scan_results, base_inspector_url)
        } else {
            let mut response = fetch_zipfile(http_client, &download_url)?;
            let file_scan_results = scan_zip(&mut response, rules)?;
            DistributionScanResults::new(file_scan_results, base_inspector_url)
        };

        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)
}

pub fn scan_targz<R: Read>(
    tar: &mut tar::Archive<GzDecoder<R>>,
    rules: &Rules,
) -> Result<Vec<FileScanResult>> {
    let mut file_scan_results: Vec<FileScanResult> = Vec::new();

    for mut entry in tar.entries()?.filter_map(Result::ok) {
        let pathbuf = entry.path()?.to_path_buf();
        if entry.size() <= APP_CONFIG.max_scan_size {
            let mut buf = Vec::with_capacity(entry.size().try_into().unwrap_or_default());
            entry.read_to_end(&mut buf)?;

            let instant = Instant::now();
            let result = scan_buf(buf.as_slice(), pathbuf.as_path(), rules)?;
            let elapsed = instant.elapsed();

            debug!(
                "Finished scanning {} in {} ms",
                pathbuf.to_string_lossy(),
                elapsed.as_millis()
            );

            file_scan_results.push(result);
        } else {
            return Err(eyre!(
                "File {} too large, {} bytes > {} bytes",
                pathbuf.to_string_lossy(),
                entry.size(),
                APP_CONFIG.max_scan_size
            ));
        }
    }

    Ok(file_scan_results)
}

pub fn scan_zip<R: Read>(source: &mut R, rules: &Rules) -> Result<Vec<FileScanResult>> {
    let mut file_scan_results: Vec<FileScanResult> = Vec::new();
    while let Ok(Some(mut file)) = read_zipfile_from_stream(source) {
        if let Some(pathbuf) = file.enclosed_name() {
            if file.size() <= APP_CONFIG.max_scan_size {
                let mut buf = Vec::with_capacity(file.size().try_into().unwrap_or_default());
                file.read_to_end(&mut buf)?;

                let instant = Instant::now();
                let result = scan_buf(buf.as_slice(), pathbuf.as_path(), rules)?;
                let elapsed = instant.elapsed();

                debug!(
                    "Finished scanning {} in {} ms",
                    pathbuf.to_string_lossy(),
                    elapsed.as_millis()
                );

                file_scan_results.push(result);
            } else {
                warn!(
                    "{} is greater than maximum configured scan size ({} bytes), skipping",
                    pathbuf.to_string_lossy(),
                    APP_CONFIG.max_scan_size
                );
                return Err(eyre!(
                    "File {} too large, {} bytes > {} bytes",
                    pathbuf.to_string_lossy(),
                    file.size(),
                    APP_CONFIG.max_scan_size
                ));
            };
        } else {
            warn!("{} could not be parsed into a path, skipping", file.name());
        }
    }

    Ok(file_scan_results)
}

/// Scan a file given it implements `Read`.
///
/// # Arguments
/// * `path` - The path corresponding to this file
/// * `rules` - The compiled rule set to scan this file against
fn scan_buf(buf: &[u8], path: &Path, rules: &Rules) -> Result<FileScanResult> {
    let rules = rules
        .scan_mem(buf, 10)?
        .into_iter()
        .filter(|rule| {
            let filetypes = rule.get_filetypes();
            filetypes.is_empty()
                || filetypes
                    .iter()
                    .any(|filetype| path.extension().unwrap_or_default() == *filetype)
        })
        .map(RuleScore::from)
        .collect();

    Ok(FileScanResult::new(path.to_path_buf(), rules))
}

#[cfg(test)]
mod tests {
    use flate2::{read::GzDecoder, write::GzEncoder, Compression};
    use std::{
        collections::HashSet,
        io::{Cursor, Write},
        path::PathBuf,
    };
    use yara::{Compiler, Rules};
    use zip::{write::SimpleFileOptions, ZipWriter};

    use super::{scan_buf, DistributionScanResults, PackageScanResults};
    use crate::{
        client::{
            build_body, ScanResultSerializer, SubmitJobResultsError, SubmitJobResultsSuccess,
        },
        scanner::{scan_targz, scan_zip, FileScanResult, RuleScore},
    };

    fn generate_sample_rules() -> Rules {
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

        compiler.compile_rules().unwrap()
    }

    #[test]
    fn test_zipfile() {
        let mut buf: Vec<u8> = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("file1.txt", options).unwrap();
        let file1_contents = b"rust";
        zip.write(file1_contents).unwrap();

        zip.start_file("file2.txt", options).unwrap();
        let file2_contents = b"contents of file two";
        zip.write(file2_contents).unwrap();

        zip.finish().unwrap();

        let rules = generate_sample_rules();
        let mut file_scan_results = scan_zip(&mut &buf[..], &rules).unwrap().into_iter();

        let expected = FileScanResult {
            path: PathBuf::from("file1.txt"),
            rules: vec![RuleScore {
                name: "contains_rust".into(),
                score: 5,
            }],
        };
        assert_eq!(file_scan_results.next(), Some(expected));

        let expected = FileScanResult {
            path: PathBuf::from("file2.txt"),
            rules: vec![],
        };
        assert_eq!(file_scan_results.next(), Some(expected));

        assert_eq!(file_scan_results.next(), None);
    }

    #[test]
    fn test_tarball() {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));

        let mut header = tar::Header::new_gnu();
        let file1_contents = b"rust";
        header.set_size(file1_contents.len().try_into().unwrap());
        header.set_cksum();
        builder
            .append_data(&mut header, "file1.txt", file1_contents.as_slice())
            .unwrap();

        let mut header = tar::Header::new_gnu();
        let file2_contents = b"contents of file two";
        header.set_size(file2_contents.len().try_into().unwrap());
        header.set_cksum();
        builder
            .append_data(&mut header, "file2.txt", file2_contents.as_slice())
            .unwrap();

        let data = builder.into_inner().unwrap().finish().unwrap();

        let mut archive = tar::Archive::new(GzDecoder::new(data.as_slice()));

        let rules = generate_sample_rules();
        let mut file_scan_results = scan_targz(&mut archive, &rules).unwrap().into_iter();

        let expected = FileScanResult {
            path: PathBuf::from("file1.txt"),
            rules: vec![RuleScore {
                name: "contains_rust".into(),
                score: 5,
            }],
        };
        assert_eq!(file_scan_results.next(), Some(expected));

        let expected = FileScanResult {
            path: PathBuf::from("file2.txt"),
            rules: vec![],
        };
        assert_eq!(file_scan_results.next(), Some(expected));

        assert_eq!(file_scan_results.next(), None);
    }

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
                path: PathBuf::from("/abc/file1"),
                rules: vec![RuleScore {
                    name: String::from("rule1"),
                    score: 5,
                }],
            },
            FileScanResult {
                path: PathBuf::from("/abc/file2"),
                rules: vec![RuleScore {
                    name: String::from("rule2"),
                    score: 7,
                }],
            },
            FileScanResult {
                path: PathBuf::from("/abc/file3"),
                rules: vec![RuleScore {
                    name: String::from("rule3"),
                    score: 4,
                }],
            },
        ];

        let expected = FileScanResult {
            path: PathBuf::from("/abc/file2"),
            rules: vec![RuleScore {
                name: String::from("rule2"),
                score: 7,
            }],
        };

        let distribution_scan_results = DistributionScanResults {
            file_scan_results,
            base_inspector_url: String::default(),
        };

        assert_eq!(
            distribution_scan_results.get_most_malicious_file(),
            Some(&expected)
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
            base_inspector_url: String::default(),
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
            base_inspector_url: String::default(),
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
                path: "abc/file1.txt".into(),
                rules: vec![RuleScore {
                    name: String::from("rule1"),
                    score: 5,
                }],
            },
            FileScanResult {
                path: "abc/file2.txt".into(),
                rules: vec![RuleScore {
                    name: String::from("rule2"),
                    score: 7,
                }],
            },
        ];
        let distribution_scan_results1 = DistributionScanResults {
            file_scan_results: file_scan_results1,
            base_inspector_url: "http://example.com/dist1/".into(),
        };

        let file_scan_results2 = vec![
            FileScanResult {
                path: "abc/file1.txt".into(),
                rules: vec![RuleScore {
                    name: String::from("rule3"),
                    score: 2,
                }],
            },
            FileScanResult {
                path: "abc/file1.txt".into(),
                rules: vec![RuleScore {
                    name: String::from("rule4"),
                    score: 9,
                }],
            },
        ];
        let distribution_scan_results2 = DistributionScanResults {
            file_scan_results: file_scan_results2,
            base_inspector_url: "http://example.com/dist2/".into(),
        };

        let package_scan_results = PackageScanResults {
            name: String::from("remmy"),
            version: String::from("4.20.69"),
            distribution_scan_results: vec![distribution_scan_results1, distribution_scan_results2],
            commit_hash: String::from("abc"),
        };

        let body = build_body(&package_scan_results);

        assert_eq!(
            body.inspector_url,
            Some(String::from("http://example.com/dist1/abc/file2.txt"))
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
        let result = scan_buf(&mut "I love Rust!".as_bytes(), &PathBuf::default(), &rules).unwrap();

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
