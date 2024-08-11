use color_eyre::Result;
use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use yara::{Compiler, Metadata, Rule, Rules, YrString};

pub type ScanResult = Result<SubmitJobResultsSuccess, SubmitJobResultsError>;

#[derive(Serialize, Debug)]
#[serde(untagged)]
#[serde(remote = "ScanResult")]
enum ScanResultDef {
    Ok(SubmitJobResultsSuccess),
    Err(SubmitJobResultsError),
}

#[derive(Serialize)]
pub struct ScanResultSerializer(#[serde(with = "ScanResultDef")] ScanResult);

impl From<ScanResult> for ScanResultSerializer {
    fn from(value: ScanResult) -> Self {
        Self(value)
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SubmitJobResultsSuccess {
    pub name: String,
    pub version: String,
    pub score: i64,
    pub inspector_url: Option<String>,

    /// Contains all rule identifiers matched for the entire release.
    pub rules_matched: Vec<String>,

    /// The commit hash of the ruleset used to produce these results.
    pub commit: String,

    pub distributions: Vec<DistributionScanResult>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct DistributionScanResult {
    pub download_url: String,
    pub files: Vec<FileScanResult>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub matches: Vec<RuleMatch>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RuleMatch {
    pub identifier: String,
    pub patterns: Vec<PatternMatch>,
    pub metadata: HashMap<String, MetadataValue>,
}

/// Owned version of [`yara::MetadataValue`]
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum MetadataValue {
    Integer(i64),
    String(String),
    Boolean(bool),
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PatternMatch {
    pub identifier: String,
    pub matches: Vec<Match>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Match {
    pub range: Range,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Range {
    pub start: usize,
    pub end: usize,
}

impl DistributionScanResult {
    pub fn new(download_url: String, files: Vec<FileScanResult>) -> Self {
        let filtered = files
            .into_iter()
            .filter(|file| !file.matches.is_empty())
            .collect();

        Self {
            download_url,
            files: filtered,
        }
    }
}

impl FileScanResult {
    pub fn new(path: PathBuf, matches: Vec<Rule>) -> Self {
        Self {
            path,
            matches: matches.into_iter().map(RuleMatch::from).collect(),
        }
    }

    /// Returns the total score of all matched rules.
    pub fn calculate_score(&self) -> i64 {
        self.matches.iter().map(RuleMatch::score).sum()
    }
}

impl From<Rule<'_>> for RuleMatch {
    fn from(rule: Rule) -> Self {
        Self {
            identifier: rule.identifier.to_string(),
            patterns: rule
                .strings
                .into_iter()
                .filter(|yr_string| !yr_string.matches.is_empty())
                .map(PatternMatch::from)
                .collect(),
            metadata: Self::map_from_metadata(rule.metadatas),
        }
    }
}

impl RuleMatch {
    pub fn score(&self) -> i64 {
        if let Some(&MetadataValue::Integer(score)) = self.metadata.get("weight") {
            score
        } else {
            0
        }
    }

    fn map_from_metadata(metadata: Vec<Metadata>) -> HashMap<String, MetadataValue> {
        let mut out = HashMap::new();

        for val in metadata {
            let metadata_value = match val.value {
                yara::MetadataValue::Integer(i) => MetadataValue::Integer(i),
                yara::MetadataValue::String(s) => MetadataValue::String(s.to_string()),
                yara::MetadataValue::Boolean(b) => MetadataValue::Boolean(b),
            };
            out.insert(val.identifier.to_string(), metadata_value);
        }

        out
    }
}

impl From<YrString<'_>> for PatternMatch {
    fn from(yr_string: YrString) -> Self {
        Self {
            identifier: yr_string.identifier.to_string(),
            matches: yr_string.matches.into_iter().map(Match::from).collect(),
        }
    }
}

impl From<yara::Match> for Match {
    fn from(match_: yara::Match) -> Self {
        Self {
            range: Range {
                start: match_.offset,

                // Fish assures me that we cannot have zero length matches, so this should never underflow
                end: match_.offset + match_.data.len() - 1,
            },
            data: match_.data,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SubmitJobResultsError {
    pub name: String,
    pub version: String,
    pub reason: String,
}

impl Display for SubmitJobResultsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Name: {}", self.name)?;
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Reason: {}", self.reason)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct Job {
    pub hash: String,
    pub name: String,
    pub version: String,
    pub distributions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RulesResponse {
    pub hash: String,
    pub rules: HashMap<String, String>,
}

impl RulesResponse {
    /// Compile the rules from the response
    pub fn compile(&self) -> Result<Rules> {
        let rules_str = self
            .rules
            .values()
            .map(String::as_ref)
            .collect::<Vec<&str>>()
            .join("\n");

        let compiled_rules = Compiler::new()?
            .add_rules_str(&rules_str)?
            .compile_rules()?;

        Ok(compiled_rules)
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub expires_in: u32,
}

#[derive(Debug, Serialize)]
pub struct AuthBody<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub audience: &'a str,
    pub grant_type: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

#[cfg(test)]
mod tests {
    use crate::client::DistributionScanResult;
    use crate::test::make_file_scan_result;

    #[test]
    fn test_serialize_distribution_scan_result() {
        let fsrs = vec![
            make_file_scan_result("file1", &[("rule1", 5), ("rule2", 7)]),
            make_file_scan_result("file2", &[("rule5", 100), ("rule3", 1)]),
        ];

        let distro = DistributionScanResult::new("https://example.com".into(), fsrs);

        let actual = serde_json::to_value(&distro).unwrap();
        let expected = serde_json::json!({
            "download_url": "https://example.com",
            "files": [
                {
                    "path": "file1",
                    "matches": [
                        {
                            "identifier": "rule1",
                            "patterns": [],
                            "metadata": {
                                "weight": 5,
                            }
                        },
                        {
                            "identifier": "rule2",
                            "patterns": [],
                            "metadata": {
                                "weight": 7,
                            }
                        }
                    ]
                },
                {
                    "path": "file2",
                    "matches": [
                        {
                            "identifier": "rule5",
                            "patterns": [],
                            "metadata": {
                                "weight": 100,
                            }
                        },
                        {
                            "identifier": "rule3",
                            "patterns": [],
                            "metadata": {
                                "weight": 1,
                            }
                        }
                    ]
                }
            ]
        });

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_file_score() {
        let fsr = make_file_scan_result("ayo", &[("rule1", 5), ("rule2", 7)]);
        assert_eq!(fsr.calculate_score(), 12);
    }
}
