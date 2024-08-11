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

/// Owned version of yara::MetadataValue
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
    pub start: i32,
    pub end: i32,
}

impl FileScanResult {
    pub fn new(path: PathBuf, matches: Vec<Rule>) -> Self {
        let mut out = Vec::new();

        for match_ in matches {
            out.push(RuleMatch::new(match_));
        }

        Self { path, matches: out }
    }

    /// Returns the total score of all matched rules.
    pub fn calculate_score(&self) -> i64 {
        self.matches
            .iter()
            .map(|rule_match| rule_match.score())
            .sum()
    }
}

impl RuleMatch {
    pub fn new(rule: Rule) -> Self {
        Self {
            identifier: rule.identifier.to_string(),
            patterns: rule.strings.into_iter().map(PatternMatch::new).collect(),
            metadata: Self::map_from_metadata(rule.metadatas),
        }
    }

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

impl PatternMatch {
    pub fn new(yr_string: YrString) -> Self {
        Self {
            identifier: yr_string.identifier.to_string(),
            matches: yr_string.matches.into_iter().map(Match::new).collect(),
        }
    }
}

impl Match {
    pub fn new(match_: yara::Match) -> Self {
        Self {
            range: Range {
                start: match_.base as i32,
                end: match_.offset as i32,
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
    use crate::test::make_file_scan_result;

    #[test]
    fn test_serialize_file_scan_result() {
        let fsr = make_file_scan_result("ayo", &[("rule1", 5), ("rule2", 7)]);

        let actual = serde_json::to_value(&fsr).unwrap();
        let expected = serde_json::json!({
            "path": "ayo",
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
        });

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_file_score() {
        let fsr = make_file_scan_result("ayo", &[("rule1", 5), ("rule2", 7)]);
        assert_eq!(fsr.calculate_score(), 12);
    }
}
