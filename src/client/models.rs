use color_eyre::Result;
use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;
use std::fmt::Display;
use yara::{Compiler, Rules};

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
