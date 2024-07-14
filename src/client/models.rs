use color_eyre::Result;
use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;
use std::fmt::Display;

pub type ScanResult = Result<SubmitJobResultsSuccess, SubmitJobResultsError>;

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
    pub fn compile(&self) -> Result<yara_x::Rules> {
        let rules_str = self
            .rules
            .values()
            .map(String::as_ref)
            .collect::<Vec<&str>>()
            .join("\n");

        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(rules_str.as_str())?;

        let rules = compiler.build();

        Ok(rules)
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
