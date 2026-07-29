use color_eyre::Result;
use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;
use std::fmt::Display;
use yara::{Compiler, Rules, ScanFlags};

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
    pub attempt: u64,
    pub assignment_id: String,
    pub score: i64,
    pub inspector_url: Option<String>,

    /// Contains all rule identifiers matched for the entire release.
    pub rules_matched: Vec<String>,

    /// The commit hash of the ruleset used to produce these results.
    pub commit: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SubmitJobResultsError {
    pub name: String,
    pub version: String,
    pub attempt: u64,
    pub assignment_id: String,
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

#[derive(Debug, Deserialize, PartialEq)]
pub struct Job {
    pub hash: String,
    pub name: String,
    pub version: String,
    pub distributions: Vec<String>,
    pub attempt: u64,
    pub assignment_id: String,
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

        let mut compiled_rules = Compiler::new()?
            .add_rules_str(&rules_str)?
            .compile_rules()?;
        compiled_rules.set_flags(ScanFlags::FAST_MODE);

        Ok(compiled_rules)
    }
}

#[cfg(test)]
mod tests {
    use super::Job;

    #[test]
    fn job_deserializes_assignment_lease() {
        let job: Job = serde_json::from_str(
            r#"{
                "hash": "rules-commit",
                "name": "example",
                "version": "1.2.3",
                "distributions": ["https://example.com/example.whl"],
                "attempt": 2,
                "assignment_id": "4e3702e8-27a3-46e6-b51c-4779a94fa4ab"
            }"#,
        )
        .unwrap();

        assert_eq!(job.attempt, 2);
        assert_eq!(job.assignment_id, "4e3702e8-27a3-46e6-b51c-4779a94fa4ab");
    }

    #[test]
    fn job_requires_assignment_lease() {
        let result = serde_json::from_str::<Job>(
            r#"{
                "hash": "rules-commit",
                "name": "example",
                "version": "1.2.3",
                "distributions": []
            }"#,
        );

        assert!(result.is_err());
    }
}
