use serde::Serialize;
use serde::{self, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct SubmitJobResultsBody<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub score: i64,
    pub inspector_url: Option<&'a str>,

    /// Contains all rule identifiers matched for the entire release.
    pub rules_matched: &'a Vec<&'a str>,

    /// The commit hash of the ruleset used to produce these results.
    pub commit: &'a str,
}

#[derive(Debug, Serialize)]
pub struct SubmitJobResultsError<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub reason: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct Job {
    pub hash: String,
    pub name: String,
    pub version: String,
    pub distributions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetJobResponse {
    Job(Job),
    Error { detail: String },
}

#[derive(Debug, Deserialize)]
pub struct GetRulesResponse {
    pub hash: String,
    pub rules: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
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
