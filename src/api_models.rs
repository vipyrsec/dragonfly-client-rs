use std::collections::{HashSet, HashMap};
use serde::{self, Deserialize};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SubmitJobResultsBody<'a> {
    pub name: &'a String,
    pub version: &'a String,
    pub score: Option<i64>,
    pub inspector_url: Option<&'a String>,
    pub rules_matched: &'a HashSet<&'a String>,
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
    pub client_id: &'a String,
    pub client_secret: &'a String,
    pub audience: &'a String,
    pub grant_type: &'a String,
    pub username: &'a String,
    pub password: &'a String,
}
