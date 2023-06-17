use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
    sync::Mutex,
};

use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use yara::Compiler;
use zip::ZipArchive;

use crate::error::DragonflyError;

const BASE_URL: &str = env!("DRAGONFLY_BASE_URL");
const MAX_SIZE: usize = 250_000_000; // 250 MB

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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GetJobResponse {
    Job(Job),
    Error { detail: String },
}

#[derive(Debug, Deserialize)]
pub struct GetRulesResponse {
    hash: String,
    rules: HashMap<String, String>,
}

pub struct State {
    pub rules: yara::Rules,
    pub hash: String,
}

pub struct DragonflyClient {
    pub client: Client,
    pub state: Mutex<State>,
}

fn fetch_rules(client: &Client) -> Result<GetRulesResponse, reqwest::Error> {
    client.get(format!("{BASE_URL}/rules")).send()?.json()
}

impl State {
    pub fn new(rules: yara::Rules, hash: String) -> Self {
        Self { rules, hash }
    }

    pub fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    pub fn set_rules(&mut self, rules: yara::Rules) {
        self.rules = rules;
    }

    pub fn sync(&mut self, http_client: &Client) -> Result<(), DragonflyError> {
        let response = fetch_rules(http_client)?;

        let rules_str = response
            .rules
            .into_values()
            .collect::<Vec<String>>()
            .join("\n");

        let compiler = Compiler::new()?.add_rules_str(&rules_str)?;
        let compiled_rules = compiler.compile_rules()?;

        self.set_hash(response.hash);
        self.set_rules(compiled_rules);

        Ok(())
    }
}

impl DragonflyClient {
    pub fn new() -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;

        let response = fetch_rules(&client)?;
        let hash = response.hash;
        let rules_str = response
            .rules
            .into_values()
            .collect::<Vec<String>>()
            .join("\n");

        let compiler = Compiler::new()?.add_rules_str(&rules_str)?;
        let rules = compiler.compile_rules()?;

        let state: Mutex<State> = State::new(rules, hash).into();

        Ok(Self { client, state })
    }

    pub fn fetch_tarball(
        &self,
        download_url: &String,
    ) -> Result<tar::Archive<Cursor<Vec<u8>>>, DragonflyError> {
        let response = self.client.get(download_url).send()?;

        let mut decompressed = GzDecoder::new(response);
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let read = decompressed.read_to_end(cursor.get_mut())?;

        if read > MAX_SIZE {
            Err(DragonflyError::DownloadTooLarge(download_url.clone()))
        } else {
            Ok(tar::Archive::new(cursor))
        }
    }

    pub fn fetch_zipfile(
        &self,
        download_url: &String,
    ) -> Result<ZipArchive<Cursor<Vec<u8>>>, DragonflyError> {
        let mut response = self.client.get(download_url).send()?;

        let mut cursor = Cursor::new(Vec::new());
        let read = response.read_to_end(cursor.get_mut())?;

        if read > MAX_SIZE {
            Err(DragonflyError::DownloadTooLarge(download_url.clone()))
        } else {
            let zip = ZipArchive::new(cursor)?;
            Ok(zip)
        }
    }

    pub fn get_job(&self) -> reqwest::Result<Option<Job>> {
        let res: GetJobResponse = self.client.post(format!("{BASE_URL}/job")).send()?.json()?;

        let job = match res {
            GetJobResponse::Job(job) => Some(job),
            GetJobResponse::Error { .. } => None,
        };

        Ok(job)
    }

    pub fn submit_job_results(&self, body: &SubmitJobResultsBody) -> reqwest::Result<()> {
        self.client
            .put(format!("{BASE_URL}/package"))
            .json(&body)
            .send()?;

        Ok(())
    }

    pub fn get_http_client(&self) -> &Client {
        // Return a reference to the underlying HTTP Client
        &self.client
    }
}
