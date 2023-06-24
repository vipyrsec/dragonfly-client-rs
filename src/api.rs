use std::{
    collections::HashSet,
    io::{Cursor, Read},
    sync::Mutex,
};

use chrono::{DateTime, Duration, Local};
use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use yara::{Compiler, Rules};
use zip::ZipArchive;

use crate::{
    api_models::{
        AuthBody, AuthResponse, GetJobResponse, GetRulesResponse, Job, SubmitJobResultsBody,
    },
    error::DragonflyError,
    AppConfig,
};

const MAX_SIZE: usize = 250_000_000;

pub struct AuthenticationInformation {
    pub access_token: String,
    pub expires_at: DateTime<Local>,
}

pub struct State {
    pub rules: yara::Rules,
    pub hash: String,
    pub authentication_information: AuthenticationInformation,
}

pub struct DragonflyClient {
    pub config: AppConfig,
    pub client: Client,
    pub state: Mutex<State>,
}

fn fetch_rules(
    client: &Client,
    base_url: &str,
    access_token: &str,
) -> Result<(String, Rules), DragonflyError> {
    let res: GetRulesResponse = client
        .get(format!("{base_url}/rules"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()?
        .error_for_status()?
        .json()?;

    let rules_str = res
        .rules
        .values()
        .cloned()
        .collect::<Vec<String>>()
        .join("\n");

    let compiler = Compiler::new()?.add_rules_str(&rules_str)?;
    let compiled_rules = compiler.compile_rules()?;

    Ok((res.hash, compiled_rules))
}

impl State {
    pub fn new(
        rules: yara::Rules,
        hash: String,
        authentication_information: AuthenticationInformation,
    ) -> Self {
        Self {
            rules,
            hash,
            authentication_information,
        }
    }

    pub fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    pub fn set_rules(&mut self, rules: yara::Rules) {
        self.rules = rules;
    }
}

fn authorize(
    http_client: &Client,
    config: &AppConfig,
) -> Result<AuthenticationInformation, reqwest::Error> {
    let url = format!("https://{}/oauth/token", config.auth0_domain);
    let json_body = AuthBody {
        client_id: &config.client_id,
        client_secret: &config.client_secret,
        audience: &config.audience,
        grant_type: &config.grant_type,
        username: &config.username,
        password: &config.password,
    };

    let res: AuthResponse = http_client
        .post(url)
        .json(&json_body)
        .send()?
        .error_for_status()?
        .json()?;

    let access_token = res.access_token;
    let expires_at = Local::now() + Duration::seconds(i64::from(res.expires_in));

    Ok(AuthenticationInformation {
        access_token,
        expires_at,
    })
}

impl DragonflyClient {
    pub fn new(config: AppConfig) -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;

        let auth_info = authorize(&client, &config)?;
        let (hash, rules) = fetch_rules(&client, &config.base_url, &auth_info.access_token)?;
        let state: Mutex<State> = State::new(rules, hash, auth_info).into();

        Ok(Self {
            config,
            client,
            state,
        })
    }

    pub fn reauthorize(&self) -> Result<(), reqwest::Error> {
        let auth_info = authorize(self.get_http_client(), &self.config)?;
        let mut state = self.state.lock().unwrap();

        state.authentication_information = auth_info;

        Ok(())
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

    pub fn fetch_rules(&self) -> Result<(String, Rules), DragonflyError> {
        let state = self.state.lock().unwrap();
        fetch_rules(
            self.get_http_client(),
            &self.config.base_url,
            &state.authentication_information.access_token,
        )
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
        let access_token = &self
            .state
            .lock()
            .unwrap()
            .authentication_information
            .access_token;
        let res: GetJobResponse = self
            .client
            .post(format!("{}/job", self.config.base_url))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()?
            .error_for_status()?
            .json()?;

        let job = match res {
            GetJobResponse::Job(job) => Some(job),
            GetJobResponse::Error { .. } => None,
        };

        Ok(job)
    }

    pub fn submit_job_results(
        &self,
        job: &Job,
        score: i64,
        inspector_url: Option<&str>,
        rules_matched: &HashSet<&str>,
    ) -> reqwest::Result<()> {
        let state = self.state.lock().unwrap();
        let access_token = &state.authentication_information.access_token;
        let commit = &state.hash;
        let url = format!("{}/package", self.config.base_url);

        let body = SubmitJobResultsBody {
            name: &job.name,
            version: &job.version,
            score,
            inspector_url,
            rules_matched,
            commit,
        };

        self.client
            .put(url)
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&body)
            .send()?
            .error_for_status()?;

        Ok(())
    }

    pub fn get_http_client(&self) -> &Client {
        // Return a reference to the underlying HTTP Client
        &self.client
    }
}
