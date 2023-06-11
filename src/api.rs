use std::{io::{Read, Cursor}, sync::Mutex};

use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use yara::{Compiler, Rules};
use zip::ZipArchive;

use crate::{error::DragonflyError, api_models::{GetRulesResponse, Job, GetJobResponse, SubmitJobResultsBody, AuthBody, AuthResponse}, AppConfig};

const MAX_SIZE: usize = 250000000;


pub struct State {
    pub rules: yara::Rules,
    pub hash: String,
    pub access_token: String,
}

pub struct DragonflyClient {
    pub config: AppConfig,
    pub client: Client,
    pub state: Mutex<State>,
}

fn fetch_rules(client: &Client, base_url: &str, access_token: &str) -> Result<(String, Rules), DragonflyError> {
    let res: GetRulesResponse = client.get(format!("{base_url}/rules"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()?
        .json()?;
    
    let rules_str = res.rules
        .iter()
        .map(|(_, v)| v.to_owned())
        .collect::<Vec<String>>()
        .join("\n");
    
    let compiler = Compiler::new()?
        .add_rules_str(&rules_str)?;
    let compiled_rules = compiler.compile_rules()?;

    Ok((res.hash, compiled_rules))
}

impl State {
    pub fn new(rules: yara::Rules, hash: String, access_token: String) -> Self {
        Self { rules, hash, access_token }
    }

    pub fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    pub fn set_rules(&mut self, rules: yara::Rules) {
        self.rules = rules;
    }
}

fn authorize(http_client: &Client, config: &AppConfig) -> Result<AuthResponse, reqwest::Error> {
    let url = format!("https://{}/oauth/token", config.auth0_domain) ;
    let json_body = AuthBody {
        client_id: &config.client_id,
        client_secret: &config.client_secret,
        audience: &config.audience,
        grant_type: &config.grant_type,
        username: &config.username,
        password: &config.password,
    };

    http_client.post(url)
        .json(&json_body)
        .send()?
        .json()
}

impl DragonflyClient {
    pub fn new(config: AppConfig) -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;
        
        let access_token = authorize(&client, &config)?.access_token;
        println!("ACCESS TOKEN: {access_token}");
        let (hash, rules) = fetch_rules(&client, &config.base_url, &access_token)?;
        
        let state: Mutex<State> = State::new(rules, hash, access_token).into();

        Ok(Self { 
            config,
            client, 
            state,
        })
    }

    pub fn fetch_tarball(&self, download_url: &String) -> Result<tar::Archive<Cursor<Vec<u8>>>, DragonflyError> {
        let response = self.client.get(download_url)
            .send()?;

        let mut decompressed = GzDecoder::new(response);
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let read = decompressed.read_to_end(cursor.get_mut())?;

        if read > MAX_SIZE {
            Err(DragonflyError::DownloadTooLarge(download_url.to_owned()))
        } else {
            Ok(tar::Archive::new(cursor))
        }
    }

    pub fn fetch_rules(&self) -> Result<(String, Rules), DragonflyError> {
        let state = self.state.lock().unwrap();
        fetch_rules(&self.get_http_client(), &self.config.base_url, &state.access_token)
    }

    pub fn fetch_zipfile(&self, download_url: &String) -> Result<ZipArchive<Cursor<Vec<u8>>>, DragonflyError> {
        let mut response = self.client.get(download_url)
            .send()?;

        let mut cursor = Cursor::new(Vec::new());
        let read = response.read_to_end(cursor.get_mut())?;

        if read > MAX_SIZE {
            Err(DragonflyError::DownloadTooLarge(download_url.to_owned()))
        } else {
            let zip = ZipArchive::new(cursor)?;
            Ok(zip)
        }
    }
    


    pub fn get_job(&self) -> reqwest::Result<Option<Job>> {
        let access_token = &self.state.lock().unwrap().access_token;
        let res: GetJobResponse = self.client.post(format!("{}/job", self.config.base_url))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()?
            .json()?;
        
        let job = match res {
            GetJobResponse::Job(job) => Some(job),
            GetJobResponse::Error {..} => None,
        };

        Ok(job)
    }

    pub fn submit_job_results(&self, body: SubmitJobResultsBody) -> reqwest::Result<()> {
        let access_token = &self.state.lock().unwrap().access_token;
        self.client.put(format!("{}/package", self.config.base_url))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&body)
            .send()?;

        Ok(())
    }

    pub fn get_http_client(&self) -> &Client {
        // Return a reference to the underlying HTTP Client
        &self.client
    }
}
