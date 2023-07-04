use crate::{
    api_models::SubmitJobResultsError,
    common::{TarballType, ZipType},
    scanner::DistributionScanResults,
    APP_CONFIG,
};
use flate2::read::GzDecoder;
use reqwest::{blocking::Client, StatusCode, Url};
use std::{
    io::{Cursor, Read},
    sync::{RwLock, RwLockWriteGuard},
    time::Duration,
};
use tracing::{error, info, warn};
use yara::{Compiler, Rules};

use crate::{
    api_models::{
        AuthBody, AuthResponse, GetJobResponse, GetRulesResponse, Job, SubmitJobResultsBody,
    },
    error::DragonflyError,
};

/// Application state
pub struct State {
    /// The current ruleset this client is using
    pub rules: yara::Rules,

    /// The GitHub commit hash of the ruleset this client is using
    pub hash: String,

    /// Access token this client is using for authentication
    pub access_token: String,
}

pub struct DragonflyClient {
    pub client: Client,
    pub state: RwLock<State>,
}

impl DragonflyClient {
    pub fn new() -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;

        let access_token = Self::fetch_access_token(&client)?;
        let (hash, rules) = Self::fetch_rules(&client, &access_token)?;
        let state = State {
            rules,
            hash,
            access_token,
        }
        .into();

        Ok(Self { client, state })
    }

    /// Update the state with a new access token
    ///
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&self) {
        let mut state = self.state.write().unwrap();

        let access_token;

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        loop {
            let r = Self::fetch_access_token(self.get_http_client());
            match r {
                Ok(at) => {
                    access_token = at;
                    break;
                }
                Err(e) => {
                    let sleep_time = if tries < 10 {
                        let t = initial_timeout * base.powf(f64::from(tries));
                        warn!("Failed to reauthenticate after {tries} tries! Error: {e:#?}. Trying again in {t:.3} seconds");
                        t
                    } else {
                        error!("Failed to reauthenticate after {tries} tries! Error: {e:#?}. Trying again in 600.000 seconds");
                        600_f64
                    };

                    std::thread::sleep(Duration::from_secs_f64(sleep_time));
                    tries += 1;
                }
            }
        }

        info!("Successfully reauthenticated.");
        state.access_token = access_token;
    }

    /// Update the global ruleset.
    ///
    /// This function takes ownership of a [`RwLockWriteGuard`] and drops it when finished. This
    /// guarantees only one thread can update the rules at once.
    pub fn update_rules(&self, mut state: RwLockWriteGuard<State>) -> Result<(), DragonflyError> {
        let (hash, rules) = Self::fetch_rules(self.get_http_client(), &state.access_token)?;

        state.hash = hash;
        state.rules = rules;

        Ok(())
    }

    /// Fetch a job. None if the server has nothing for us to do.
    pub fn get_job(&self) -> reqwest::Result<Option<Job>> {
        let access_token = &self.state.read().unwrap().access_token;
        let res: GetJobResponse = self
            .client
            .post(format!("{}/job", APP_CONFIG.base_url))
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

    /// Report an error to the server.
    pub fn send_error(&self, job: &Job, reason: &str) -> reqwest::Result<()> {
        let access_token = &self.state.read().unwrap().access_token;

        let body = SubmitJobResultsError {
            name: &job.name,
            version: &job.version,
            reason,
        };

        self.client
            .put(format!("{}/package", APP_CONFIG.base_url))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&body)
            .send()?
            .error_for_status()?;

        Ok(())
    }

    /// Submit the results of a scan to the server, given the job and the scan results of each
    /// distribution
    pub fn send_success(
        &self,
        job: &Job,
        distribution_scan_results: &[DistributionScanResults],
    ) -> reqwest::Result<()> {
        let state = self.state.read().unwrap();
        let access_token = &state.access_token;

        let highest_score_distribution = distribution_scan_results
            .iter()
            .max_by_key(|distrib| distrib.get_total_score());

        let score = highest_score_distribution
            .map(DistributionScanResults::get_total_score)
            .unwrap_or_default();
        let inspector_url =
            highest_score_distribution.and_then(DistributionScanResults::inspector_url);
        let rules_matched = highest_score_distribution
            .map(DistributionScanResults::get_matched_rule_identifiers)
            .unwrap_or_default();

        let body = SubmitJobResultsBody {
            name: &job.name,
            version: &job.version,
            score,
            inspector_url: inspector_url.as_deref(),
            rules_matched: &rules_matched,
            commit: &state.hash,
        };

        info!("Results for this scan: {body:#?}");

        let r = self
            .client
            .put(format!("{}/package", APP_CONFIG.base_url))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&body)
            .send()?
            .error_for_status();

        match r {
            Ok(_) => Ok(()),
            Err(e) if e.status() == Some(StatusCode::UNAUTHORIZED) => {
                self.reauthenticate();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Return a reference to the underlying HTTP Client
    pub fn get_http_client(&self) -> &Client {
        &self.client
    }

    fn fetch_access_token(http_client: &Client) -> reqwest::Result<String> {
        let url = format!("https://{}/oauth/token", APP_CONFIG.auth0_domain);
        let json_body = AuthBody {
            client_id: &APP_CONFIG.client_id,
            client_secret: &APP_CONFIG.client_secret,
            audience: &APP_CONFIG.audience,
            grant_type: &APP_CONFIG.grant_type,
            username: &APP_CONFIG.username,
            password: &APP_CONFIG.password,
        };

        let res: AuthResponse = http_client
            .post(url)
            .json(&json_body)
            .send()?
            .error_for_status()?
            .json()?;

        Ok(res.access_token)
    }

    fn fetch_rules(
        http_client: &Client,
        access_token: &str,
    ) -> Result<(String, Rules), DragonflyError> {
        let res: GetRulesResponse = http_client
            .get(format!("{}/rules", APP_CONFIG.base_url))
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

        let compiled_rules = Compiler::new()?
            .add_rules_str(&rules_str)?
            .compile_rules()?;

        Ok((res.hash, compiled_rules))
    }
}

pub fn fetch_tarball(
    http_client: &Client,
    download_url: &Url,
) -> Result<TarballType, DragonflyError> {
    let response = http_client.get(download_url.clone()).send()?;

    let decompressed = GzDecoder::new(response);
    let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    decompressed
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(tar::Archive::new(cursor))
}

pub fn fetch_zipfile(http_client: &Client, download_url: &Url) -> Result<ZipType, DragonflyError> {
    let response = http_client.get(download_url.to_string()).send()?;

    let mut cursor = Cursor::new(Vec::new());
    response
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(zip::ZipArchive::new(cursor)?)
}
