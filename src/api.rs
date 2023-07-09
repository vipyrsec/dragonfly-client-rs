use crate::{
    api_models::{SubmitJobResultsError, SubmitJobResultsSuccess},
    common::{TarballType, ZipType},
    APP_CONFIG,
};
use flate2::read::GzDecoder;
use reqwest::{blocking::Client, StatusCode, Url};
use std::{
    io::{Cursor, Read},
    sync::RwLock,
    time::Duration,
};
use tracing::{error, info, warn};

use crate::{
    api_models::{AuthBody, AuthResponse, GetRulesResponse, Job},
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

// The following are methods that are "low level" to the API
// They simply send requests to the API and receive responses.
// Their counterpart methods in the DragonflyClient struct
// provide some abstractions on top of these methods such as
// credential checking, revalidating, easier data access, etc...

fn fetch_access_token(http_client: &Client) -> reqwest::Result<AuthResponse> {
    let url = format!("https://{}/oauth/token", APP_CONFIG.auth0_domain);
    let json_body = AuthBody {
        client_id: &APP_CONFIG.client_id,
        client_secret: &APP_CONFIG.client_secret,
        audience: &APP_CONFIG.audience,
        grant_type: &APP_CONFIG.grant_type,
        username: &APP_CONFIG.username,
        password: &APP_CONFIG.password,
    };

    http_client
        .post(url)
        .json(&json_body)
        .send()?
        .error_for_status()?
        .json()
}

fn fetch_bulk_job(
    http_client: &Client,
    access_token: &str,
    n_jobs: usize,
) -> reqwest::Result<Vec<Job>> {
    http_client
        .post(format!("{}/jobs", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .query(&[("batch", n_jobs)])
        .send()?
        .error_for_status()?
        .json()
}

fn fetch_rules(http_client: &Client, access_token: &str) -> reqwest::Result<GetRulesResponse> {
    http_client
        .get(format!("{}/rules", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()?
        .error_for_status()?
        .json()
}

fn send_success(
    http_client: &Client,
    access_token: &str,
    body: &SubmitJobResultsSuccess,
) -> reqwest::Result<()> {
    http_client
        .put(format!("{}/package", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}

fn send_error(
    http_client: &Client,
    access_token: &str,
    body: &SubmitJobResultsError,
) -> reqwest::Result<()> {
    http_client
        .put(format!("{}/package", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}

impl DragonflyClient {
    pub fn new() -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;

        let auth_response = fetch_access_token(&client)?;
        let rules_response = fetch_rules(&client, &auth_response.access_token)?;
        let state = State {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
            access_token: auth_response.access_token,
        }
        .into();

        Ok(Self { client, state })
    }

    /// Update the state with a new access token, using the given write lock [`RwLockWriteGuard`]
    ///
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&self) -> String {
        let access_token;

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        loop {
            let r = fetch_access_token(self.get_http_client());
            match r {
                Ok(authentication_response) => {
                    access_token = authentication_response.access_token;
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
        access_token
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&self) -> Result<(), DragonflyError> {
        let mut state = self.state.write().unwrap();
        let rules_response = fetch_rules(self.get_http_client(), &state.access_token)?;
        state.rules = rules_response.compile()?;
        state.hash = rules_response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        let state = self.state.read().unwrap();
        match fetch_bulk_job(self.get_http_client(), &state.access_token, n_jobs) {
            Err(err) if err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(state); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while doing a bulk fetch job request");
                info!("Waiting on write lock to update access token");
                let mut state = self.state.write().unwrap();
                info!("Successfully obtained write lock!");
                info!("Requesting new access token...");
                let new_access_token = self.reauthenticate();
                info!("Successfuly got new access token!");
                state.access_token = new_access_token;
                info!("Successfully updated local access token to new one!");
                info!("Doing a bulk fetch job again...");
                fetch_bulk_job(self.get_http_client(), &state.access_token, n_jobs)
            }

            other => other,
        }
    }

    /// Report an error to the server.
    pub fn send_error(&self, body: &SubmitJobResultsError) -> reqwest::Result<()> {
        let state = self.state.read().unwrap();
        match send_error(self.get_http_client(), &state.access_token, body) {
            Err(http_err) if http_err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(state); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while sending success");
                info!("Waiting on write lock to update access token");
                let mut state = self.state.write().unwrap();
                info!("Successfully obtained write lock!");
                info!("Requesting new access token...");
                let new_access_token = self.reauthenticate();
                info!("Successfuly got new access token!");
                state.access_token = new_access_token;
                info!("Successfully updated local access token to new one!");
                info!("Sending success body again...");
                send_error(self.get_http_client(), &state.access_token, body)
            }

            other => other,
        }
    }

    /// Submit the results of a scan to the server, given the job and the scan results of each
    /// distribution
    pub fn send_success(&self, body: &SubmitJobResultsSuccess) -> reqwest::Result<()> {
        let state = self.state.read().unwrap();
        match send_success(self.get_http_client(), &state.access_token, body) {
            Err(http_err) if http_err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(state); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while sending success");
                info!("Waiting on write lock to update access token");
                let mut state = self.state.write().unwrap();
                info!("Successfully obtained write lock!");
                info!("Requesting new access token...");
                let new_access_token = self.reauthenticate();
                info!("Successfuly got new access token!");
                state.access_token = new_access_token;
                info!("Successfully updated local access token to new one!");
                info!("Sending success body again");
                send_success(self.get_http_client(), &state.access_token, body)
            }

            other => other,
        }
    }

    /// Return a reference to the underlying HTTP Client
    pub fn get_http_client(&self) -> &Client {
        &self.client
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
