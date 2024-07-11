mod methods;
mod models;

pub use methods::*;
pub use models::*;

use crate::APP_CONFIG;
use color_eyre::Result;
use flate2::read::GzDecoder;
use parking_lot::RwLock;
use reqwest::{blocking::Client, Url};
use std::{
    io::{Cursor, Read},
    time::Duration,
};
use tracing::{error, info, trace, warn};

/// Type alias representing a tar archive
pub type TarballType = tar::Archive<Cursor<Vec<u8>>>;

/// Type alias representing a zip archive
pub type ZipType = zip::ZipArchive<Cursor<Vec<u8>>>;

pub struct AuthState {
    pub access_token: String,
    pub expires_in: u32,
}

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[warn(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    pub client: Client,
    pub authentication_state: RwLock<AuthState>,
    pub rules_state: RwLock<RulesState>,
}

impl DragonflyClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder().gzip(true).build()?;

        let auth_response = fetch_access_token(&client)?;
        let rules_response = fetch_rules(&client, &auth_response.access_token)?;

        let authentication_state = RwLock::new(AuthState {
            access_token: auth_response.access_token,
            expires_in: auth_response.expires_in,
        });

        let rules_state = RwLock::new(RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        });

        Ok(Self {
            client,
            authentication_state,
            rules_state,
        })
    }

    /// Update the state with a new access token.
    ///
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&self) {
        trace!("Waiting for write lock on authentication state");
        let mut state = self.authentication_state.write();
        trace!("Acquired lock");

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        let authentication_response = loop {
            let r = fetch_access_token(self.get_http_client());
            match r {
                Ok(authentication_response) => break authentication_response,
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
        };

        trace!("Successfully got new access token!");

        *state = AuthState {
            access_token: authentication_response.access_token,
            expires_in: authentication_response.expires_in,
        };

        info!("Successfully reauthenticated.");
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&self) -> Result<()> {
        let response = fetch_rules(
            self.get_http_client(),
            &self.authentication_state.read().access_token,
        )?;
        let mut rules_state = self.rules_state.write();
        rules_state.rules = response.compile()?;
        rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        fetch_bulk_job(
            self.get_http_client(),
            &self.authentication_state.read().access_token,
            n_jobs,
        )
    }

    /// Report an error to the server.
    pub fn send_error(&self, body: &SubmitJobResultsError) -> reqwest::Result<()> {
        send_error(
            self.get_http_client(),
            &self.authentication_state.read().access_token,
            body,
        )
    }

    /// Submit the results of a scan to the server, given the job and the scan results of each
    /// distribution
    pub fn send_success(&self, body: &SubmitJobResultsSuccess) -> reqwest::Result<()> {
        send_success(
            self.get_http_client(),
            &self.authentication_state.read().access_token,
            body,
        )
    }

    /// Return a reference to the underlying HTTP Client
    pub fn get_http_client(&self) -> &Client {
        &self.client
    }
}

pub fn fetch_tarball(http_client: &Client, download_url: &Url) -> Result<TarballType> {
    let response = http_client.get(download_url.clone()).send()?;

    let decompressed = GzDecoder::new(response);
    let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    decompressed
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(tar::Archive::new(cursor))
}

pub fn fetch_zipfile(http_client: &Client, download_url: &Url) -> Result<ZipType> {
    let response = http_client.get(download_url.to_string()).send()?;

    let mut cursor = Cursor::new(Vec::new());
    response
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(zip::ZipArchive::new(cursor)?)
}
