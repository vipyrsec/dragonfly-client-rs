mod methods;
mod models;

use chrono::{DateTime, TimeDelta, Utc};
pub use methods::*;
pub use models::*;

use crate::APP_CONFIG;
use color_eyre::Result;
use flate2::read::GzDecoder;
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
    pub expires_at: DateTime<Utc>,
}

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[warn(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    pub client: Client,
    pub authentication_state: AuthState,
    pub rules_state: RulesState,
}

impl DragonflyClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder().gzip(true).build()?;

        let auth_response = fetch_access_token(&client)?;
        let rules_response = fetch_rules(&client, &auth_response.access_token)?;

        let authentication_state = AuthState {
            access_token: auth_response.access_token,
            expires_at: Utc::now() + TimeDelta::seconds(auth_response.expires_in.into()),
        };

        let rules_state = RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        };

        Ok(Self {
            client,
            authentication_state,
            rules_state,
        })
    }

    /// Update the state with a new access token, if it's expired.
    ///
    /// If the token is not expired, then nothing is done.
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&mut self) {
        if Utc::now() <= self.authentication_state.expires_at {
            return;
        }

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

        self.authentication_state = AuthState {
            access_token: authentication_response.access_token,
            expires_at: Utc::now() + TimeDelta::seconds(authentication_response.expires_in.into()),
        };

        info!("Successfully reauthenticated.");
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&mut self) -> Result<()> {
        self.reauthenticate();

        let response = fetch_rules(
            self.get_http_client(),
            &self.authentication_state.access_token,
        )?;
        self.rules_state.rules = response.compile()?;
        self.rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&mut self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        self.reauthenticate();

        fetch_bulk_job(
            self.get_http_client(),
            &self.authentication_state.access_token,
            n_jobs,
        )
    }

    pub fn get_job(&mut self) -> reqwest::Result<Option<Job>> {
        self.reauthenticate();

        // not `slice::first` because we want to own the Job
        self.bulk_get_job(1).map(|jobs| jobs.into_iter().nth(0))
    }

    /// Send a [`crate::client::models::ScanResult`] to mainframe
    pub fn send_result(&mut self, body: models::ScanResult) -> reqwest::Result<()> {
        self.reauthenticate();

        send_result(
            self.get_http_client(),
            &self.authentication_state.access_token,
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
