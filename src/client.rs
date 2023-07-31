mod methods;
mod models;

pub use methods::*;
pub use models::*;

use crate::{error::DragonflyError, APP_CONFIG};
use flate2::read::GzDecoder;
use parking_lot::{Condvar, Mutex, RwLock};
use reqwest::{blocking::Client, StatusCode, Url};
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
    pub access_token: RwLock<String>,
    pub authenticating: Mutex<bool>,
    pub cvar: Condvar,
}

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[allow(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    pub client: Client,
    pub authentication_state: AuthState,
    pub rules_state: RwLock<RulesState>,
}

impl DragonflyClient {
    pub fn new() -> Result<Self, DragonflyError> {
        let client = Client::builder().gzip(true).build()?;

        let auth_response = fetch_access_token(&client)?;
        let rules_response = fetch_rules(&client, &auth_response.access_token)?;

        let auth_state = AuthState {
            access_token: RwLock::new(auth_response.access_token),
            authenticating: Mutex::new(false),
            cvar: Condvar::new(),
        };

        let rules_state = RwLock::new(RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        });

        Ok(Self {
            client,
            authentication_state: auth_state,
            rules_state,
        })
    }

    /// Update the state with a new access token.
    ///
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&self) {
        trace!("Trying to lock to check if we're authenticating.");
        let mut authing = self.authentication_state.authenticating.lock();
        trace!("Acquired lock");
        if *authing {
            trace!("Another thread is authenticating. Waiting for it to finish.");
            self.authentication_state.cvar.wait(&mut authing);
            trace!("Was notified, returning");
            return;
        }
        trace!("No other thread is authenticating. Trying to reauthenticate.");
        *authing = true;
        drop(authing);

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

        trace!("Successfully got new access token!");

        *self.authentication_state.access_token.write() = access_token;

        let mut authing = self.authentication_state.authenticating.lock();
        *authing = false;
        self.authentication_state.cvar.notify_all();

        info!("Successfully reauthenticated.");
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&self) -> Result<(), DragonflyError> {
        let response = match fetch_rules(
            self.get_http_client(),
            &self.authentication_state.access_token.read(),
        ) {
            Err(err) if err.status() == Some(StatusCode::UNAUTHORIZED) => {
                info!("Got 401 UNAUTHORIZED while updating rules");
                self.reauthenticate();
                info!("Fetching rules again...");
                fetch_rules(
                    self.get_http_client(),
                    &self.authentication_state.access_token.read(),
                )
            }

            Ok(response) => Ok(response),

            Err(err) => Err(err),
        }?;

        let mut rules_state = self.rules_state.write();
        rules_state.rules = response.compile()?;
        rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        let access_token = self.authentication_state.access_token.read();
        match fetch_bulk_job(self.get_http_client(), &access_token, n_jobs) {
            Err(err) if err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(access_token); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while doing a bulk fetch job request");
                self.reauthenticate();
                info!("Doing a bulk fetch job again...");
                fetch_bulk_job(
                    self.get_http_client(),
                    &self.authentication_state.access_token.read(),
                    n_jobs,
                )
            }

            other => other,
        }
    }

    /// Report an error to the server.
    pub fn send_error(&self, body: &SubmitJobResultsError) -> reqwest::Result<()> {
        let access_token = self.authentication_state.access_token.read();
        match send_error(self.get_http_client(), &access_token, body) {
            Err(http_err) if http_err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(access_token); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while sending success");
                self.reauthenticate();
                info!("Sending error body again...");
                send_error(
                    self.get_http_client(),
                    &self.authentication_state.access_token.read(),
                    body,
                )
            }

            other => other,
        }
    }

    /// Submit the results of a scan to the server, given the job and the scan results of each
    /// distribution
    pub fn send_success(&self, body: &SubmitJobResultsSuccess) -> reqwest::Result<()> {
        let access_token = self.authentication_state.access_token.read();
        match send_success(self.get_http_client(), &access_token, body) {
            Err(http_err) if http_err.status() == Some(StatusCode::UNAUTHORIZED) => {
                drop(access_token); // Drop the read lock
                info!("Got 401 UNAUTHORIZED while sending success");
                self.reauthenticate();
                info!("Sending success body again...");
                send_success(
                    self.get_http_client(),
                    &self.authentication_state.access_token.read(),
                    body,
                )
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
