mod methods;
mod models;

use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
pub use methods::*;
pub use models::*;
use tempfile::{tempdir, tempfile, TempDir};

use color_eyre::Result;
use reqwest::{blocking::Client, Url};
use std::{io, time::Duration};
use tracing::{error, info, trace, warn};

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[warn(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    pub client: Client,
    pub authentication_expires: DateTime<Utc>,
    pub rules_state: RulesState,
}

impl DragonflyClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder().gzip(true).cookie_store(true).build()?;

        let authentication_expires = perform_initial_authentication(&client)?;
        let rules_response = fetch_rules(&client)?;

        let rules_state = RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        };

        Ok(Self {
            client,
            authentication_expires,
            rules_state,
        })
    }

    /// Update the state with a new access token, if it's expired.
    ///
    /// If the token is not expired, then nothing is done.
    /// If an error occurs while reauthenticating, the function retries with an exponential backoff
    /// described by the equation `min(10 * 60, 2^(x - 1))` where `x` is the number of failed tries.
    pub fn reauthenticate(&mut self) {
        if Utc::now() <= self.authentication_expires {
            return;
        }

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        let authentication_expires = loop {
            let r =  perform_initial_authentication(self.get_http_client());
            match r {
                Ok(authentication_expires) => break authentication_expires,
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

        self.authentication_expires = authentication_expires;

        info!("Successfully reauthenticated.");
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&mut self) -> Result<()> {
        self.reauthenticate();

        let response = fetch_rules(self.get_http_client())?;
        self.rules_state.rules = response.compile()?;
        self.rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&mut self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        self.reauthenticate();

        fetch_bulk_job(self.get_http_client(), n_jobs)
    }

    pub fn get_job(&mut self) -> reqwest::Result<Option<Job>> {
        self.reauthenticate();

        // not `slice::first` because we want to own the Job
        self.bulk_get_job(1).map(|jobs| jobs.into_iter().nth(0))
    }

    /// Send a [`crate::client::models::ScanResult`] to mainframe
    pub fn send_result(&mut self, body: models::ScanResult) -> reqwest::Result<()> {
        self.reauthenticate();

        send_result(self.get_http_client(), body)
    }

    /// Return a reference to the underlying HTTP Client
    pub fn get_http_client(&self) -> &Client {
        &self.client
    }
}

/// Download and unpack a tarball, return the [`TempDir`] containing the contents.
fn extract_tarball<R: io::Read>(response: R) -> Result<TempDir> {
    let mut tarball = tar::Archive::new(GzDecoder::new(response));
    let tmpdir = tempdir()?;
    tarball.unpack(tmpdir.path())?;
    Ok(tmpdir)
}

/// Download and extract a zip, return the [`TempDir`] containing the contents.
fn extract_zipfile<R: io::Read>(mut response: R) -> Result<TempDir> {
    let mut file = tempfile()?;

    // first write the archive to a file because `response` isn't Seek, which is needed by
    // `zip::ZipArchive::new`
    io::copy(&mut response, &mut file)?;

    let mut zip = zip::ZipArchive::new(file)?;
    let tmpdir = tempdir()?;
    zip.extract(tmpdir.path())?;

    Ok(tmpdir)
}

pub fn download_distribution(http_client: &Client, download_url: Url) -> Result<TempDir> {
    // This conversion is fast as per the docs
    let is_tarball = download_url.as_str().ends_with(".tar.gz");
    let response = http_client.get(download_url).send()?;

    if is_tarball {
        extract_tarball(response)
    } else {
        extract_zipfile(response)
    }
}
