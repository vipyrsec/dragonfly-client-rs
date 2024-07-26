mod methods;
mod models;

use chrono::{DateTime, TimeDelta, Utc};
use flate2::read::GzDecoder;
pub use methods::*;
pub use models::*;

use color_eyre::Result;
use reqwest::{
    blocking::{Client, Response},
    Url,
};
use std::{collections::HashSet, time::Duration};
use tracing::{error, info, trace, warn};

use crate::scanner::{DistributionScanResults, PackageScanResults};

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

/// Return a tar archive backed by a gzip decompression stream, which itself is backed by the
/// Response.
pub fn fetch_tarball(
    http_client: &Client,
    download_url: &Url,
) -> Result<tar::Archive<GzDecoder<Response>>> {
    let response = http_client.get(download_url.clone()).send()?;

    let decoder = GzDecoder::new(response);
    let tar = tar::Archive::new(decoder);

    Ok(tar)
}

/// Return a Response from which zipfiles can be streamed using `read_zipfile_from_stream`.
pub fn fetch_zipfile(http_client: &Client, download_url: &Url) -> Result<Response> {
    let response = http_client.get(download_url.to_string()).send()?;

    Ok(response)
}

/// Format the package scan results into something that can be sent over the API
pub fn build_body(package_scan_results: &PackageScanResults) -> SubmitJobResultsSuccess {
    let highest_score_distribution = package_scan_results
        .distribution_scan_results
        .iter()
        .max_by_key(|distrib| distrib.get_total_score());

    let score = highest_score_distribution
        .map(DistributionScanResults::get_total_score)
        .unwrap_or_default();

    let inspector_url = highest_score_distribution.and_then(DistributionScanResults::inspector_url);

    // collect all rule identifiers into a HashSet to dedup, then convert to Vec
    let rules_matched = package_scan_results
        .distribution_scan_results
        .iter()
        .flat_map(DistributionScanResults::get_matched_rule_identifiers)
        .map(std::string::ToString::to_string)
        .collect::<HashSet<String>>()
        .into_iter()
        .collect();

    SubmitJobResultsSuccess {
        name: package_scan_results.name.clone(),
        version: package_scan_results.version.clone(),
        score,
        inspector_url,
        rules_matched,
        commit: package_scan_results.commit_hash.clone(),
    }
}
