mod methods;
mod models;

use flate2::read::GzDecoder;
pub use methods::*;
pub use models::*;
use tempfile::{tempdir, tempfile, TempDir};

use crate::APP_CONFIG;
use color_eyre::Result;
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue},
    Url,
};
use std::io;

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[warn(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    pub client: Client,
    pub rules_state: RulesState,
    base_url: String,
}

impl DragonflyClient {
    pub fn new() -> Result<Self> {
        let client = build_http_client(
            &APP_CONFIG.cf_access_client_id,
            &APP_CONFIG.cf_access_client_secret,
        )?;

        let rules_response = fetch_rules(&client, &APP_CONFIG.base_url)?;

        let rules_state = RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        };

        Ok(Self {
            client,
            rules_state,
            base_url: APP_CONFIG.base_url.clone(),
        })
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&mut self) -> Result<()> {
        let response = fetch_rules(self.get_http_client(), &self.base_url)?;
        self.rules_state.rules = response.compile()?;
        self.rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&mut self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        fetch_bulk_job(self.get_http_client(), &self.base_url, n_jobs)
    }

    pub fn get_job(&mut self) -> reqwest::Result<Option<Job>> {
        // not `slice::first` because we want to own the Job
        self.bulk_get_job(1).map(|jobs| jobs.into_iter().nth(0))
    }

    /// Send a [`crate::client::models::ScanResult`] to mainframe
    pub fn send_result(&mut self, body: models::ScanResult) -> reqwest::Result<()> {
        send_result(self.get_http_client(), &self.base_url, body)
    }

    /// Return a reference to the underlying HTTP Client
    pub fn get_http_client(&self) -> &Client {
        &self.client
    }
}

fn build_http_client(client_id: &str, client_secret: &str) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert("CF-Access-Client-Id", HeaderValue::from_str(client_id)?);

    let mut secret = HeaderValue::from_str(client_secret)?;
    secret.set_sensitive(true);
    headers.insert("CF-Access-Client-Secret", secret);

    Ok(Client::builder()
        .gzip(true)
        .default_headers(headers)
        .build()?)
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
