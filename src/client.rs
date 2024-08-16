mod methods;
mod models;

use chrono::{DateTime, TimeDelta, Utc};
use flate2::read::GzDecoder;
pub use methods::*;
pub use models::*;
use tempfile::{tempdir, tempdir_in, tempfile, TempDir};

use color_eyre::Result;
use reqwest::{blocking::Client, Url};
use std::{fs, io, time::Duration};
use tracing::{error, info, trace, warn};

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

/// Perform a request to the given download URL and stream the response body to a file.
fn download_to_file(http_client: &Client, download_url: Url) -> Result<fs::File> {
    let mut response = http_client.get(download_url).send()?;
    let mut file = tempfile()?;
    io::copy(&mut response, &mut file)?;

    Ok(file)
}

/// Extract the given zipfile into a temporary directory
fn extract_zipfile(file: fs::File) -> Result<TempDir> {
    let mut zip = zip::ZipArchive::new(file)?;
    let tmpdir = tempdir()?;
    zip.extract(tmpdir.path())?;

    Ok(tmpdir)
}

/// Extract the given tarball into a temporary directory
fn unpack_tarball(file: fs::File) -> Result<TempDir> {
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let tmpdir = tempdir()?;
    tar.unpack(tmpdir.path())?;

    Ok(tmpdir)
}

/// Download and unpack a tarball, return the TempDir containing the contents.
pub fn download_tarball(http_client: &Client, download_url: &Url) -> Result<TempDir> {
    let file = download_to_file(http_client, download_url.to_owned())?;
    let dir = unpack_tarball(file)?;

    Ok(dir)
}

/// Download and extract a zip, return the TempDir containing the contents.
pub fn download_zipfile(http_client: &Client, download_url: &Url) -> Result<TempDir> {
    let file = download_to_file(http_client, download_url.to_owned())?;
    let dir = extract_zipfile(file)?;

    Ok(dir)
}

#[cfg(test)]
mod tests {
    use flate2::{write::GzEncoder, Compression};
    use fs::File;
    use io::Write;
    use zip::{write::SimpleFileOptions, ZipWriter};

    use super::*;

    #[test]
    fn test_extract_zipfile() {
        let file = tempfile().unwrap();
        let mut zip = ZipWriter::new(file);

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("hello_world.txt", options).unwrap();
        zip.write(b"Hello, world!").unwrap();
        let file = zip.finish().unwrap();

        let dir = extract_zipfile(file).unwrap();
        let n = dir.path().read_dir().unwrap().next();
        assert!(
            n.is_some(),
            "expected extracted zipfile to have at least one file"
        );

        assert_eq!(n.unwrap().unwrap().file_name(), "hello_world.txt");
    }

    #[test]
    fn test_extract_tarball() {
        let mut header = tar::Header::new_gnu();
        let fd = b"this is foo file";
        header.set_path("foo.txt").unwrap();
        header.set_size(fd.len().try_into().unwrap());
        header.set_cksum();

        let compressor = GzEncoder::new(Vec::new(), Compression::default());
        let mut ar = tar::Builder::new(compressor);
        ar.append(&header, fd.as_slice()).unwrap();
        let compressed_data = ar.into_inner().unwrap().finish().unwrap();

        let mut file = tempfile().unwrap();
        file.write_all(compressed_data.as_slice()).unwrap();

        let dir = unpack_tarball(file).unwrap();
        let n = dir.path().read_dir().unwrap().next();
        assert!(
            n.is_some(),
            "expected unpacked tarball to have at least one file"
        );

        assert_eq!(n.unwrap().unwrap().file_name(), "foo.txt");
    }
}
