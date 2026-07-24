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
    redirect::Policy,
    Url,
};
use std::io;

pub struct RulesState {
    pub rules: yara::Rules,
    pub hash: String,
}

#[warn(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    api_client: Client,
    download_client: Client,
    pub rules_state: RulesState,
    base_url: String,
}

impl DragonflyClient {
    pub fn new() -> Result<Self> {
        let api_client = build_api_http_client(
            &APP_CONFIG.cf_access_client_id,
            &APP_CONFIG.cf_access_client_secret,
        )?;
        let download_client = build_download_http_client()?;

        let rules_response = fetch_rules(&api_client, &APP_CONFIG.base_url)?;

        let rules_state = RulesState {
            rules: rules_response.compile()?,
            hash: rules_response.hash,
        };

        Ok(Self {
            api_client,
            download_client,
            rules_state,
            base_url: APP_CONFIG.base_url.clone(),
        })
    }

    /// Update the global ruleset. Waits for a write lock.
    pub fn update_rules(&mut self) -> Result<()> {
        let response = fetch_rules(&self.api_client, &self.base_url)?;
        self.rules_state.rules = response.compile()?;
        self.rules_state.hash = response.hash;

        Ok(())
    }

    pub fn bulk_get_job(&mut self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        fetch_bulk_job(&self.api_client, &self.base_url, n_jobs)
    }

    pub fn get_job(&mut self) -> reqwest::Result<Option<Job>> {
        // not `slice::first` because we want to own the Job
        self.bulk_get_job(1).map(|jobs| jobs.into_iter().nth(0))
    }

    /// Send a [`crate::client::models::ScanResult`] to mainframe
    pub fn send_result(&mut self, body: models::ScanResult) -> reqwest::Result<()> {
        send_result(&self.api_client, &self.base_url, body)
    }

    /// Return the client used for uncredentialed distribution downloads.
    pub(crate) fn download_client(&self) -> &Client {
        &self.download_client
    }
}

fn build_api_http_client(client_id: &str, client_secret: &str) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert("CF-Access-Client-Id", HeaderValue::from_str(client_id)?);

    let mut secret = HeaderValue::from_str(client_secret)?;
    secret.set_sensitive(true);
    headers.insert("CF-Access-Client-Secret", secret);

    Ok(Client::builder()
        .gzip(true)
        .redirect(Policy::custom(|attempt| {
            attempt.error("Dragonfly API redirects are not allowed")
        }))
        .default_headers(headers)
        .build()?)
}

fn build_download_http_client() -> reqwest::Result<Client> {
    Client::builder().gzip(true).build()
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

#[cfg(test)]
mod tests {
    use super::{build_api_http_client, build_download_http_client, DragonflyClient, RulesState};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };
    use yara::Compiler;

    const CLIENT_ID: &str = "test-client.access";
    const CLIENT_SECRET: &str = "test-secret";

    fn serve_once(response: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];

            loop {
                let bytes_read = stream.read(&mut buffer).unwrap();
                if bytes_read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            sender.send(String::from_utf8(request).unwrap()).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });

        (format!("http://{address}/example.tar.gz"), receiver)
    }

    #[test]
    fn distribution_downloads_do_not_send_cloudflare_access_credentials() {
        let response =
            String::from("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (download_url, request) = serve_once(response);
        let rules = Compiler::new()
            .unwrap()
            .add_rules_str("rule test_rule { condition: false }")
            .unwrap()
            .compile_rules()
            .unwrap();
        let client = DragonflyClient {
            api_client: build_api_http_client(CLIENT_ID, CLIENT_SECRET).unwrap(),
            download_client: build_download_http_client().unwrap(),
            rules_state: RulesState {
                rules,
                hash: String::new(),
            },
            base_url: String::from("https://dragonfly.example"),
        };

        client
            .download_client()
            .get(download_url)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();

        let request = request.recv().unwrap().to_ascii_lowercase();
        assert!(!request.contains("\r\ncf-access-client-id:"));
        assert!(!request.contains("\r\ncf-access-client-secret:"));
        assert!(!request.contains("\r\nauthorization:"));
    }

    #[test]
    fn api_client_rejects_redirects_before_forwarding_credentials() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let target_url = format!("http://{}/capture", redirect_target.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (api_url, source_request) = serve_once(response);
        let api_client = build_api_http_client(CLIENT_ID, CLIENT_SECRET).unwrap();

        let error = api_client.get(api_url).send().unwrap_err();

        assert!(error.is_redirect());
        assert_eq!(
            redirect_target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let source_request = source_request.recv().unwrap().to_ascii_lowercase();
        assert!(source_request.contains("\r\ncf-access-client-id:"));
        assert!(source_request.contains("\r\ncf-access-client-secret:"));
    }
}
