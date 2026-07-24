mod methods;
mod models;

use flate2::read::GzDecoder;
pub use methods::*;
pub use models::*;
use tempfile::{tempdir, tempfile, TempDir};

use crate::APP_CONFIG;
use color_eyre::{
    eyre::{bail, ensure},
    Result,
};
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
    Url,
};
use std::{
    fs::File,
    io::{self, Read, Seek},
};

#[derive(Clone, Copy)]
struct ArchiveLimits {
    entries: usize,
    download_size: u64,
    expanded_size: u64,
    scan_size: u64,
}

impl ArchiveLimits {
    fn configured() -> Self {
        Self {
            entries: APP_CONFIG.max_archive_entries,
            download_size: APP_CONFIG.max_download_size,
            expanded_size: APP_CONFIG.max_expanded_size,
            scan_size: APP_CONFIG.max_scan_size,
        }
    }
}

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

    pub fn bulk_get_job(&self, n_jobs: usize) -> reqwest::Result<Vec<Job>> {
        fetch_bulk_job(&self.api_client, &self.base_url, n_jobs)
    }

    /// Send a [`crate::client::models::ScanResult`] to mainframe
    pub fn send_result(&self, body: models::ScanResult) -> reqwest::Result<()> {
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

fn stage_download<R: Read>(response: R, limit: u64) -> Result<File> {
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| color_eyre::eyre::eyre!("download size limit is too large"))?;
    let mut file = tempfile()?;
    let downloaded = io::copy(&mut response.take(read_limit), &mut file)?;
    ensure!(
        downloaded <= limit,
        "compressed distribution exceeds the {limit}-byte download limit"
    );
    file.rewind()?;

    Ok(file)
}

/// Unpack a tarball within the configured resource limits.
fn extract_tarball(file: File, limits: ArchiveLimits) -> Result<TempDir> {
    let mut tarball = tar::Archive::new(GzDecoder::new(file));
    let tmpdir = tempdir()?;
    let mut entries = 0_usize;
    let mut expanded_size = 0_u64;

    for entry in tarball.entries()? {
        let mut entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| color_eyre::eyre::eyre!("tar entry count overflowed"))?;
        ensure!(
            entries <= limits.entries,
            "tar archive exceeds the {}-entry limit",
            limits.entries
        );

        let entry_size = entry.size();
        ensure!(
            entry_size <= limits.scan_size,
            "tar entry {} is {entry_size} bytes, exceeding the {}-byte scan limit",
            entry.path()?.display(),
            limits.scan_size
        );
        expanded_size = expanded_size
            .checked_add(entry_size)
            .ok_or_else(|| color_eyre::eyre::eyre!("expanded tar size overflowed"))?;
        ensure!(
            expanded_size <= limits.expanded_size,
            "tar archive exceeds the {}-byte expanded-size limit",
            limits.expanded_size
        );
        ensure!(
            entry.unpack_in(tmpdir.path())?,
            "tar entry would unpack outside the temporary directory"
        );
    }

    Ok(tmpdir)
}

fn zip_entry_count(file: &mut File) -> Result<usize> {
    const END_HEADER_SIZE: usize = 22;
    const MAX_COMMENT_SIZE: usize = u16::MAX as usize;
    const SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

    let file_size = file.seek(io::SeekFrom::End(0))?;
    let tail_size = file_size.min((END_HEADER_SIZE + MAX_COMMENT_SIZE) as u64);
    file.seek(io::SeekFrom::End(
        -i64::try_from(tail_size).expect("ZIP footer window fits in i64"),
    ))?;

    let mut tail = vec![0_u8; usize::try_from(tail_size)?];
    file.read_exact(&mut tail)?;
    let Some(header_start) =
        (0..=tail.len().saturating_sub(SIGNATURE.len()))
            .rev()
            .find(|&index| {
                if tail[index..].get(..SIGNATURE.len()) != Some(&SIGNATURE) {
                    return false;
                }
                let Some(comment_size) = tail
                    .get(index + 20..index + 22)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
                else {
                    return false;
                };
                tail.len() - index == END_HEADER_SIZE + comment_size
            })
    else {
        bail!("ZIP end-of-central-directory record is missing");
    };
    let header = &tail[header_start..];
    let disk_number = u16::from_le_bytes([header[4], header[5]]);
    let directory_disk = u16::from_le_bytes([header[6], header[7]]);
    let entries_on_disk = u16::from_le_bytes([header[8], header[9]]);
    let entries = u16::from_le_bytes([header[10], header[11]]);
    ensure!(
        disk_number == 0 && directory_disk == 0 && entries_on_disk == entries,
        "multi-disk ZIP archives are not supported"
    );
    ensure!(
        entries != u16::MAX,
        "ZIP64 archives are not accepted in the constrained scanner"
    );
    file.rewind()?;

    Ok(entries as usize)
}

/// Extract a ZIP archive within the configured resource limits.
fn extract_zipfile(mut file: File, limits: ArchiveLimits) -> Result<TempDir> {
    let entry_count = zip_entry_count(&mut file)?;
    ensure!(
        entry_count <= limits.entries,
        "ZIP archive contains {entry_count} entries, exceeding the {}-entry limit",
        limits.entries
    );
    let mut zip = zip::ZipArchive::new(file)?;
    ensure!(
        zip.len() == entry_count,
        "ZIP central-directory entry count changed while parsing"
    );

    let mut expanded_size = 0_u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        ensure!(
            matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            ),
            "ZIP entry {} uses unsupported compression method {:?}",
            entry.name(),
            entry.compression()
        );
        let entry_size = entry.size();
        ensure!(
            entry_size <= limits.scan_size,
            "ZIP entry {} is {entry_size} bytes, exceeding the {}-byte scan limit",
            entry.name(),
            limits.scan_size
        );
        expanded_size = expanded_size
            .checked_add(entry_size)
            .ok_or_else(|| color_eyre::eyre::eyre!("expanded ZIP size overflowed"))?;
        ensure!(
            expanded_size <= limits.expanded_size,
            "ZIP archive exceeds the {}-byte expanded-size limit",
            limits.expanded_size
        );
    }

    let tmpdir = tempdir()?;
    zip.extract(tmpdir.path())?;

    Ok(tmpdir)
}

pub fn download_distribution(http_client: &Client, download_url: Url) -> Result<TempDir> {
    let is_tarball = download_url.as_str().ends_with(".tar.gz");
    let response = http_client.get(download_url).send()?.error_for_status()?;
    let limits = ArchiveLimits::configured();
    let file = stage_download(response, limits.download_size)?;

    if is_tarball {
        extract_tarball(file, limits)
    } else {
        extract_zipfile(file, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_api_http_client, build_download_http_client, extract_tarball, extract_zipfile,
        stage_download, ArchiveLimits, DragonflyClient, RulesState,
    };
    use flate2::{write::GzEncoder, Compression};
    use std::{
        io::{Cursor, Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };
    use yara::Compiler;
    use zip::{write::SimpleFileOptions, ZipWriter};

    const CLIENT_ID: &str = "test-client.access";
    const CLIENT_SECRET: &str = "test-secret";

    fn archive_limits() -> ArchiveLimits {
        ArchiveLimits {
            entries: 4,
            download_size: 1024,
            expanded_size: 1024,
            scan_size: 1024,
        }
    }

    fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn build_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut tarball = tar::Builder::new(encoder);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len().try_into().unwrap());
            header.set_cksum();
            tarball.append_data(&mut header, name, *contents).unwrap();
        }
        tarball.into_inner().unwrap().finish().unwrap()
    }

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

    #[test]
    fn stage_download_rejects_oversized_input() {
        let error = stage_download(Cursor::new(vec![0_u8; 5]), 4).unwrap_err();

        assert!(error.to_string().contains("4-byte download limit"));
    }

    #[test]
    fn zip_entry_limit_is_checked_before_extraction() {
        let bytes = build_zip(&[("one", b"1"), ("two", b"2")]);
        let file = stage_download(Cursor::new(bytes), 1024).unwrap();
        let limits = ArchiveLimits {
            entries: 1,
            ..archive_limits()
        };

        let error = extract_zipfile(file, limits).unwrap_err();

        assert!(error.to_string().contains("2 entries"));
    }

    #[test]
    fn zip_expanded_size_is_bounded() {
        let bytes = build_zip(&[("one", b"1234"), ("two", b"5678")]);
        let file = stage_download(Cursor::new(bytes), 1024).unwrap();
        let limits = ArchiveLimits {
            expanded_size: 7,
            ..archive_limits()
        };

        let error = extract_zipfile(file, limits).unwrap_err();

        assert!(error.to_string().contains("expanded-size limit"));
    }

    #[test]
    fn zip_file_scan_size_is_bounded() {
        let bytes = build_zip(&[("large", b"12345")]);
        let file = stage_download(Cursor::new(bytes), 1024).unwrap();
        let limits = ArchiveLimits {
            scan_size: 4,
            ..archive_limits()
        };

        let error = extract_zipfile(file, limits).unwrap_err();

        assert!(error.to_string().contains("4-byte scan limit"));
    }

    #[test]
    fn tar_expanded_size_is_bounded() {
        let bytes = build_tarball(&[("one", b"1234"), ("two", b"5678")]);
        let file = stage_download(Cursor::new(bytes), 1024).unwrap();
        let limits = ArchiveLimits {
            expanded_size: 7,
            ..archive_limits()
        };

        let error = extract_tarball(file, limits).unwrap_err();

        assert!(error.to_string().contains("expanded-size limit"));
    }
}
