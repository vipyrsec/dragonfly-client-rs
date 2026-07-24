use super::{models, ScanResultSerializer};

use reqwest::blocking::Client;

pub fn fetch_bulk_job(
    http_client: &Client,
    base_url: &str,
    n_jobs: usize,
) -> reqwest::Result<Vec<models::Job>> {
    http_client
        .post(format!("{base_url}/jobs"))
        .query(&[("batch", n_jobs)])
        .send()?
        .error_for_status()?
        .json()
}

pub fn fetch_rules(http_client: &Client, base_url: &str) -> reqwest::Result<models::RulesResponse> {
    http_client
        .get(format!("{base_url}/rules"))
        .send()?
        .error_for_status()?
        .json()
}

pub fn send_result(
    http_client: &Client,
    base_url: &str,
    body: models::ScanResult,
) -> reqwest::Result<()> {
    let body: ScanResultSerializer = body.into();
    http_client
        .put(format!("{base_url}/package"))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{fetch_bulk_job, fetch_rules, send_result};
    use crate::client::{build_api_http_client, SubmitJobResultsError};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    const CLIENT_ID: &str = "test-client.access";
    const CLIENT_SECRET: &str = "test-secret";

    fn serve_once(response_body: &str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response_body = response_body.to_owned();
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

                let request_text = String::from_utf8_lossy(&request);
                let Some(headers_end) = request_text.find("\r\n\r\n") else {
                    continue;
                };
                let content_length = request_text[..headers_end]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or_default();
                if request.len() >= headers_end + 4 + content_length {
                    break;
                }
            }

            sender.send(String::from_utf8(request).unwrap()).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body,
            )
            .unwrap();
        });

        (format!("http://{address}"), receiver)
    }

    fn assert_cloudflare_access_headers(request: &str) {
        let lowercase_request = request.to_ascii_lowercase();
        assert!(lowercase_request.contains(&format!(
            "\r\ncf-access-client-id: {}\r\n",
            CLIENT_ID.to_ascii_lowercase()
        )));
        assert!(lowercase_request
            .contains(&format!("\r\ncf-access-client-secret: {CLIENT_SECRET}\r\n")));
        assert!(!lowercase_request.contains("\r\nauthorization:"));
    }

    #[test]
    fn jobs_route_uses_cloudflare_access_service_token() {
        let (base_url, request) = serve_once("[]");
        let client = build_api_http_client(CLIENT_ID, CLIENT_SECRET).unwrap();

        let jobs = fetch_bulk_job(&client, &base_url, 3).unwrap();

        assert!(jobs.is_empty());
        let request = request.recv().unwrap();
        assert!(request.starts_with("POST /jobs?batch=3 HTTP/1.1\r\n"));
        assert_cloudflare_access_headers(&request);
    }

    #[test]
    fn rules_route_uses_cloudflare_access_service_token() {
        let (base_url, request) = serve_once(r#"{"hash":"abc123","rules":{}}"#);
        let client = build_api_http_client(CLIENT_ID, CLIENT_SECRET).unwrap();

        let rules = fetch_rules(&client, &base_url).unwrap();

        assert_eq!(rules.hash, "abc123");
        let request = request.recv().unwrap();
        assert!(request.starts_with("GET /rules HTTP/1.1\r\n"));
        assert_cloudflare_access_headers(&request);
    }

    #[test]
    fn package_route_uses_cloudflare_access_service_token() {
        let (base_url, request) = serve_once("");
        let client = build_api_http_client(CLIENT_ID, CLIENT_SECRET).unwrap();
        let result = Err(SubmitJobResultsError {
            name: "example".to_owned(),
            version: "1.0.0".to_owned(),
            reason: "test failure".to_owned(),
        });

        send_result(&client, &base_url, result).unwrap();

        let request = request.recv().unwrap();
        assert!(request.starts_with("PUT /package HTTP/1.1\r\n"));
        assert_cloudflare_access_headers(&request);
        assert!(request.contains(r#"{"name":"example","version":"1.0.0","reason":"test failure"}"#));
    }
}
