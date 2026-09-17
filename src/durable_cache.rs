//! Batched, optional database cache transport. File bytes never leave the worker.
use color_eyre::{eyre::ensure, Result};
use reqwest::blocking::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) const BATCH_SIZE: usize = 128;
const MAX_RESULT_BYTES: usize = 16_384;
const MAX_BATCH_BYTES: usize = 512 * 1024;
const MAX_RESPONSE_BYTES: u64 = 3 * 1024 * 1024;
const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
const NETWORK_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Serialize)]
pub(crate) struct Context {
    scanner: &'static str,
    rules_commit: String,
    rules_digest: String,
    engine_digest: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct Lease {
    pub name: String,
    pub version: String,
    pub assignment_id: String,
    pub attempt: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub file_digest: String,
    pub language: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Value {
    #[serde(flatten)]
    key: Key,
    result: String,
}

#[derive(Deserialize)]
struct Reply {
    revoked: bool,
    entries: Vec<Value>,
}

#[derive(Deserialize)]
struct Acknowledgement {
    quarantined: usize,
}

pub(crate) struct DurableCache {
    client: Client,
    url: String,
    context: Context,
    lease: Option<Lease>,
    keys: HashMap<String, Key>,
    hits: HashMap<String, String>,
    pending: Vec<Value>,
    quarantines: Vec<Key>,
    pending_bytes: usize,
    read_bytes: usize,
    spent: Duration,
    unavailable: bool,
    pub revoked: bool,
}

impl DurableCache {
    pub fn new(
        client: Client,
        url: &str,
        scanner: &'static str,
        commit: &str,
        rules: &HashMap<String, String>,
        engine: Option<&Path>,
    ) -> Result<Self> {
        let mut digest = Sha256::new();
        digest.update(hash_path(&std::env::current_exe()?)?);
        if let Some(engine) = engine {
            digest.update(hash_path(engine)?);
        }
        digest.update(b"durable-file-results-v1");
        Ok(Self {
            client,
            url: format!("{}/scan-cache", url.trim_end_matches('/')),
            context: Context {
                scanner,
                rules_commit: commit.to_owned(),
                rules_digest: rules_digest(rules),
                engine_digest: format!("{:x}", digest.finalize()),
            },
            lease: None,
            keys: HashMap::new(),
            hits: HashMap::new(),
            pending: Vec::new(),
            quarantines: Vec::new(),
            pending_bytes: 0,
            read_bytes: 0,
            spent: Duration::ZERO,
            unavailable: false,
            revoked: false,
        })
    }

    pub fn begin_job(&mut self, lease: Lease) {
        self.lease = Some(lease);
        self.keys.clear();
        self.hits.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        self.read_bytes = 0;
        self.spent = Duration::ZERO;
        self.unavailable = false;
    }

    fn available(&self) -> bool {
        !self.unavailable && !self.revoked && self.lease.is_some() && self.spent < NETWORK_BUDGET
    }

    fn post<T: DeserializeOwned>(&mut self, route: &str, body: &impl Serialize) -> Result<T> {
        let started = Instant::now();
        let result = (|| {
            let response = self
                .client
                .post(format!("{}/{route}", self.url))
                .timeout(Duration::from_millis(750))
                .json(body)
                .send()?
                .error_for_status()?;
            let mut bytes = Vec::new();
            response
                .take(MAX_RESPONSE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_RESPONSE_BYTES,
                "Cache response exceeds limit"
            );
            Ok(serde_json::from_slice(&bytes)?)
        })();
        self.spent += started.elapsed();
        if result.is_err() {
            self.unavailable = true;
        }
        result
    }

    pub fn prefetch(&mut self, keys: &[(String, Key)]) -> Result<()> {
        self.flush_quarantines()?;
        if !self.available() {
            return Ok(());
        }
        for chunk in keys.chunks(BATCH_SIZE) {
            if !self.available() || self.keys.len() + chunk.len() > 65_536 {
                break;
            }
            let by_key: HashMap<Key, String> = chunk
                .iter()
                .map(|(local, key)| (key.clone(), local.clone()))
                .collect();
            let body = serde_json::json!({"context":self.context,"keys":by_key.keys().collect::<Vec<_>>()});
            let reply: Reply = self.post("lookup", &body)?;
            if reply.revoked {
                self.revoked = true;
                self.hits.clear();
                break;
            }
            for (local, key) in chunk {
                self.keys.insert(local.clone(), key.clone());
            }
            for value in reply.entries {
                if value.result.len() > MAX_RESULT_BYTES {
                    self.unavailable = true;
                    self.hits.clear();
                    color_eyre::eyre::bail!("Cache result exceeds limit");
                }
                if self.read_bytes + value.result.len() > MAX_READ_BYTES {
                    continue;
                }
                if let Some(local) = by_key.get(&value.key) {
                    self.read_bytes += value.result.len();
                    self.hits.insert(local.clone(), value.result);
                }
            }
        }
        Ok(())
    }

    pub fn lookup<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        if self.unavailable || self.revoked {
            return Ok(None);
        }
        self.hits
            .get(key)
            .map(|value| serde_json::from_str(value).map_err(Into::into))
            .transpose()
    }

    pub fn insert(&mut self, local: &str, result: &impl Serialize) -> Result<()> {
        if !self.available() || self.hits.contains_key(local) {
            return Ok(());
        }
        let Some(key) = self.keys.get(local).cloned() else {
            return Ok(());
        };
        let result = serde_json::to_string(result)?;
        if result.len() > MAX_RESULT_BYTES {
            return Ok(());
        }
        let value = Value { key, result };
        let encoded_bytes = serde_json::to_vec(&value)?.len();
        let envelope_bytes = serde_json::to_vec(&serde_json::json!({
            "context": self.context, "lease": self.lease, "entries": [], "revoke": false
        }))?
        .len();
        if self.pending.len() >= BATCH_SIZE
            || envelope_bytes + self.pending_bytes + encoded_bytes + self.pending.len()
                > MAX_BATCH_BYTES
        {
            self.flush()?;
        }
        if !self.available() {
            return Ok(());
        }
        if envelope_bytes + encoded_bytes > MAX_BATCH_BYTES {
            return Ok(());
        }
        self.pending_bytes += encoded_bytes;
        self.pending.push(value);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let entries = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        if !self.available() {
            return Ok(());
        }
        let body = serde_json::json!({"context":self.context,"lease":self.lease,"entries":entries,"revoke":false});
        let _: serde_json::Value = self.post("write", &body)?;
        Ok(())
    }

    pub fn quarantine(&mut self, local: &str) -> Result<()> {
        let key = self
            .keys
            .get(local)
            .cloned()
            .ok_or_else(|| color_eyre::eyre::eyre!("Missing cache key for quarantine"))?;
        self.hits.remove(local);
        self.pending.clear();
        self.pending_bytes = 0;
        if !self.quarantines.contains(&key) {
            ensure!(
                self.quarantines.len() < 4096,
                "Pending quarantine capacity reached"
            );
            self.quarantines.push(key);
        }
        self.flush_quarantines()
    }

    fn flush_quarantines(&mut self) -> Result<()> {
        while !self.quarantines.is_empty() && self.available() {
            let count = self.quarantines.len().min(BATCH_SIZE);
            let body = serde_json::json!({"context":self.context,"lease":self.lease,"entries":[],"quarantine":self.quarantines[..count]});
            let reply: Acknowledgement = self.post("write", &body)?;
            ensure!(
                reply.quarantined <= count,
                "Invalid quarantine acknowledgement"
            );
            self.quarantines.drain(..count);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn revoke(&mut self) -> Result<()> {
        self.revoked = true;
        self.hits.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        let body = serde_json::json!({"context":self.context,"lease":self.lease,"entries":[],"revoke":true});
        let _: serde_json::Value = self.post("write", &body)?;
        Ok(())
    }
}

pub(crate) fn hash_path(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    Ok(digest.finalize().into())
}

fn rules_digest(rules: &HashMap<String, String>) -> String {
    let mut pairs = rules.iter().collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(name, _)| *name);
    let mut digest = Sha256::new();
    for (name, contents) in pairs {
        for value in [name, contents] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, sync::mpsc, thread};

    fn server(
        responses: Vec<(u16, String)>,
    ) -> (
        String,
        mpsc::Receiver<serde_json::Value>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                let (offset, length) = loop {
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..offset]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= offset + 4 + length {
                            break (offset + 4, length);
                        }
                    }
                };
                tx.send(serde_json::from_slice(&bytes[offset..offset + length]).unwrap())
                    .unwrap();
                write!(stream,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        (url, rx, handle)
    }

    fn client(url: &str) -> DurableCache {
        let mut cache =
            DurableCache::new(Client::new(), url, "yara", "rules", &HashMap::new(), None).unwrap();
        cache.begin_job(Lease {
            name: "test".into(),
            version: "1".into(),
            assignment_id: "lease".into(),
            attempt: 1,
        });
        cache
    }

    fn key() -> (String, Key) {
        (
            "local".into(),
            Key {
                file_digest: "a".repeat(64),
                language: "py".into(),
            },
        )
    }

    #[test]
    fn fresh_worker_reads_durable_result_and_persistent_revocation() {
        let (_, key) = key();
        let hit=serde_json::json!({"revoked":false,"entries":[{"file_digest":key.file_digest,"language":"py","result":"[1,2]"}]}).to_string();
        let (url, rx, server) = server(vec![
            (200, "{\"revoked\":false,\"entries\":[]}".into()),
            (200, "{\"inserted\":1,\"skipped\":0}".into()),
            (200, hit),
            (200, "{}".into()),
            (200, "{\"revoked\":true,\"entries\":[]}".into()),
        ]);
        let mut first = client(&url);
        first.prefetch(&[self::key()]).unwrap();
        assert!(first.lookup::<Vec<u64>>("local").unwrap().is_none());
        first.insert("local", &vec![1_u64, 2]).unwrap();
        first.flush().unwrap();
        drop(first);
        let mut second = client(&url);
        second.prefetch(&[self::key()]).unwrap();
        assert_eq!(
            second.lookup::<Vec<u64>>("local").unwrap().unwrap(),
            vec![1, 2]
        );
        second.revoke().unwrap();
        assert!(second.lookup::<Vec<u64>>("local").unwrap().is_none());
        let mut third = client(&url);
        third.prefetch(&[self::key()]).unwrap();
        assert!(third.revoked);
        server.join().unwrap();
        let bodies = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(bodies[0]["context"], bodies[2]["context"]);
        assert_eq!(bodies[1]["entries"][0]["result"], "[1,2]");
        assert_eq!(bodies[3]["revoke"], true);
    }

    #[test]
    fn unavailable_cache_stops_requests_for_this_job() {
        let (url, rx, server) = server(vec![(503, "{}".into())]);
        let mut cache = client(&url);
        assert!(cache.prefetch(&[key()]).is_err());
        cache.prefetch(&[key()]).unwrap();
        cache.insert("local", &Vec::<u8>::new()).unwrap();
        cache.flush().unwrap();
        assert!(cache.lookup::<Vec<u8>>("local").unwrap().is_none());
        server.join().unwrap();
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[test]
    fn quarantine_retries_after_failure_without_revoking_namespace() {
        let hit = serde_json::json!({"revoked":false,"entries":[
            {"file_digest":"a".repeat(64),"language":"py","result":"[1]"}
        ]})
        .to_string();
        let (url, rx, server) = server(vec![
            (200, hit),
            (503, "{}".into()),
            (200, "{\"quarantined\":1}".into()),
            (200, "{\"revoked\":false,\"entries\":[]}".into()),
            (200, "{\"revoked\":false,\"entries\":[]}".into()),
        ]);
        let mut cache = client(&url);
        cache.prefetch(&[key()]).unwrap();
        assert!(cache.quarantine("local").is_err());
        assert!(!cache.revoked);
        assert!(cache.lookup::<Vec<u8>>("local").unwrap().is_none());
        cache.begin_job(Lease {
            name: "next".into(),
            version: "1".into(),
            assignment_id: "lease".into(),
            attempt: 1,
        });
        cache.prefetch(&[key()]).unwrap();
        assert!(cache.quarantines.is_empty());
        assert!(cache.lookup::<Vec<u8>>("local").unwrap().is_none());
        let mut restarted = client(&url);
        restarted.prefetch(&[key()]).unwrap();
        assert!(restarted.lookup::<Vec<u8>>("local").unwrap().is_none());
        assert!(!restarted.revoked);
        server.join().unwrap();
        let bodies = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(bodies.len(), 5);
        assert_eq!(bodies[1]["quarantine"], bodies[2]["quarantine"]);
        assert!(bodies[1].get("revoke").is_none());
    }

    #[test]
    fn oversized_response_disables_previously_loaded_hits() {
        let (_, key) = key();
        let hit = serde_json::json!({"revoked":false,"entries":[
            {"file_digest":key.file_digest,"language":"py","result":"[]"}
        ]})
        .to_string();
        let bad = serde_json::json!({"revoked":false,"entries":[
            {"file_digest":key.file_digest,"language":"py","result":"x".repeat(MAX_RESULT_BYTES + 1)}
        ]}).to_string();
        let (url, rx, server) = server(vec![(200, hit), (200, bad)]);
        let mut cache = client(&url);
        cache.prefetch(&[self::key()]).unwrap();
        assert!(cache.lookup::<Vec<u8>>("local").unwrap().is_some());
        assert!(cache.prefetch(&[self::key()]).is_err());
        assert!(cache.lookup::<Vec<u8>>("local").unwrap().is_none());
        cache.prefetch(&[self::key()]).unwrap();
        server.join().unwrap();
        assert_eq!(rx.try_iter().count(), 2);
    }

    #[test]
    fn writes_bound_the_entire_encoded_request() {
        let (url, rx, server) = server(vec![(200, "{}".into()), (200, "{}".into())]);
        let mut cache = client(&url);
        for n in 0..32 {
            let local = n.to_string();
            cache.keys.insert(
                local.clone(),
                Key {
                    file_digest: format!("{n:064x}"),
                    language: "py".into(),
                },
            );
            cache.insert(&local, &vec!["\"".repeat(7_000)]).unwrap();
        }
        cache.flush().unwrap();
        server.join().unwrap();
        let requests = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests
                .iter()
                .map(|v| v["entries"].as_array().unwrap().len())
                .sum::<usize>(),
            32
        );
        for request in requests {
            assert!(serde_json::to_vec(&request).unwrap().len() <= MAX_BATCH_BYTES);
        }
    }

    #[test]
    fn hash_and_corpus_fingerprints_are_stable_and_content_sensitive() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"abc").unwrap();
        let digest = hash_path(file.path()).unwrap();
        assert_eq!(digest.to_vec(), Sha256::digest(b"abc").to_vec());
        let a = HashMap::from([("a".into(), "bc".into())]);
        let b = HashMap::from([("ab".into(), "c".into())]);
        assert_ne!(rules_digest(&a), rules_digest(&b));
    }
}
