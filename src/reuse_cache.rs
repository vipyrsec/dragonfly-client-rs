//! Bounded process-local results. A cache belongs to one loaded rules snapshot.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    #[default]
    Off,
    Observe,
    Reuse,
}

struct Entry {
    content: Vec<u8>,
    result: Vec<u8>,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    order: VecDeque<String>,
    bytes: usize,
}

pub(crate) struct ReuseCache {
    pub mode: CacheMode,
    remote: Option<Mutex<crate::durable_cache::DurableCache>>,
    max_entries: usize,
    max_bytes: usize,
    state: Mutex<State>,
    hits: AtomicU64,
    disabled: AtomicBool,
}

impl ReuseCache {
    pub(crate) fn new(mode: CacheMode, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            mode,
            remote: None,
            max_entries,
            max_bytes,
            state: Mutex::new(State::default()),
            hits: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_database(&mut self, remote: crate::durable_cache::DurableCache) {
        self.remote = Some(Mutex::new(remote));
    }

    pub(crate) fn uses_database(&self) -> bool {
        self.remote.is_some()
    }

    pub(crate) fn begin_job(&self, job: &crate::client::Job) {
        if let Some(remote) = &self.remote {
            if let Ok(mut remote) = remote.lock() {
                remote.begin_job(crate::durable_cache::Lease {
                    name: job.name.clone(),
                    version: job.version.clone(),
                    assignment_id: job.assignment_id.clone(),
                    attempt: job.attempt,
                });
            }
        }
    }

    pub(crate) fn prefetch(
        &self,
        keys: &[(String, crate::durable_cache::Key)],
        stats: &mut CacheStats,
    ) {
        self.remote_operation(stats, |remote| remote.prefetch(keys));
    }

    pub(crate) fn flush(&self, stats: &mut CacheStats) {
        self.remote_operation(stats, crate::durable_cache::DurableCache::flush);
    }

    fn remote_operation(
        &self,
        stats: &mut CacheStats,
        operation: impl FnOnce(&mut crate::durable_cache::DurableCache) -> color_eyre::Result<()>,
    ) {
        if self.mode == CacheMode::Off || self.disabled.load(Ordering::Acquire) {
            return;
        }
        let Some(remote) = &self.remote else {
            return;
        };
        let started = Instant::now();
        let result = (|| {
            let mut remote = remote
                .lock()
                .map_err(|_| color_eyre::eyre::eyre!("cache lock poisoned"))?;
            let result = operation(&mut remote);
            if remote.revoked {
                self.disabled.store(true, Ordering::Release);
            }
            result
        })();
        stats.overhead_us += started.elapsed().as_micros();
        if let Err(error) = result {
            stats.errors += 1;
            tracing::warn!(event="scan_reuse_error", %error, "Database cache unavailable; scanning normally");
        }
    }

    pub(crate) fn should_reuse(&self) -> bool {
        self.mode == CacheMode::Reuse
            && !self.disabled.load(Ordering::Relaxed)
            && !(self.hits.fetch_add(1, Ordering::Relaxed) + 1).is_multiple_of(100)
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Acquire)
    }

    pub(crate) fn disable(&self) {
        self.disabled.store(true, Ordering::Release);
        if let Some(remote) = &self.remote {
            if let Ok(mut remote) = remote.lock() {
                if let Err(error) = remote.revoke() {
                    tracing::error!(event="scan_cache_revocation_failed", %error, "Failed to persist cache revocation");
                }
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.state = Mutex::new(State::default());
        self.disabled.store(false, Ordering::Relaxed);
        self.hits.store(0, Ordering::Relaxed);
    }

    pub(crate) fn lookup<T: DeserializeOwned>(
        &self,
        key: &str,
        path: &Path,
        stats: &mut CacheStats,
    ) -> Option<T> {
        if self.mode == CacheMode::Off || self.disabled.load(Ordering::Relaxed) {
            return None;
        }
        let started = Instant::now();
        stats.lookups += 1;
        let result = self.read(key, path);
        stats.overhead_us += started.elapsed().as_micros();
        match result {
            Ok(Some(value)) => {
                stats.candidate_files += 1;
                Some(value)
            }
            Ok(None) => None,
            Err(error) => {
                stats.errors += 1;
                tracing::warn!(event = "scan_reuse_error", %error, "Cache lookup failed; scanning normally");
                None
            }
        }
    }

    fn read<T: DeserializeOwned>(&self, key: &str, path: &Path) -> color_eyre::Result<Option<T>> {
        if let Some(remote) = &self.remote {
            return remote
                .lock()
                .map_err(|_| color_eyre::eyre::eyre!("cache lock poisoned"))?
                .lookup(key);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| color_eyre::eyre::eyre!("cache lock poisoned"))?;
        let Some(entry) = state.entries.get(key) else {
            return Ok(None);
        };
        // Hashes locate candidates; exact bytes are required before trusting results.
        if fs::read(path)? != entry.content {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&entry.result)?))
    }

    pub(crate) fn insert<T: Serialize>(
        &self,
        key: String,
        path: &Path,
        value: &T,
        stats: &mut CacheStats,
    ) {
        if self.mode == CacheMode::Off
            || self.max_entries == 0
            || self.disabled.load(Ordering::Relaxed)
        {
            return;
        }
        let started = Instant::now();
        if let Err(error) = self.write(key, path, value, stats) {
            stats.errors += 1;
            tracing::warn!(event = "scan_reuse_error", %error, "Cache write failed; preserving scan result");
        }
        stats.overhead_us += started.elapsed().as_micros();
    }

    fn write<T: Serialize>(
        &self,
        key: String,
        path: &Path,
        value: &T,
        stats: &mut CacheStats,
    ) -> color_eyre::Result<()> {
        if let Some(remote) = &self.remote {
            return remote
                .lock()
                .map_err(|_| color_eyre::eyre::eyre!("cache lock poisoned"))?
                .insert(&key, value);
        }
        if path.metadata()?.len() > u64::try_from(self.max_bytes)? {
            return Ok(());
        }
        let result = serde_json::to_vec(value)?;
        let content = fs::read(path)?;
        let size = content.len().saturating_add(result.len());
        if size > self.max_bytes {
            return Ok(());
        }
        let mut storage = self
            .state
            .lock()
            .map_err(|_| color_eyre::eyre::eyre!("cache lock poisoned"))?;
        if storage.entries.contains_key(&key) {
            return Ok(());
        }
        while storage.entries.len() >= self.max_entries
            || storage.bytes.saturating_add(size) > self.max_bytes
        {
            let Some(oldest) = storage.order.pop_front() else {
                break;
            };
            if let Some(entry) = storage.entries.remove(&oldest) {
                storage.bytes -= entry.content.len() + entry.result.len();
                stats.evicted_files += 1;
            }
        }
        storage.bytes += size;
        storage.order.push_back(key.clone());
        storage.entries.insert(key, Entry { content, result });
        stats.inserted_files += 1;
        Ok(())
    }
}

/// Per-job work counters, emitted even when a job exits early with an error.
#[derive(Clone, Serialize)]
pub(crate) struct CacheStats {
    scanner: &'static str,
    pub mode: CacheMode,
    pub lookups: u64,
    pub candidate_files: u64,
    pub reused_files: u64,
    pub reused_bytes: u64,
    pub inserted_files: u64,
    pub evicted_files: u64,
    pub errors: u64,
    pub validated_files: u64,
    pub mismatched_files: u64,
    pub overhead_us: u128,
    pub engine_us: u128,
    pub engine_files: u64,
    pub engine_bytes: u64,
}

impl CacheStats {
    pub(crate) fn new(scanner: &'static str, mode: CacheMode) -> Self {
        Self {
            scanner,
            mode,
            lookups: 0,
            candidate_files: 0,
            reused_files: 0,
            reused_bytes: 0,
            inserted_files: 0,
            evicted_files: 0,
            errors: 0,
            validated_files: 0,
            mismatched_files: 0,
            overhead_us: 0,
            engine_us: 0,
            engine_files: 0,
            engine_bytes: 0,
        }
    }
}

impl CacheStats {
    pub(crate) fn emit(&self) {
        tracing::info!(event = "scan_reuse", scanner = self.scanner, mode = ?self.mode,
            lookups = self.lookups, candidate_files = self.candidate_files,
            reused_files = self.reused_files, reused_bytes = self.reused_bytes,
            inserted_files = self.inserted_files, evicted_files = self.evicted_files,
            cache_errors = self.errors, validated_files = self.validated_files, mismatched_files = self.mismatched_files, overhead_us = self.overhead_us,
            engine_us = self.engine_us, engine_files = self.engine_files, engine_bytes = self.engine_bytes,
            "Cross-package scan reuse statistics");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_audits_every_hundredth_hit_and_can_be_disabled() {
        let mut cache = ReuseCache::new(CacheMode::Reuse, 10, 1024);
        for _ in 0..99 {
            assert!(cache.should_reuse());
        }
        assert!(!cache.should_reuse());
        assert!(cache.should_reuse());
        cache.disable();
        assert!(!cache.should_reuse());
        cache.clear();
        assert!(cache.should_reuse());
    }

    #[test]
    fn exact_bytes_bounds_and_rule_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        fs::write(&path, b"clean").unwrap();
        let mut cache = ReuseCache::new(CacheMode::Reuse, 1, 64);
        let mut stats = CacheStats::new("test", CacheMode::Reuse);
        cache.insert("key".into(), &path, &vec!["finding"], &mut stats);
        assert_eq!(
            cache
                .lookup::<Vec<String>>("key", &path, &mut stats)
                .unwrap(),
            vec!["finding"]
        );
        fs::write(&path, b"evil!").unwrap();
        assert!(cache
            .lookup::<Vec<String>>("key", &path, &mut stats)
            .is_none());
        cache.insert("new".into(), &path, &Vec::<String>::new(), &mut stats);
        assert_eq!(stats.evicted_files, 1);
        assert!(cache
            .lookup::<Vec<String>>("new", &path, &mut stats)
            .unwrap()
            .is_empty());
        cache.clear();
        assert!(cache
            .lookup::<Vec<String>>("new", &path, &mut stats)
            .is_none());
        fs::write(&path, [0_u8; 65]).unwrap();
        cache.insert("large".into(), &path, &0, &mut stats);
        assert!(cache.state.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn disabled_cache_has_no_io_and_errors_fall_back() {
        let missing = Path::new("/nonexistent/scan-reuse-test");
        let cache = ReuseCache::new(CacheMode::Off, 1, 10);
        let mut stats = CacheStats::new("test", CacheMode::Off);
        cache.insert("key".into(), missing, &0, &mut stats);
        assert!(cache.lookup::<u32>("key", missing, &mut stats).is_none());
        assert_eq!((stats.lookups, stats.errors), (0, 0));
        let cache = ReuseCache::new(CacheMode::Observe, 1, 10);
        cache.insert("key".into(), missing, &0, &mut stats);
        assert_eq!(stats.errors, 1);
    }
}
