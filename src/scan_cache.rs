use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use color_eyre::{eyre::ensure, Result};
use tempfile::TempDir;
use xxhash_rust::xxh3::Xxh3;
use yara::Rules;

use crate::{exts::RuleExt, scanner::RuleScore};

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct ContentMatch {
    score: RuleScore,
    filetypes: Vec<String>,
}

struct CachedFile {
    path: PathBuf,
    matches: Vec<ContentMatch>,
}

/// Reuse successful content scans within one package and one compiled ruleset.
/// Representative bytes live on bounded temporary storage, not in memory.
pub struct ScanCache<'a> {
    rules: &'a Rules,
    reuse: Option<&'a crate::reuse_cache::ReuseCache>,
    pub stats: crate::reuse_cache::CacheStats,
    directory: TempDir,
    files: HashMap<(u128, u64), CachedFile>,
    max_entries: usize,
    remaining_bytes: u64,
    pub scanned_files: usize,
    pub reused_files: usize,
}

impl<'a> ScanCache<'a> {
    pub fn new(rules: &'a Rules, max_entries: usize, max_bytes: u64) -> Result<Self> {
        Ok(Self {
            rules,
            reuse: None,
            stats: crate::reuse_cache::CacheStats::new("yara", crate::reuse_cache::CacheMode::Off),
            directory: tempfile::tempdir()?,
            files: HashMap::new(),
            max_entries,
            remaining_bytes: max_bytes,
            scanned_files: 0,
            reused_files: 0,
        })
    }

    pub fn set_reuse(&mut self, reuse: Option<&'a crate::reuse_cache::ReuseCache>) {
        self.reuse = reuse;
        self.stats.mode = reuse.map_or(crate::reuse_cache::CacheMode::Off, |cache| cache.mode);
    }

    pub fn scan(&mut self, path: &Path, max_scan_size: u64) -> Result<Vec<RuleScore>> {
        let size = path.metadata()?.len();
        ensure!(
            size <= max_scan_size,
            "file {} is {size} bytes, exceeding the {max_scan_size}-byte scan limit",
            path.display()
        );
        let identity = (hash_file(path)?, size);
        if let Some(cached) = self.files.get(&identity) {
            // A hash collision must never suppress a scan of different bytes.
            if files_equal(path, &cached.path, size)? {
                self.reused_files += 1;
                return Ok(matches_for_path(&cached.matches, path));
            }
        }

        let key = format!("{:032x}:{}", identity.0, size);
        let cached = self
            .reuse
            .and_then(|cache| cache.lookup::<Vec<ContentMatch>>(&key, path, &mut self.stats));
        let reuse_enabled = cached.is_some()
            && self
                .reuse
                .is_some_and(crate::reuse_cache::ReuseCache::should_reuse);
        let matches = if let Some(matches) = cached.as_ref().filter(|_| reuse_enabled) {
            self.stats.reused_files += 1;
            self.stats.reused_bytes += size;
            matches.clone()
        } else {
            let started = std::time::Instant::now();
            self.stats.engine_files += 1;
            self.stats.engine_bytes += size;
            let scanned = self.rules.scan_file(path, 10);
            self.stats.engine_us += started.elapsed().as_micros();
            let matches: Vec<_> = scanned?
                .into_iter()
                .map(|rule| ContentMatch {
                    filetypes: rule
                        .get_filetypes()
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    score: RuleScore::from(rule),
                })
                .collect();
            self.scanned_files += 1;
            if let Some(previous) = cached {
                self.stats.validated_files += 1;
                if previous != matches {
                    self.stats.mismatched_files += 1;
                    if let Some(cache) = self.reuse {
                        cache.disable();
                    }
                    tracing::error!(
                        event = "scan_reuse_mismatch",
                        "Cached YARA results differ from fresh scan"
                    );
                }
            }
            if let Some(cache) = self.reuse {
                cache.insert(key, path, &matches, &mut self.stats);
            }
            matches
        };
        let result = matches_for_path(&matches, path);
        if self.files.len() < self.max_entries
            && size <= self.remaining_bytes
            && !self.files.contains_key(&identity)
        {
            let destination = self.directory.path().join(self.files.len().to_string());
            match fs::copy(path, &destination) {
                Ok(_) => {
                    self.remaining_bytes -= size;
                    self.files.insert(
                        identity,
                        CachedFile {
                            path: destination,
                            matches,
                        },
                    );
                }
                Err(error) => {
                    // The package result is already valid. Stop new writes; any
                    // partial representative is removed with the temporary directory.
                    self.max_entries = 0;
                    tracing::warn!(
                        event = "content_scan_cache_write_failed",
                        %error,
                        "Disabling new cache entries; continuing with successful YARA results"
                    );
                }
            }
        }
        Ok(result)
    }
}

fn matches_for_path(matches: &[ContentMatch], path: &Path) -> Vec<RuleScore> {
    matches
        .iter()
        .filter(|matched| {
            matched.filetypes.is_empty()
                || matched
                    .filetypes
                    .iter()
                    .any(|suffix| path.to_string_lossy().ends_with(suffix))
        })
        .map(|matched| matched.score.clone())
        .collect()
}

fn hash_file(path: &Path) -> Result<u128> {
    let mut file = File::open(path)?;
    let mut hasher = Xxh3::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.digest128());
        }
        hasher.update(&buffer[..read]);
    }
}

fn files_equal(left: &Path, right: &Path, mut remaining: u64) -> Result<bool> {
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut left_buffer = [0_u8; 8192];
    let mut right_buffer = [0_u8; 8192];
    while remaining > 0 {
        let length = usize::try_from(remaining.min(8192))?;
        left.read_exact(&mut left_buffer[..length])?;
        right.read_exact(&mut right_buffer[..length])?;
        if left_buffer[..length] != right_buffer[..length] {
            return Ok(false);
        }
        remaining -= u64::try_from(length)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{hash_file, ScanCache};
    use std::fs;
    use tempfile::tempdir;
    use yara::{Compiler, Rules};

    fn rules() -> Rules {
        Compiler::new()
            .unwrap()
            .add_rules_str(
                r#"rule python {
                    meta: filetype = ".py .pyi" weight = 5
                    strings: $a = "danger"
                    condition: $a
                }
                rule compound_suffix {
                    meta: filetype = "special.txt" weight = 3
                    strings: $a = "danger"
                    condition: $a
                }"#,
            )
            .unwrap()
            .compile_rules()
            .unwrap()
    }

    #[test]
    fn cross_job_reuse_observation_and_rules_reset_preserve_results() {
        use crate::reuse_cache::{CacheMode, ReuseCache};
        let rules = rules();
        let dir = tempdir().unwrap();
        let path = dir.path().join("first.py");
        fs::write(&path, b"danger").unwrap();
        for mode in [CacheMode::Off, CacheMode::Observe, CacheMode::Reuse] {
            let mut shared = ReuseCache::new(mode, 10, 1024);
            for iteration in 0..2 {
                let mut job = ScanCache::new(&rules, 10, 1024).unwrap();
                job.set_reuse(Some(&shared));
                assert_eq!(job.scan(&path, 1024).unwrap()[0].name, "python");
                assert_eq!(
                    job.stats.reused_files,
                    u64::from(iteration == 1 && mode == CacheMode::Reuse)
                );
                assert_eq!(
                    job.stats.validated_files,
                    u64::from(iteration == 1 && mode == CacheMode::Observe)
                );
                assert_eq!(job.stats.mismatched_files, 0);
            }
            shared.clear();
            let changed = Compiler::new()
                .unwrap()
                .add_rules_str("rule changed { condition: true }")
                .unwrap()
                .compile_rules()
                .unwrap();
            let mut job = ScanCache::new(&changed, 10, 1024).unwrap();
            job.set_reuse(Some(&shared));
            assert_eq!(job.scan(&path, 1024).unwrap()[0].name, "changed");
            assert_eq!(job.stats.reused_files, 0);
        }
    }

    #[test]
    fn reuse_filters_each_original_path_including_compound_suffixes() {
        let rules = rules();
        let directory = tempdir().unwrap();
        let mut cache = ScanCache::new(&rules, 10, 1024).unwrap();
        for (name, expected) in [
            ("first.txt", None),
            ("second.py", Some("python")),
            ("third.pyi", Some("python")),
            ("special.txt", Some("compound_suffix")),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, b"danger").unwrap();
            let matches = cache.scan(&path, 1024).unwrap();
            assert_eq!(
                matches.first().map(|matched| matched.name.as_str()),
                expected
            );
        }
        assert_eq!((cache.scanned_files, cache.reused_files), (1, 3));
    }

    #[test]
    fn cache_limits_fall_back_to_scanning_and_keep_existing_hits() {
        let rules = rules();
        let directory = tempdir().unwrap();
        for (entries, bytes) in [(1, 1024), (10, 6)] {
            let mut cache = ScanCache::new(&rules, entries, bytes).unwrap();
            let original = directory.path().join("original.py");
            let other = directory.path().join("other.py");
            fs::write(&original, b"danger").unwrap();
            fs::write(&other, b"danger too").unwrap();
            assert_eq!(cache.scan(&original, 1024).unwrap().len(), 1);
            assert_eq!(cache.scan(&other, 1024).unwrap().len(), 1);
            assert_eq!(cache.scan(&other, 1024).unwrap().len(), 1);
            assert_eq!(cache.scan(&original, 1024).unwrap().len(), 1);
            assert_eq!((cache.scanned_files, cache.reused_files), (3, 1));
            assert_eq!(cache.files.len(), 1);
        }
    }

    #[test]
    fn cache_write_failure_preserves_successful_results_and_stops_new_writes() {
        let rules = rules();
        let directory = tempdir().unwrap();
        let path = directory.path().join("module.py");
        fs::write(&path, b"danger").unwrap();
        let mut cache = ScanCache::new(&rules, 10, 1024).unwrap();
        fs::remove_dir(cache.directory.path()).unwrap();
        assert_eq!(cache.scan(&path, 1024).unwrap().len(), 1);
        assert_eq!(cache.scan(&path, 1024).unwrap().len(), 1);
        assert_eq!((cache.scanned_files, cache.reused_files), (2, 0));
        assert_eq!(cache.max_entries, 0);
        assert!(cache.files.is_empty());
    }

    #[test]
    fn hash_collision_does_not_reuse_a_clean_result() {
        let rules = rules();
        let directory = tempdir().unwrap();
        let clean = directory.path().join("clean.py");
        let malicious = directory.path().join("malicious.py");
        fs::write(&clean, b"benign").unwrap();
        fs::write(&malicious, b"danger").unwrap();
        let mut cache = ScanCache::new(&rules, 10, 1024).unwrap();
        assert!(cache.scan(&clean, 1024).unwrap().is_empty());
        let cached = cache
            .files
            .remove(&(hash_file(&clean).unwrap(), 6))
            .unwrap();
        cache
            .files
            .insert((hash_file(&malicious).unwrap(), 6), cached);
        assert_eq!(cache.scan(&malicious, 1024).unwrap().len(), 1);
        assert_eq!((cache.scanned_files, cache.reused_files), (2, 0));
    }

    #[test]
    fn clean_empty_files_reuse_but_size_checks_still_apply() {
        let rules = rules();
        let directory = tempdir().unwrap();
        let path = directory.path().join("empty.py");
        fs::write(&path, b"").unwrap();
        let mut cache = ScanCache::new(&rules, 10, 1024).unwrap();
        assert!(cache.scan(&path, 0).unwrap().is_empty());
        assert!(cache.scan(&path, 0).unwrap().is_empty());
        assert_eq!((cache.scanned_files, cache.reused_files), (1, 1));
        fs::write(&path, b"danger").unwrap();
        cache.scan(&path, 6).unwrap();
        assert!(cache.scan(&path, 5).is_err());
        assert_eq!((cache.scanned_files, cache.reused_files), (2, 1));
    }
}
