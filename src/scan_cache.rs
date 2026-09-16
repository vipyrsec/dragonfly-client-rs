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

#[derive(Clone)]
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
            directory: tempfile::tempdir()?,
            files: HashMap::new(),
            max_entries,
            remaining_bytes: max_bytes,
            scanned_files: 0,
            reused_files: 0,
        })
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

        let matches: Vec<_> = self
            .rules
            .scan_file(path, 10)?
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
        let result = matches_for_path(&matches, path);
        if self.files.len() < self.max_entries
            && size <= self.remaining_bytes
            && !self.files.contains_key(&identity)
        {
            let destination = self.directory.path().join(self.files.len().to_string());
            fs::copy(path, &destination)?;
            self.remaining_bytes -= size;
            self.files.insert(
                identity,
                CachedFile {
                    path: destination,
                    matches,
                },
            );
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
