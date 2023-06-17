use std::{
    collections::HashSet,
    io::{Cursor, Read},
    path::PathBuf,
};

use yara::{MetadataValue, Rule, Rules};
use zip::ZipArchive;

use crate::{api::DragonflyClient, error::DragonflyError};

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct RuleScore {
    pub rule_name: String,
    pub score: Option<i64>,
}

#[derive(Debug)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub rules: Vec<RuleScore>,
}

impl FileScanResult {
    fn calculate_score(&self) -> i64 {
        self.rules.iter().map(|i| i.score.unwrap_or(0)).sum()
    }
}

pub struct DistributionScanResults {
    download_url: String,
    file_scan_results: Vec<FileScanResult>,
}

impl DistributionScanResults {
    pub fn get_most_malicious_file(&self) -> Option<&FileScanResult> {
        self.file_scan_results
            .iter()
            .max_by_key(|i| i.calculate_score())
    }

    pub fn get_total_score(&self) -> i64 {
        let mut rules: HashSet<&RuleScore> = HashSet::new();
        for file_scan_result in &self.file_scan_results {
            for rule in &file_scan_result.rules {
                rules.insert(rule);
            }
        }

        rules.iter().map(|i| i.score.unwrap_or(0)).sum()
    }

    pub fn get_all_rules(&self) -> HashSet<&String> {
        let mut rule_names: HashSet<&String> = HashSet::new();

        for file_scan_result in &self.file_scan_results {
            for rule in &file_scan_result.rules {
                rule_names.insert(&rule.rule_name);
            }
        }

        rule_names
    }

    pub fn download_url(&self) -> &String {
        &self.download_url
    }
}

pub fn scan_distribution(
    client: &DragonflyClient,
    download_url: &String,
) -> Result<DistributionScanResults, DragonflyError> {
    if download_url.ends_with("tar.gz") {
        let mut tar = client.fetch_tarball(download_url)?;
        let rules = { &client.state.lock().unwrap().rules };
        scan_tarball(&mut tar, download_url, rules)
    } else {
        let mut zip = client.fetch_zipfile(download_url)?;
        let rules = { &client.state.lock().unwrap().rules };
        scan_zipfile(&mut zip, download_url, rules)
    }
}

fn get_rule_score(rule: &Rule) -> Option<i64> {
    let m = rule
        .metadatas
        .iter()
        .find(|metadata| metadata.identifier == "weight");

    if let Some(metadata) = m {
        match metadata.value {
            MetadataValue::Integer(integer) => Some(integer),
            _ => None,
        }
    } else {
        None
    }
}

fn get_filetypes<'a>(rule: &'a Rule) -> Vec<&'a str> {
    let m = rule
        .metadatas
        .iter()
        .find(|metadata| metadata.identifier == "filetypes")
        .map(|metadata| &metadata.value);

    if let Some(MetadataValue::String(string)) = m {
        string.split(' ').collect()
    } else {
        Vec::new()
    }
}

pub fn scan_zipfile(
    zip: &mut ZipArchive<Cursor<Vec<u8>>>,
    download_url: &str,
    rules: &Rules,
) -> Result<DistributionScanResults, DragonflyError> {
    let mut file_scan_results: Vec<FileScanResult> = Vec::new();
    let file_names: Vec<String> = zip
        .file_names()
        .map(std::borrow::ToOwned::to_owned)
        .collect();
    for file_name in file_names {
        let mut file = zip.by_name(&file_name)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let rules_matched = rules.scan_mem(&buffer, 10)?;

        file_scan_results.push(FileScanResult {
            path: PathBuf::from(&file_name),
            rules: rules_matched
                .into_iter()
                .filter(|rule| {
                    let filetypes = get_filetypes(rule);
                    if filetypes.is_empty() {
                        true
                    } else {
                        filetypes
                            .iter()
                            .any(|filetype| file_name.ends_with(filetype))
                    }
                })
                .map(|rule| RuleScore {
                    rule_name: rule.identifier.to_owned(),
                    score: get_rule_score(&rule),
                })
                .collect(),
        });
    }

    Ok(DistributionScanResults {
        file_scan_results,
        download_url: download_url.to_owned(),
    })
}

pub fn scan_tarball(
    tar: &mut tar::Archive<Cursor<Vec<u8>>>,
    download_url: &str,
    rules: &Rules,
) -> Result<DistributionScanResults, DragonflyError> {
    let mut file_scan_results: Vec<FileScanResult> = Vec::new();

    for entry in tar.entries()? {
        let mut entry = entry?;

        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer)?;

        let rules_matched = rules.scan_mem(&buffer, 10)?;
        let path = entry.path()?;

        file_scan_results.push(FileScanResult {
            path: path.to_path_buf(),
            rules: rules_matched
                .into_iter()
                .filter(|rule| {
                    let filetypes = get_filetypes(rule);
                    if filetypes.is_empty() {
                        true
                    } else {
                        filetypes.iter().any(|filetype| path.ends_with(filetype))
                    }
                })
                .map(|rule| RuleScore {
                    rule_name: rule.identifier.to_owned(),
                    score: get_rule_score(&rule),
                })
                .collect(),
        });
    }

    Ok(DistributionScanResults {
        file_scan_results,
        download_url: download_url.to_string(),
    })
}
