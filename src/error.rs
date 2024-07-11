use std::io;

use figment::Error as ConfigError;
use thiserror::Error;
use zip::result::ZipError;

#[allow(clippy::module_name_repetitions)]
#[derive(Error, Debug)]
pub enum DragonflyError {
    #[error("Yara X Error: {source:#?}")]
    YaraError {
        #[from]
        source: yara_x::Error,
    },

    #[error("Yara X Scan Error: {source:#?}")]
    ScanError {
        #[from]
        source: yara_x::ScanError,
    },

    #[error("HTTP Error: {source:#?}")]
    HTTPError {
        #[from]
        source: reqwest::Error,
    },

    #[error("IO Error: {source:#?}")]
    IOError {
        #[from]
        source: io::Error,
    },

    #[error("Zipfile Error: {source:#?}")]
    ZipError {
        #[from]
        source: ZipError,
    },

    #[error("Configuration Error: {source:#?}")]
    ConfigError {
        #[from]
        source: ConfigError,
    },

    #[allow(dead_code)]
    #[error("Download too large: '{0:#?}'")]
    DownloadTooLarge(String),
}
