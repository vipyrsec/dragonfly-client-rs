use std::io;

use config::ConfigError;
use yara;
use reqwest;
use zip::result::ZipError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DragonflyError {

    #[error("Yara Error: {source:#?}")]
    YaraError{
        #[from]
        source: yara::YaraError
    },

    #[error("Yara Error: {source:#?}")]
    GenericYaraError{
        #[from]
        source: yara::Error
    },

    #[error("HTTP Error: {source:#?}")]
    HTTPError {
        #[from]
        source: reqwest::Error
    },

    #[error("IO Error: {source:#?}")]
    IOError{
        #[from]
        source: io::Error
    },

    #[error("Zipfile Error: {source:#?}")]
    ZipError {
        #[from]
        source: ZipError
    },

    #[error("Configuration Error: {source:#?}")]
    ConfigError {
        #[from]
        source: ConfigError 
    },
    #[error("Download too large: '{0:#?}'")]
    DownloadTooLarge(String),
}
