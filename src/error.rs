use std::{io, sync::PoisonError};

use yara;
use reqwest;
use zip::result::ZipError;

#[derive(Debug)]
pub enum DragonflyError {
    YaraError(yara::errors::Error),
    HTTPError(reqwest::Error),
    IOError(io::Error),
    ZipError(ZipError),
    UnsupportedDistributionType(String),
    DownloadTooLarge(String),
}

impl From<yara::errors::Error> for DragonflyError {
    fn from(value: yara::errors::Error) -> Self {
        Self::YaraError(value)
    }
}

impl From<yara::YaraError> for DragonflyError {
    fn from(value: yara::YaraError) -> Self {
        Self::YaraError(yara::errors::Error::Yara(value)) 
    }
}

impl From<reqwest::Error> for DragonflyError {
    fn from(value: reqwest::Error) -> Self {
        Self::HTTPError(value)
    }
}

impl From<io::Error> for DragonflyError {
    fn from(value: io::Error) -> Self {
        Self::IOError(value) 
    } 
}

impl From<ZipError> for DragonflyError {
    fn from(value: ZipError) -> Self {
        Self::ZipError(value)
    }
}
