use std::io::Cursor;

use crate::app_config::AppConfig;

/// The global, immutable application configuration.
pub static APP_CONFIG: AppConfig = AppConfig::build().unwrap();

/// Type alias representing a tar archive. The underlying type is `Cursor<Vec<u8>>`
pub type TarballType = tar::Archive<Cursor<Vec<u8>>>;

/// Type alias representing a zip archive. The underlying type is `Cursor<Vec<u8>>`
pub type ZipType = zip::ZipArchive<Cursor<Vec<u8>>>;
