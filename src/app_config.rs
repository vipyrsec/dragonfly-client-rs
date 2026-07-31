use std::sync::LazyLock;

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

const MEBIBYTE: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub threads: usize,
    pub load_duration: u64,
    pub bulk_size: usize,
    pub cf_access_client_id: String,
    pub cf_access_client_secret: String,
    pub max_archive_entries: usize,
    pub max_distributions: usize,
    pub max_download_size: u64,
    pub max_expanded_size: u64,
    pub max_scan_size: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        let available_parallelism = std::thread::available_parallelism().map_or(1, usize::from);

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        AppConfig {
            base_url: String::from("https://dragonfly.vipyrsec.com"),
            cf_access_client_id: String::new(),
            cf_access_client_secret: String::new(),
            threads: available_parallelism,
            bulk_size: 20,
            load_duration: 60,
            max_archive_entries: 4096,
            max_distributions: 32,
            max_download_size: 32 * MEBIBYTE,
            max_expanded_size: 64 * MEBIBYTE,
            max_scan_size: 16 * MEBIBYTE,
        }
    }
}

impl AppConfig {
    /// Load configuration defaults, TOML files, and environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error when configured values cannot be deserialized.
    #[allow(clippy::result_large_err)]
    pub fn build() -> Result<AppConfig, figment::Error> {
        Figment::from(Serialized::defaults(AppConfig::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Toml::file("Config-dev.toml"))
            .merge(Env::prefixed("DRAGONFLY_"))
            .extract()
    }
}

/// The global, immutable application configuration.
pub static APP_CONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig::build().unwrap());
