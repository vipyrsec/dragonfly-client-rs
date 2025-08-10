use std::sync::LazyLock;

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub load_duration: u64,
    pub auth0_domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub grant_type: String,
    pub username: String,
    pub password: String,
    pub max_scan_size: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        AppConfig {
            base_url: String::from("https://dragonfly.vipyrsec.com"),
            auth0_domain: String::from("vipyrsec.us.auth0.com"),
            audience: String::from("https://dragonfly.vipyrsec.com"),
            grant_type: String::from("password"),
            client_id: String::new(),
            client_secret: String::new(),
            username: String::new(),
            password: String::new(),
            load_duration: 60,
            max_scan_size: 1.28e+8 as u64, // 128 MB
        }
    }
}

impl AppConfig {
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
