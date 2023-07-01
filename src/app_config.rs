use config::{Config, ConfigError};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub threads: usize,
    pub wait_duration: u64,
    pub auth0_domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub grant_type: String,
    pub username: String,
    pub password: String,
    pub max_scan_size: u64,
}

impl AppConfig {
    pub fn build() -> Result<Self, ConfigError> {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Config::builder()
            .add_source(config::File::with_name("Config.toml").required(false))
            .add_source(config::File::with_name("Config-dev.toml").required(false))
            .add_source(config::Environment::default())
            .set_default("base_url", "https://dragonfly.vipyrsec.com")?
            .set_default(
                "threads",
                std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1) as u64,
            )?
            .set_default("auth0_domain", "vipyrsec.us.auth0.com")?
            .set_default("audience", "https://dragonfly.vipyrsec.com")?
            .set_default("grant_type", "password")?
            .set_default("wait_duration", 60u64)?
            .set_default("max_scan_size", 2.56e+8 as u64)?
            .build()?
            .try_deserialize()
    }
}
