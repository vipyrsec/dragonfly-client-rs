use figment::{Figment, providers::{Serialized, Toml, Format, Env}};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
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
    pub max_scan_size: usize,
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
            threads: std::thread::available_parallelism().map(usize::from).unwrap_or(1),
            wait_duration: 60u64,
            max_scan_size: 2.56e+8 as usize,
        }
    }
}

impl AppConfig {
    pub fn build() -> Result<AppConfig, figment::Error> {
        Figment::from(Serialized::defaults(AppConfig::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Toml::file("Config-dev.toml"))
            .merge(Env::prefixed("DRAGONFLY_"))
            .extract()
    }
}
