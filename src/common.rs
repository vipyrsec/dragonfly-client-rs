use once_cell::sync::Lazy;

use crate::app_config::AppConfig;

/// The global, immutable application configuration.
pub static APP_CONFIG: Lazy<AppConfig> = Lazy::new(|| AppConfig::build().unwrap());
