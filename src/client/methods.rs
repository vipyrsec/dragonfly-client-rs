use super::{models, ScanResultSerializer};

use crate::{utils::get_jwt_exp, APP_CONFIG};
use chrono::{DateTime, Utc};
use color_eyre::eyre::OptionExt;
use reqwest::blocking::Client;

pub fn perform_initial_authentication(http_client: &Client) -> color_eyre::Result<DateTime<Utc>> {
    let response = http_client
        .get(&APP_CONFIG.base_url)
        .header("CF-Access-Client-Id", &APP_CONFIG.client_id)
        .header("CF-Access-Client-Secret", &APP_CONFIG.client_secret)
        .send()?
        .error_for_status()?;

    let cookie = response
        .cookies()
        .find(|c| c.name() == "CF_Authorization")
        .ok_or_eyre("Did not find CF_Authorization header in response")?;

    get_jwt_exp(cookie.value())
}

pub fn fetch_bulk_job(http_client: &Client, n_jobs: usize) -> reqwest::Result<Vec<models::Job>> {
    http_client
        .post(format!("{}/jobs", APP_CONFIG.base_url))
        .query(&[("batch", n_jobs)])
        .send()?
        .error_for_status()?
        .json()
}

pub fn fetch_rules(http_client: &Client) -> reqwest::Result<models::RulesResponse> {
    http_client
        .get(format!("{}/rules", APP_CONFIG.base_url))
        .send()?
        .error_for_status()?
        .json()
}

pub fn send_result(http_client: &Client, body: models::ScanResult) -> reqwest::Result<()> {
    let body: ScanResultSerializer = body.into();
    http_client
        .put(format!("{}/package", APP_CONFIG.base_url))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}
