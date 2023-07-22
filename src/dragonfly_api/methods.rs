use crate::dragonfly_api::models;
use crate::APP_CONFIG;
use reqwest::blocking::Client;

pub fn fetch_access_token(http_client: &Client) -> reqwest::Result<models::AuthResponse> {
    let url = format!("https://{}/oauth/token", APP_CONFIG.auth0_domain);
    let json_body = models::AuthBody {
        client_id: &APP_CONFIG.client_id,
        client_secret: &APP_CONFIG.client_secret,
        audience: &APP_CONFIG.audience,
        grant_type: &APP_CONFIG.grant_type,
        username: &APP_CONFIG.username,
        password: &APP_CONFIG.password,
    };

    http_client
        .post(url)
        .json(&json_body)
        .send()?
        .error_for_status()?
        .json()
}

pub fn fetch_bulk_job(
    http_client: &Client,
    access_token: &str,
    n_jobs: usize,
) -> reqwest::Result<Vec<models::Job>> {
    http_client
        .post(format!("{}/jobs", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .query(&[("batch", n_jobs)])
        .send()?
        .error_for_status()?
        .json()
}

pub fn fetch_rules(
    http_client: &Client,
    access_token: &str,
) -> reqwest::Result<models::RulesResponse> {
    http_client
        .get(format!("{}/rules", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()?
        .error_for_status()?
        .json()
}

pub fn send_success(
    http_client: &Client,
    access_token: &str,
    body: &models::SubmitJobResultsSuccess,
) -> reqwest::Result<()> {
    http_client
        .put(format!("{}/package", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}

pub fn send_error(
    http_client: &Client,
    access_token: &str,
    body: &models::SubmitJobResultsError,
) -> reqwest::Result<()> {
    http_client
        .put(format!("{}/package", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&body)
        .send()?
        .error_for_status()?;

    Ok(())
}
