use reqwest::Client;

use crate::app_config::APP_CONFIG;

use super::models;

pub async fn fetch_access_token(
    http_client: &Client,
) -> reqwest::Result<models::AuthenticationResponse> {
    let url = format!("https://{}/oauth/token", APP_CONFIG.auth0_domain);
    let json_body = models::AuthenticationBody {
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
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

pub async fn fetch_rules(
    http_client: &Client,
    access_token: &str,
) -> reqwest::Result<models::RulesResponse> {
    http_client
        .get(format!("{}/rules", APP_CONFIG.base_url))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}
