mod methods;
mod models;

use lapin::{
    message::Delivery,
    options::{
        BasicConsumeOptions, BasicPublishOptions, BasicQosOptions, ExchangeDeclareOptions,
        QueueBindOptions, QueueDeclareOptions,
    },
    types::FieldTable,
    BasicProperties, Channel, Connection, Consumer, ExchangeKind,
};
pub use methods::*;
pub use models::*;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, instrument, trace, warn};
use yara::Compiler;

use crate::{error::DragonflyError, scanner::DistributionFile, APP_CONFIG};
use flate2::read::GzDecoder;
use futures::StreamExt;
use reqwest::{Client, Url};
use std::io::{Cursor, Read};

/// Type alias representing a tar archive
pub type TarballType = tar::Archive<Cursor<Vec<u8>>>;

/// Type alias representing a zip archive
pub type ZipType = zip::ZipArchive<Cursor<Vec<u8>>>;

pub struct RulesState {
    pub compiled_rules: yara::Rules,
    pub commit_hash: String,
}

impl TryFrom<RulesResponse> for RulesState {
    type Error = yara::Error;

    fn try_from(rules_response: RulesResponse) -> Result<Self, Self::Error> {
        let rules_str = rules_response
            .rules
            .values()
            .map(String::as_ref)
            .collect::<Vec<&str>>()
            .join("\n");

        let compiled_rules = Compiler::new()?
            .add_rules_str(&rules_str)?
            .compile_rules()?;
        let commit_hash = rules_response.hash;

        Ok(RulesState {
            compiled_rules,
            commit_hash,
        })
    }
}

pub struct AuthenticationState {
    pub access_token: String,
    pub expires_in: tokio::time::Duration,
}

impl From<AuthenticationResponse> for AuthenticationState {
    fn from(authentication_response: AuthenticationResponse) -> Self {
        let access_token = authentication_response.access_token;
        let expires_in =
            tokio::time::Duration::from_secs(u64::from(authentication_response.expires_in));
        Self {
            access_token,
            expires_in,
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct DragonflyClient {
    http_client: Client,
    consumer: Mutex<Consumer>,
    rule_updates_consumer: Mutex<Consumer>,
    channel: Channel,

    pub authentication: RwLock<AuthenticationState>,
    pub rules: RwLock<RulesState>,
}

impl DragonflyClient {
    pub async fn init(
        http_client: Client,
        amqp_connection: Connection,
    ) -> Result<Self, DragonflyError> {
        let channel = amqp_connection.create_channel().await?;
        channel
            .basic_qos(APP_CONFIG.prefetch, BasicQosOptions::default())
            .await?;
        info!("Created channel");

        channel
            .queue_declare(
                "jobs",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;
        info!("Declared incoming jobs queue");

        channel
            .queue_declare(
                "results",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;
        info!("Declared outgoing results queue");

        channel
            .exchange_declare(
                "rule_updates",
                ExchangeKind::Fanout,
                ExchangeDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;
        info!("Declared rule_updates exchange");

        let rule_updates_queue = channel
            .queue_declare(
                "",
                QueueDeclareOptions {
                    auto_delete: true,
                    durable: false,
                    exclusive: true,
                    nowait: false,
                    passive: false,
                },
                FieldTable::default(),
            )
            .await?;
        info!(
            "Declared exlusive rule updates queue (name: {})",
            rule_updates_queue.name()
        );

        channel
            .queue_bind(
                rule_updates_queue.name().as_str(),
                "rule_updates",
                "",
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        info!(
            "Bound rules update queue (name: {}) to exchange rules_updated",
            rule_updates_queue.name()
        );

        let rule_updates_consumer = channel
            .basic_consume(
                rule_updates_queue.name().as_str(),
                "rules_update",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;

        let consumer = channel
            .basic_consume(
                "jobs",
                "incoming_jobs",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;

        trace!("Performing initial authentication");
        // First fetch an access token
        let authentication_response = fetch_access_token(&http_client).await?;
        let authentication_state = AuthenticationState::from(authentication_response);
        info!("Successfully performed initial authentication");

        trace!("Fetching initial rules");
        // Then use the access token to fetch and compile YARA rules
        let rules_response = fetch_rules(&http_client, &authentication_state.access_token).await?;
        let rules_state = RulesState::try_from(rules_response)?;
        info!("Successfully fetched initial rules");

        Ok(Self {
            http_client,
            consumer: Mutex::new(consumer),
            rule_updates_consumer: Mutex::new(rule_updates_consumer),
            channel,

            authentication: RwLock::new(authentication_state),

            rules: RwLock::new(rules_state),
        })
    }

    /// Receive a delivery from the message queue
    pub async fn receive_delivery(&self) -> Result<Delivery, DragonflyError> {
        match self.consumer.lock().await.next().await {
            Some(Ok(delivery)) => Ok(delivery),
            Some(Err(err)) => Err(DragonflyError::from(err)),
            None => Err(DragonflyError::ConsumerCancelled),
        }
    }

    /// Receive a delivery from the rule updates queue
    pub async fn receive_rule_update(&self) -> Result<Delivery, DragonflyError> {
        match self.rule_updates_consumer.lock().await.next().await {
            Some(Ok(delivery)) => Ok(delivery),
            Some(Err(err)) => Err(DragonflyError::from(err)),
            None => Err(DragonflyError::ConsumerCancelled),
        }
    }

    pub async fn push_results(
        &self,
        results: &SubmitJobResultsSuccess,
    ) -> Result<(), DragonflyError> {
        let serialized_results = serde_json::to_string(&results)?;
        self.channel
            .basic_publish(
                "",
                "results",
                BasicPublishOptions::default(),
                serialized_results.as_bytes(),
                BasicProperties::default(),
            )
            .await?;

        Ok(())
    }

    #[instrument(skip(self), name = "reauthenticating")]
    pub async fn reauthenticate(&self) {
        trace!("Waiting for write lock");
        let mut lock = self.authentication.write().await;
        info!("Acquired write lock");

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        let authentication_response = loop {
            match fetch_access_token(&self.http_client).await {
                Ok(authentication_response) => break authentication_response,
                Err(e) => {
                    let sleep_time = if tries < 10 {
                        let t = initial_timeout * base.powf(f64::from(tries));
                        warn!("Failed after {tries} tries! Error: {e:#?}. Trying again in {t:.3} seconds");
                        t
                    } else {
                        error!("Failed after {tries} tries! Error: {e:#?}. Trying again in 600.000 seconds");
                        600_f64
                    };

                    tokio::time::sleep(std::time::Duration::from_secs_f64(sleep_time)).await;
                    tries += 1;
                }
            }
        };

        trace!("Got new access token!");

        *lock = AuthenticationState::from(authentication_response);

        info!("Successfully reauthenticated.");
    }

    #[instrument(skip(self), name = "updating_rules")]
    pub async fn update_rules(&self) {
        trace!("Waiting for write lock");
        let mut lock = self.rules.write().await;
        info!("Acquired write lock");

        let base = 2_f64;
        let initial_timeout = 1_f64;
        let mut tries = 0;

        info!("Fetching rules");
        let rules_state = loop {
            match fetch_rules(
                &self.http_client,
                &self.authentication.read().await.access_token,
            )
            .await
            {
                Ok(rules_response) => match RulesState::try_from(rules_response) {
                    Ok(rules_state) => break rules_state,
                    Err(yara_error) => error!("YARA error: {yara_error}"),
                },
                Err(http_err) => error!("HTTP Error: {http_err}"),
            };

            let sleep_time = if tries < 10 {
                initial_timeout * base.powf(f64::from(tries))
            } else {
                600_f64
            };

            warn!("Failed in {tries} attempts, trying again in {sleep_time} seconds");
            tokio::time::sleep(std::time::Duration::from_secs_f64(sleep_time)).await;
            tries += 1;
        };
        info!("Got new rules");

        *lock = rules_state;

        info!("Successfully updated rules.");
    }
}

pub fn fetch_tarball(download_url: &Url) -> Result<TarballType, DragonflyError> {
    let response = reqwest::blocking::get(download_url.clone())?;

    let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let decompressed = GzDecoder::new(response);
    decompressed
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(tar::Archive::new(cursor))
}

pub fn fetch_zipfile(download_url: &Url) -> Result<ZipType, DragonflyError> {
    let response = reqwest::blocking::get(download_url.to_string())?;

    let mut cursor = Cursor::new(Vec::new());
    response
        .take(APP_CONFIG.max_scan_size)
        .read_to_end(cursor.get_mut())?;

    Ok(zip::ZipArchive::new(cursor)?)
}

pub fn download_distribution(download_url: &str) -> Result<DistributionFile, DragonflyError> {
    let parsed_download_url: Url = download_url.parse().unwrap();
    if download_url.ends_with(".tar.gz") {
        let tar = fetch_tarball(&parsed_download_url)?;
        Ok(DistributionFile::Tar(tar))
    } else {
        let zip = fetch_zipfile(&parsed_download_url)?;
        Ok(DistributionFile::Zip(zip))
    }
}
