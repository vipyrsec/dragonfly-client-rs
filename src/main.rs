mod app_config;
mod client;
mod error;
mod exts;
mod scanner;
mod utils;

use std::sync::Arc;
use std::time::Instant;

use client::download_distribution;
use client::DragonflyClient;
use error::DragonflyError;
use tracing::trace_span;
use tracing::Instrument;
use tracing::{error, info, trace};
use tracing_subscriber::EnvFilter;

use lapin::{
    message::Delivery,
    options::{BasicAckOptions, BasicRejectOptions},
    Connection, ConnectionProperties,
};
use reqwest::Client;
use scanner::{Distribution, DistributionScanResults};
use tracing::info_span;
use tracing::warn;
use utils::create_inspector_url;

use crate::{app_config::APP_CONFIG, client::Job, scanner::PackageScanResults};

#[tracing::instrument(skip_all, fields(name = job.name, version = job.version))]
fn runner(client: &DragonflyClient, job: Job) -> Result<PackageScanResults, DragonflyError> {
    let mut distribution_scan_results: Vec<DistributionScanResults> = Vec::new();
    for download_url in &job.distributions {
        let _span = trace_span!(
            "Scanner",
            distribution = download_url.split('/').last().unwrap_or("/")
        )
        .entered();
        trace!("Downloading distribution");
        let file = download_distribution(download_url)?;
        trace!("Successfully downloaded distribution");
        let inspector_url = create_inspector_url(
            &job.name,
            &job.version,
            &download_url.clone().parse().unwrap(),
        );
        let mut distribution = Distribution {
            file,
            inspector_url,
        };
        trace!("Blocking until rules are available");
        let rules_state = client.rules.blocking_read();
        trace!("Got read lock on rules, starting scan");
        let start = Instant::now();
        let distribution_scan_result = distribution.scan(&rules_state.compiled_rules)?;
        let end = Instant::now();
        let duration = end - start;
        trace!(
            "Finished scan! Took {}s {}ms ",
            duration.as_secs(),
            duration.subsec_millis()
        );

        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(PackageScanResults {
        name: job.name,
        version: job.version,
        distribution_scan_results,
    })
}

#[tracing::instrument(skip_all, fields(name, version))]
async fn handle_delivery(
    client: Arc<DragonflyClient>,
    delivery: &Delivery,
) -> Result<(), DragonflyError> {
    trace!("Parsing delivery for job");
    let job: Job = serde_json::from_slice(&delivery.data)?;
    trace!("Successfully parsed delivery");

    tracing::Span::current().record("name", &job.name);
    tracing::Span::current().record("version", &job.version);

    trace!("Spawning blocking scanner job in threadpool");
    let results = tokio::task::spawn_blocking({
        let client = Arc::clone(&client);
        move || runner(&client, job)
    })
    .await??;
    trace!("Scanner job in threadpool finished");
    trace!("Pushing results onto results queue");
    client.push_results(&results.build_body()).await?;
    trace!("Ack'ing original delivery");
    delivery.ack(BasicAckOptions::default()).await?;
    info!("Acknowledged delivery");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let http_client = Client::new();

    let connection = Connection::connect(&APP_CONFIG.amqp, ConnectionProperties::default()).await?;
    info!("Established connection to AMQP server");
    let client = Arc::new(DragonflyClient::init(http_client, connection).await?);

    tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            loop {
                let sleep = client.authentication.read().await.expires_in
                    - tokio::time::Duration::from_secs(10);
                tokio::time::sleep(sleep).await;
                client.reauthenticate().await;
            }
        }
    });

    tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            loop {
                match client.receive_rule_update().await {
                    Ok(_) => client.update_rules().await,
                    Err(err) => error!("Error from rule updates queue: {err}"),
                }
            }
        }
    });

    loop {
        trace!("Waiting for message");
        match client.receive_delivery().await {
            Ok(delivery) => {
                trace!("Message received");
                let client = Arc::clone(&client);
                tokio::task::spawn(async move {
                    if let Err(err) = handle_delivery(Arc::clone(&client), &delivery).await {
                        error!("Error while scanning: {err}");
                        match delivery.reject(BasicRejectOptions { requeue: false }).await {
                            Ok(()) => warn!("Rejected message"),
                            Err(err) => error!("Error while rejecting: {err}"),
                        }
                    }
                });
            }
            Err(err) => error!("Error while consuming: {err}"),
        }
    }
}
