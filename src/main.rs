mod app_config;
mod client;
mod exts;
mod scanner;
mod utils;

use std::time::Duration;

use client::DragonflyClient;
use color_eyre::eyre::Result;
use tracing::{error, info, span, trace, Level};
use tracing_subscriber::EnvFilter;

use crate::{
    app_config::APP_CONFIG,
    client::{Job, ScanResult, SubmitJobResultsError},
    scanner::{scan_all_distributions, PackageScanResults},
};

fn scan_package(client: &DragonflyClient, job: Job) -> ScanResult {
    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
    let _enter = span.enter();

    match scan_all_distributions(client.get_http_client(), &client.rules_state.rules, &job) {
        Ok(results) => {
            let package_scan_results =
                PackageScanResults::new(job.name, job.version, results, job.hash);
            let body = package_scan_results.build_body();

            Ok(body)
        }
        Err(err) => Err(SubmitJobResultsError {
            name: job.name,
            version: job.version,
            reason: format!("{err}"),
        }),
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let default_env_filter = EnvFilter::builder()
        .parse("warn,dragonfly_client_rs=info")
        .unwrap();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(default_env_filter);

    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    let mut client = DragonflyClient::new()?;

    loop {
        info!("Fetching job");
        match client.get_job() {
            Ok(Some(job)) => {
                trace!("Successfully fetched job");

                info!("Starting scan of {} v{}", job.name, job.version);
                if job.hash != client.rules_state.hash {
                    info!(
                        "Must update rules, updating from {} to {}",
                        client.rules_state.hash, job.hash
                    );

                    if let Err(err) = client.update_rules() {
                        error!("Error while updating rules: {err}");
                    }
                }

                let scan_result = scan_package(&client, job);
                let http_result = client.send_result(scan_result);
                if let Err(err) = http_result {
                    error!("Error while sending response to API: {err}");
                }
            }

            Ok(None) => info!("No job found"),

            Err(err) => error!("Unexpected HTTP error: {err}"),
        }

        std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
    }
}
