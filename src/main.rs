mod app_config;
mod client;
mod exts;
mod scanner;
mod utils;

use std::time::Duration;

use client::DragonflyClient;
use color_eyre::eyre::{ensure, Result};
use tracing::{error, info, span, trace, warn, Level};
use tracing_subscriber::EnvFilter;

use crate::{
    app_config::APP_CONFIG,
    client::{Job, ScanResult, SubmitJobResultsError},
    scanner::{scan_all_distributions, PackageScanResults},
};

fn scan_package(client: &DragonflyClient, job: Job) -> Option<ScanResult> {
    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
    let _enter = span.enter();

    if job.hash != client.rules_state.hash {
        warn!(
            "Deferring job requiring rules commit {}; scanner loaded {}",
            job.hash, client.rules_state.hash
        );
        // Do not submit a failure: mainframe will requeue the pending job after its timeout.
        return None;
    }

    let result =
        match scan_all_distributions(client.download_client(), &client.rules_state.rules, &job) {
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
        };
    Some(result)
}

fn run_job(client: &DragonflyClient, job: Job) {
    let Some(scan_result) = scan_package(client, job) else {
        return;
    };
    if let Err(err) = client.send_result(scan_result) {
        error!("Error while sending response to API: {err}");
    }
}

fn run_jobs(client: &DragonflyClient, jobs: Vec<Job>, worker_count: usize) {
    if worker_count == 1 {
        for job in jobs {
            run_job(client, job);
        }
        return;
    }

    std::thread::scope(|scope| {
        for job in jobs {
            scope.spawn(move || run_job(client, job));
        }
    });
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let default_env_filter = EnvFilter::builder()
        .parse("warn,dragonfly_client_rs=info")
        .unwrap();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(default_env_filter);

    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    let mut client = DragonflyClient::new()?;
    ensure!(
        APP_CONFIG.threads > 0,
        "DRAGONFLY_THREADS must be greater than zero"
    );
    ensure!(
        APP_CONFIG.bulk_size > 0,
        "DRAGONFLY_BULK_SIZE must be greater than zero"
    );
    let batch_size = APP_CONFIG.bulk_size.min(APP_CONFIG.threads);

    loop {
        info!("Fetching up to {batch_size} jobs");
        match client.bulk_get_job(batch_size) {
            Ok(jobs) if jobs.is_empty() => {
                info!("No jobs found");
                std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
            }
            Ok(jobs) => {
                trace!("Successfully fetched {} jobs", jobs.len());

                if jobs.iter().any(|job| job.hash != client.rules_state.hash) {
                    info!(
                        "At least one job requires rules other than {}, updating rules",
                        client.rules_state.hash
                    );

                    if let Err(err) = client.update_rules() {
                        error!("Error while updating rules: {err}");
                    }
                }

                run_jobs(&client, jobs, APP_CONFIG.threads);
            }

            Err(err) => {
                error!("Unexpected HTTP error: {err}");
                std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
            }
        }
    }
}
