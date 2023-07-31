mod app_config;
mod client;
mod error;
mod exts;
mod scanner;
mod utils;

use std::{
    sync::Arc,
    time::Duration,
};

use client::DragonflyClient;
use error::DragonflyError;
use reqwest::blocking::Client;
use threadpool::ThreadPool;
use tracing::{debug, error, info, span, trace, Level};
use tracing_subscriber::EnvFilter;
use yara::Rules;

use crate::{
    app_config::APP_CONFIG,
    client::{Job, SubmitJobResultsError},
    scanner::{scan_all_distributions, PackageScanResults},
};

/// The actual scanning logic.
///
/// Takes the job to be scanned, the compiled rules, the commit hash being used, and the HTTP
/// client (for downloading distributions), and returns the `PackageScanResults`.
fn scanner(
    http_client: &Client,
    job: &Job,
    rules: &Rules,
    commit_hash: &str,
) -> Result<PackageScanResults, DragonflyError> {
    let distribution_scan_results = scan_all_distributions(http_client, rules, job)?;

    let package_scan_result = PackageScanResults::new(
        job.name.to_string(),
        job.version.to_string(),
        distribution_scan_results,
        commit_hash.to_string(),
    );

    Ok(package_scan_result)
}

/// The job to run in the threadpool.
fn runner(client: &DragonflyClient, job: Job) {
    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
    let _enter = span.enter();
    let rules_state = client.rules_state.read().unwrap();

    let send_result = match scanner(client.get_http_client(), &job, &rules_state.rules, &rules_state.hash) {
        Ok(package_scan_results) => {
            let body = package_scan_results.build_body();

            client.send_success(&body)
        }

        Err(err) => {
            let body = SubmitJobResultsError {
                name: job.name,
                version: job.version,
                reason: format!("{err}")
            };

            client.send_error(&body)
        }
    };

    if let Err(err) = send_result {
        error!("Error while sending response to API: {err}");
    }
}

fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let client = Arc::new(DragonflyClient::new()?);

    // We spawn `n_jobs` threads using a threadpool for processing jobs, +1 more thread to send the
    // results. The main thread will handle requesting the jobs and submitting them to the threadpool.
    let n_jobs = APP_CONFIG.threads;
    let pool = ThreadPool::new(n_jobs);
    debug!("Started threadpool with {} workers", n_jobs);

    loop {
        info!("Fetching {} bulk jobs...", APP_CONFIG.bulk_size);
        match client.bulk_get_job(APP_CONFIG.bulk_size) {
            Ok(jobs) => {
                if jobs.is_empty() {
                    debug!("Bulk job request returned no jobs");
                }

                info!("Successfully fetched {} jobs", jobs.len());

                for job in jobs {
                    info!("Submitting {} v{} for execution", job.name, job.version);
                    let rules_state = client.rules_state.read().unwrap();
                    if job.hash != rules_state.hash {
                        info!(
                            "Must update rules, updating from {} to {}",
                            rules_state.hash, job.hash
                        );
                        drop(rules_state);
                        if let Err(err) = client.update_rules() {
                            error!("Error while updating rules: {err}");
                        }
                    }

                    pool.execute({
                        let client = Arc::clone(&client);
                        move || runner(&client, job)
                    });
                }

                trace!("Finished loading jobs into queue!");
            }

            Err(err) => error!("Unexpected HTTP error: {err}"),
        }

        std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
    }
}
