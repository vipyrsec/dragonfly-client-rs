mod app_config;
mod client;
mod error;
mod exts;
mod scanner;
mod utils;

use std::{
    sync::{
        mpsc::{self, SyncSender},
        Arc,
    },
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
    client::{Job, SubmitJobResultsBody, SubmitJobResultsError},
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
fn runner(client: &DragonflyClient, job: Job, tx: &SyncSender<SubmitJobResultsBody>) {
    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
    let _enter = span.enter();
    let rules_state = client.rules_state.read();
    let send_result = match scanner(
        client.get_http_client(),
        &job,
        &rules_state.rules,
        &rules_state.hash,
    ) {
        Ok(package_scan_results) => tx.send(SubmitJobResultsBody::Success(
            package_scan_results.build_body(),
        )),
        Err(err) => tx.send(SubmitJobResultsBody::Error(SubmitJobResultsError {
            name: job.name,
            version: job.version,
            reason: format!("{err:#?}"),
        })),
    };

    if send_result.is_err() {
        error!("No more receivers listening across channel!");
    }
}

fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let client = Arc::new(DragonflyClient::new()?);
    let (tx, rx) = mpsc::sync_channel(1024);

    // We spawn `n_jobs` threads using a threadpool for processing jobs, +1 more thread to send the
    // results. The main thread will handle requesting the jobs and submitting them to the threadpool.
    let n_jobs = APP_CONFIG.threads;
    let pool = ThreadPool::new(n_jobs);
    debug!("Started threadpool with {} workers", n_jobs);

    // Spawning the authentication thread
    std::thread::spawn({
        let client = Arc::clone(&client);
        trace!("Starting access token refresh thread");
        move || loop {
            trace!(
                "Waiting for read lock on authentication state to determine how long to sleep for"
            );
            let expires_in = client.authentication_state.read().expires_in - 10;
            trace!("Got read lock on authentication state");
            info!("Will reauthenticate in {expires_in} seconds");
            std::thread::sleep(Duration::from_secs(u64::from(expires_in)));

            info!("Reauthenticating");
            client.reauthenticate();
        }
    });

    // Spawning the "sender" thread
    std::thread::spawn({
        let client = Arc::clone(&client);
        trace!("Starting loader thread");
        move || loop {
            match rx.recv() {
                Ok(SubmitJobResultsBody::Success(success_body)) => {
                    let span = span!(
                        Level::INFO,
                        "Job",
                        name = success_body.name,
                        version = success_body.version
                    );
                    let _enter = span.enter();

                    trace!("Received success body, sending upstream...");
                    trace!("Success body: {success_body:#?}");
                    if let Err(err) = client.send_success(&success_body) {
                        error!("Unexpected error while sending success: {err}");
                    } else {
                        info!("Successfully sent success!");
                    }
                }

                Ok(SubmitJobResultsBody::Error(error_body)) => {
                    let span = span!(
                        Level::INFO,
                        "Job",
                        name = error_body.name,
                        version = error_body.version
                    );
                    let _enter = span.enter();

                    trace!("Received error body, sending upstream...");
                    trace!("Error body: {error_body}");
                    if let Err(err) = client.send_error(&error_body) {
                        error!("Unexpected error while sending error: {err}");
                    } else {
                        info!("Successfully sent error!");
                    }
                }

                Err(_) => error!("No more transmitters!"),
            }
        }
    });

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
                    let rules_state = client.rules_state.read();
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
                        let tx = tx.clone();
                        move || runner(&client, job, &tx)
                    });
                }

                trace!("Finished loading jobs into queue!");
            }

            Err(err) => error!("Unexpected HTTP error: {err}"),
        }

        std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
    }
}
