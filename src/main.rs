mod api;
mod api_models;
mod app_config;
mod common;
mod error;
mod scanner;
mod utils;
mod exts;

use std::{
    collections::VecDeque,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use api::DragonflyClient;
use api_models::Job;
use error::DragonflyError;
use reqwest::blocking::Client;
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};
use yara::Rules;

use crate::{
    api_models::{SubmitJobResultsBody, SubmitJobResultsError},
    common::APP_CONFIG,
    scanner::{scan_all_distributions, PackageScanResults},
};

/// The actual scanning logic. Takes the job to be scanned, the compiled rules, the commit hash
/// being used, and the HTTP client (for downloading distributions), and returns the `PackageScanResults`
fn runner(
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

fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt().init();
    let client = Arc::new(DragonflyClient::new()?);
    let (tx, rx) = mpsc::sync_channel(1024);
    let queue: Arc<Mutex<VecDeque<Job>>> = Arc::new(Mutex::new(VecDeque::new()));

    let n_jobs = APP_CONFIG.threads;
    let pool = ThreadPool::new(n_jobs);
    info!("Started threadpool with {} workers", n_jobs);

    // This thread periodically loads jobs into the queue
    std::thread::spawn({
        let client = Arc::clone(&client);
        let queue = Arc::clone(&queue);
        info!("Starting loader thread");
        move || loop {
            info!("Fetching {} bulk jobs...", APP_CONFIG.bulk_size);
            match client.bulk_get_job(APP_CONFIG.bulk_size) {
                Ok(jobs) => {
                    info!("Waiting for mutex lock on queue to push jobs");
                    let mut queue = queue.lock().unwrap();

                    if jobs.is_empty() {
                        info!("Bulk job request returned no jobs");
                    }

                    for job in jobs {
                        info!("Pushing {} v{} onto queue", job.name, job.version);
                        if job.hash != client.state.read().unwrap().hash {
                            info!("Detected job hash mismatch, attempting to sync rules");
                            if let Err(err) = client.update_rules() {
                                error!("Error while updating rules: {err}");
                            }
                        }
                        queue.push_back(job);
                    }

                    info!("Finished loading jobs into queue!");
                }

                Err(err) => error!("Unexpected HTTP error: {err}")
            }

            std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
        }
    });

    // These threads do the actual scanning and send results over a channel
    for _ in 0..n_jobs {
        let client = Arc::clone(&client);
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        pool.execute(move || loop {
            let state = client.state.read().unwrap();

            info!("Attempting to get lock on queue");
            match queue.lock().map(|mut q| q.pop_front()) {
                Ok(Some(job)) => {
                    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
                    let _enter = span.enter();
                    info!("Successfuly got job from queue!");
                    let send_result =
                        match runner(client.get_http_client(), &job, &state.rules, &state.hash) {
                            Ok(package_scan_results) => tx.send(SubmitJobResultsBody::Success(
                                package_scan_results.build_body(),
                            )),
                            Err(err) => {
                                tx.send(SubmitJobResultsBody::Error(SubmitJobResultsError {
                                    name: job.name,
                                    version: job.version,
                                    reason: format!("{err:#?}"),
                                }))
                            }
                        };

                    if send_result.is_err() {
                        error!("No more receivers listening across channel!");
                    }
                }
                Ok(None) => {
                    let s = APP_CONFIG.wait_duration;
                    let d = Duration::from_secs(s);
                    info!("No jobs in queue! Trying again in {s} seconds...");
                    std::thread::sleep(d);
                }
                Err(_) => error!("Queue lock is poisoned!"),
            }
        })
    }

    // This loop continuously recieves results from the mpsc channel and sends it upstream
    loop {
        let client = Arc::clone(&client);
        match rx.recv() {
            Ok(SubmitJobResultsBody::Success(success_body)) => {
                let span = span!(
                    Level::INFO,
                    "Job",
                    name = success_body.name,
                    version = success_body.version
                );
                let _enter = span.enter();

                info!("Received success body, sending upstream...");
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

                info!("Received error body, sending upstream...");
                if let Err(err) = client.send_error(&error_body) {
                    error!("Unexpected error while sending error: {err}");
                } else {
                    info!("Successfully sent error!");
                }
            }

            Err(_) => error!("No more transmitters!"),
        }
    }
}
