mod api;
mod api_models;
mod app_config;
mod common;
mod error;
mod scanner;
mod utils;

use std::{
    collections::VecDeque,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use api::DragonflyClient;
use api_models::Job;
use error::DragonflyError;
use reqwest::{blocking::Client, StatusCode};
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
    let distribution_scan_results = scan_all_distributions(http_client, rules, commit_hash, job)?;

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
            info!("Fetching bulk jobs...");
            for job in client.bulk_get_job(n_jobs) {
                info!("Pushing {} v{} onto scan queue", job.name, job.version);
                let mut queue = queue.lock().unwrap();
                queue.push_back(job);
            }
            info!("Finished loading jobs into queue!");
            std::thread::sleep(Duration::from_secs(APP_CONFIG.wait_duration));
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
                match client.send_success(&success_body) {
                    Err(DragonflyError::HTTPError { source: http_err })
                        if http_err.status() == Some(StatusCode::UNAUTHORIZED) =>
                    {
                        info!("Got 401 UNAUTHORIZED while sending success");
                        info!("Waiting on write lock to update access token");
                        let mut state = client.state.write().unwrap();
                        info!("Successfully obtained write lock!");
                        info!("Requesting new access token...");
                        let new_access_token = client.reauthenticate();
                        info!("Successfuly got new access token!");
                        state.access_token = new_access_token;
                        info!("Successfully updated local access token to new one!");
                        info!("Sending success body again...");
                        client.send_success(&success_body)?;
                        info!("Successfully sent success body again!");
                    }

                    Ok(()) => info!("Successfully sent success"),

                    Err(err) => error!("Unexpected error while sending success: {err}"),
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
                match client.send_error(&error_body) {
                    Err(DragonflyError::HTTPError { source: http_err })
                        if http_err.status() == Some(StatusCode::UNAUTHORIZED) =>
                    {
                        info!("Got 401 UNAUTHORIZED while sending success");
                        info!("Waiting on write lock to update access token");
                        let mut state = client.state.write().unwrap();
                        info!("Successfully obtained write lock!");
                        info!("Requesting new access token...");
                        let new_access_token = client.reauthenticate();
                        info!("Successfuly got new access token!");
                        state.access_token = new_access_token;
                        info!("Successfully updated local access token to new one!");
                        info!("Sending success body again...");
                        client.send_error(&error_body)?;
                        info!("Successfully sent success body again!");
                    }

                    Ok(()) => info!("Successfully sent error"),

                    Err(err) => error!("Unexpected error while sending error: {err}"),
                }
            }

            Err(_) => error!("No more transmitters!"),
        }
    }
}
