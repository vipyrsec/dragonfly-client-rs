mod api;
mod api_models;
mod app_config;
mod common;
mod error;
mod scanner;
mod utils;

use std::{sync::Arc, thread, time::Duration};

use api::DragonflyClient;
use api_models::Job;
use error::DragonflyError;
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};

use crate::{common::APP_CONFIG, scanner::scan_all_distributions};

fn runner(client: &DragonflyClient, job: &Job) -> Result<(), DragonflyError> {
    info!("Starting job {}@{}", job.name, job.version);

 
    let state = client.state.read().unwrap();
    if state.hash != job.hash {
        info!(
            "Rules are outdated: attempting to update from {} to {}.",
            state.hash, job.hash
        );
        drop(state);

        client.update_rules()?;
        info!("Successfully synced state!");
    } else {
        drop(state);
    }

    // Acquire a ReadGuard for scanning and sending results
    let state = client.state.read().unwrap();

    let distribution_scan_results =
        scan_all_distributions(client.get_http_client(), &state.rules, job)?;

    info!("Sending success HTTP response");
    client.send_success(job, &distribution_scan_results)?;

    info!("Successfully sent results upstream");

    Ok(())
}

fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt().init();
    let client = Arc::new(DragonflyClient::new()?);

    let n_jobs = APP_CONFIG.threads;
    let pool = ThreadPool::new(n_jobs);
    info!("Started threadpool with {} workers", n_jobs);

    for _ in 0..n_jobs {
        let client = Arc::clone(&client);
        pool.execute(move || loop {
            match client.get_job() {
                Ok(Some(job)) => {
                    // Set up logging
                    let span = span!(Level::INFO, "Job", name = job.name, version = job.version);
                    let _enter = span.enter();

                    if let Err(err) = runner(&client, &job) {
                        let errstr = format!("{err:#?}");
                        error!("Unexpected error: {errstr}");
                        client.send_error(&job, &errstr).unwrap();
                    }
                }

                Ok(None) => {
                    let s = APP_CONFIG.wait_duration;
                    info!("No job found! Trying again in {s} seconds...");
                    thread::sleep(Duration::from_secs(s));
                }

                Err(err) => error!("Unexpected error while fetching a job: {err:#?}"),
            }
        });
    }

    pool.join();

    Ok(())
}
