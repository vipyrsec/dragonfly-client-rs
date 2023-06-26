mod api;
mod api_models;
mod error;
pub mod scanner;
mod app_config;
mod utils;
mod common;

use std::{sync::Arc, thread, time::Duration};

use api::DragonflyClient;
use api_models::Job;
use error::DragonflyError;
use reqwest::StatusCode;
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};

use crate::{common::APP_CONFIG, scanner::scan_all_distributions};

fn runner(client: &DragonflyClient, job: &Job) -> Result<(), DragonflyError> {
    info!("Starting job {}@{}", job.name, job.version);

    let state = client.state.read().unwrap();
    if state.hash != job.hash {
        info!("Local hash: {}, remote hash: {}", state.hash, job.hash);
        info!("State is behind, syncing...");
        client.reauthorize()?;
        info!("Successfully synced state!");
    }
    
    let distribution_scan_results = scan_all_distributions(client.get_http_client(), &state.rules, job)?;
    if let Err(Some(StatusCode::UNAUTHORIZED)) =  client.submit_job_results(job, &distribution_scan_results).map_err(|err| err.status()) {
        info!("Got 401 unauthorized while submitting job, reauthorizing and trying again") ;
        client.reauthorize()?;
        info!("Successfully reauthorized! Sending results again...");
        client.submit_job_results(&job, &distribution_scan_results)?;
    }

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
                    let span =
                        span!(Level::INFO, "Job", name = job.name, version = job.version);
                    let _enter = span.enter();

                    if let Err(err) = runner(&client, &job) {
                        let errstr = format!("{err:#?}");
                        error!("Unexpected error: {errstr}");
                        client.send_error(&job, &errstr).unwrap();
                    }
                },

                Ok(None) => {
                    let s = APP_CONFIG.wait_duration;
                    info!("No job found! Trying again in {s} seconds...");
                    thread::sleep(Duration::from_secs(s));
                },

                Err(http_error) if http_error.status() == Some(StatusCode::UNAUTHORIZED) => {
                    info!("Got 401 UNAUTHORIZED while fetching rules, revalidating credentials and trying again...");
                    if let Err(reauth_error) = client.reauthorize() {
                        error!("Failed reauthorizing credentials! {reauth_error:#?}");
                        continue;
                    }

                    info!("Successfully reauthorized, will use new credentials next time around");
                },

                Err(err) => error!("Unexpected error while fetching rules: {err:#?}")
            }
        });
    }

    pool.join();

    Ok(())
}
