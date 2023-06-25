mod api;
mod api_models;
mod error;
mod scanner;
mod app_config;
mod utils;
mod common;

use std::{sync::Arc, thread, time::Duration};

use api::DragonflyClient;
use api_models::Job;
use common::{TarballType, ZipType};
use error::DragonflyError;
use reqwest::{StatusCode, blocking::Client, Url};
use scanner::{DistributionScanResults, scan_tarball, scan_zip};
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};
use yara::Rules;

use crate::{
    api::{ fetch_tarball, fetch_zipfile }, 
    utils::create_inspector_url, common::APP_CONFIG
};

enum Distribution {
    Tar {
        file: TarballType, 
        inspector_url: Url,
    },
    
    Zip {
        file: ZipType,
        inspector_url: Url,
    }
}

impl Distribution {
    /// Scan this distribution against the given rules
    fn scan(&self, rules: &Rules) -> Result<DistributionScanResults, DragonflyError> {
        match self {
            Self::Tar { file, inspector_url } => 
                scan_tarball(file, rules).map(|files| DistributionScanResults::new(files, inspector_url.to_owned())), 

            Self::Zip { file, inspector_url } => 
                scan_zip(file, rules).map(|files| DistributionScanResults::new(files, inspector_url.to_owned())),
        }
    }
}

/// Scan all the distributions of the given job against the given ruleset, returning the
/// results of each distribution. Uses the provided HTTP client to download each
/// distribution
fn scan_all_distributions<'a>(http_client: &Client, rules: &Rules, job: &'a Job) -> Result<Vec<DistributionScanResults>, DragonflyError> {
    let mut distribution_scan_results = Vec::new();
    for distribution in &job.distributions {

        let download_url: Url = distribution.parse().unwrap();
        let inspector_url = create_inspector_url(&job.name, &job.version, &download_url);

        let dist = if distribution.ends_with(".tar.gz") { 
            let file = fetch_tarball(http_client, &download_url)?;
            Distribution::Tar { file, inspector_url }
        } else {
            let file = fetch_zipfile(http_client, &download_url)?;
            Distribution::Zip { file, inspector_url }
        };
        
        let distribution_scan_result = dist.scan(rules)?;
        distribution_scan_results.push(distribution_scan_result);
    }

    Ok(distribution_scan_results)

}

fn runner(client: &DragonflyClient, job: &Job) -> Result<(), DragonflyError> {
    info!("Starting job {}@{}", job.name, job.version);

    let state = client.state.lock().unwrap();
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
        info!("Successfully sent results upstream");
    }


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
                        error!("Unexpected error: {err:#?}");
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
