mod api;
mod api_models;
mod error;
mod scanner;

use std::{path::Path, sync::Arc, thread, time::Duration};

use api::DragonflyClient;
use api_models::Job;
use config::Config;
use error::DragonflyError;
use reqwest::StatusCode;
use scanner::{scan_distribution, DistributionScanResults};
use serde::Deserialize;
use threadpool::ThreadPool;
use tracing::{error, info, span, warn, Level};

use crate::api_models::SubmitJobResultsBody;

fn create_inspector_url(name: &str, version: &str, download_url: &str, path: &Path) -> String {
    let mut url = reqwest::Url::parse(download_url).unwrap();
    let new_path = format!(
        "project/{}/{}/{}/{}",
        name,
        version,
        url.path().strip_prefix('/').unwrap(),
        path.display()
    );

    url.set_host(Some("inspector.pypi.io")).unwrap();
    url.set_path(&new_path);

    url.into()
}

fn do_job(client: &DragonflyClient, job: &Job) -> Result<(), DragonflyError> {
    let mut distribution_results: Vec<DistributionScanResults> = Vec::new();
    for download_url in &job.distributions {
        let result = scan_distribution(client, download_url)?;
        distribution_results.push(result);
    }

    let highest_score_distribution = distribution_results
        .iter()
        .max_by_key(|distrib| distrib.get_total_score())
        .unwrap();

    let inspector_url =
        if let Some(most_malicious_file) = &highest_score_distribution.get_most_malicious_file() {
            let url = create_inspector_url(
                &job.name,
                &job.version,
                highest_score_distribution.download_url(),
                &most_malicious_file.path,
            );

            Some(url)
        } else {
            None
        };

    let score = if inspector_url.is_some() {
        highest_score_distribution.get_total_score()
    } else {
        0
    };
    let inspector_url = inspector_url.as_deref();
    let rules_matched = &highest_score_distribution.get_all_rules();

    // We perform this validation here instead of upstream (i.e in runner) because
    // here, we only have to re-send the HTTP request with the same results
    // If we did it upstream (i.e in runner), we'd need to run the whole scanning process again
    if let Err(err) = client.submit_job_results(&job, score, inspector_url, rules_matched) {
        if let Some(StatusCode::UNAUTHORIZED) = err.status() {
            info!(
                "Got 401 UNAUTHORIZED while trying to send results upstream, revalidating creds..."
            );
            client.reauthorize()?;
            info!("Successfully reauthorized! Sending results again...");
            client.submit_job_results(&job, score, inspector_url, rules_matched)?;
            info!("Successfully sent results!");
        }
    }

    Ok(())
}

fn runner(client: &DragonflyClient, job: &Job) -> Result<(), DragonflyError> {
    info!("Starting job {}@{}", job.name, job.version);

    // Control when the MutexGuard is dropped
    {
        let mut state = client.state.lock().unwrap();
        if state.hash != job.hash {
            info!("Local hash: {}, remote hash: {}", state.hash, job.hash);
            info!("State is behind, syncing...");
            let (hash, rules) = client.fetch_rules()?;
            info!("Successfully synced state, we are now on hash {hash}");

            state.set_hash(hash);
            state.set_rules(rules);
        }
    }

    do_job(client, job)?;
    info!("Successfully sent results upstream");

    Ok(())
}

#[derive(Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub threads: usize,
    pub wait_duration: u64,
    pub auth0_domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub grant_type: String,
    pub username: String,
    pub password: String,
}

fn main() -> Result<(), DragonflyError> {
    let config: AppConfig = Config::builder()
        .add_source(config::File::with_name("Config.toml").required(false))
        .add_source(config::Environment::default())
        .set_default("base_url", "https://dragonfly.vipyrsec.com")?
        .set_default("threads", 1)?
        .set_default("auth0_domain", "vipyrsec.us.auth0.com")?
        .set_default("audience", "https://dragonfly.vipyrsec.com")?
        .set_default("grant_type", "password")?
        .set_default("wait_duration", 60u64)?
        .build()?
        .try_deserialize()?;

    tracing_subscriber::fmt().init();
    let client = Arc::new(DragonflyClient::new(config)?);

    let n_jobs = client.config.threads;
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
                    let s = client.config.wait_duration;
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
