mod api;
mod api_models;
mod error;
mod scanner;

use std::{path::Path, sync::Arc, thread, time::Duration};

use api::DragonflyClient;
use api_models::Job;
use chrono::Local;
use config::Config;
use error::DragonflyError;
use scanner::{scan_distribution, DistributionScanResults};
use serde::Deserialize;
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};

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

fn do_job(client: &DragonflyClient, job: Job) -> Result<(), DragonflyError> {
    let mut distribution_results: Vec<DistributionScanResults> = Vec::new();

    for download_url in job.distributions {
        info!("Scanning distribution {}...", download_url);
        let result = scan_distribution(client, &download_url)?;
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

    info!("Finished scanning job! Sending results...");
    client.submit_job_results(&SubmitJobResultsBody {
        name: &job.name,
        version: &job.version,
        score: if inspector_url.is_some() {
            highest_score_distribution.get_total_score()
        } else {
            0
        },
        inspector_url: inspector_url.as_deref(),
        rules_matched: &highest_score_distribution.get_all_rules(),
    })?;
    info!("Successfully sent results for job");

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
        .add_source(config::File::with_name("Config.toml"))
        .add_source(config::Environment::with_prefix("DRAGONFLY_"))
        .set_default("base_url", "https://dragonfly.vipyrsec.com")?
        .set_default("threads", 1)?
        .set_default("auth0_domain", "vipyrsec-dev.us.auth0.com")?
        .set_default("audience", "https://dragonfly.vipyrsec.local")?
        .set_default("grant_type", "password")?
        .set_default("wait_duration", 60u64)?
        .build()?
        .try_deserialize()?;

    tracing_subscriber::fmt().init();
    let client = Arc::new(DragonflyClient::new(config)?);
    
    let n_jobs = usize::from(client.config.threads);
    let pool = ThreadPool::new(client.config.threads);
    info!("Started threadpool with {} workers", n_jobs);

    for _ in 0..n_jobs {
        let client = Arc::clone(&client);
        pool.execute(move || loop {
            let state = { client.state.lock().unwrap() };
            if Local::now() > state.authentication_information.expires_at {
                if let Err(err) = client.reauthorize() {
                    error!("Error while trying to reauthorize: {err:#?}");
                    continue;
                }
            }

            match client.get_job() {
                Ok(response) => {
                    if let Some(job) = response {
                        let span =
                            span!(Level::INFO, "Job", name = job.name, version = job.version);
                        let _enter = span.enter();

                        info!("Start job {}@{}", job.name, job.version);
                        {
                            let mut state = client.state.lock().unwrap();
                            if state.hash != job.hash {
                                info!("Local hash: {}, remote hash: {}", state.hash, job.hash);
                                info!("State is behind, syncing...");
                                match client.fetch_rules() {
                                    Ok((hash, rules)) => {
                                        state.set_hash(hash);
                                        state.set_rules(rules);
                                    }
                                    Err(err) => error!("Failed to sync rules: {:#?}", err),
                                }
                            }
                        }

                        if let Err(err) = do_job(&client, job) {
                            error!("Unexpected error occured: {:#?}", err);
                        }
                    } else {
                        info!(
                            "No job found! Trying again in {} seconds...",
                            client.config.wait_duration
                        );
                        thread::sleep(Duration::from_secs(client.config.wait_duration));
                    }
                }
                Err(err) => error!("Unexpected HTTP error: {err:#?}"),
            }
        });
    }

    pool.join();

    Ok(())
}
