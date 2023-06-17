mod api;
mod error;
mod scanner;

use std::{path::Path, sync::Arc, thread, time::Duration};

use api::{DragonflyClient, Job};
use error::DragonflyError;
use scanner::{scan_distribution, DistributionScanResults};
use threadpool::ThreadPool;
use tracing::{error, info, span, Level};

use crate::api::SubmitJobResultsBody;

const WAIT_DURATION: u64 = 60;

fn create_inspector_url(
    name: &String,
    version: &String,
    download_url: &str,
    path: &Path,
) -> String {
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
            Some(highest_score_distribution.get_total_score())
        } else {
            None
        },
        inspector_url: inspector_url.as_ref(),
        rules_matched: &highest_score_distribution.get_all_rules(),
    })?;
    info!("Successfully sent results for job");

    Ok(())
}

fn main() -> Result<(), DragonflyError> {
    tracing_subscriber::fmt().init();
    let client = Arc::new(DragonflyClient::new()?);

    let n_jobs = 5;
    let pool = ThreadPool::new(n_jobs);
    info!("Started threadpool with {} workers", n_jobs);

    for _ in 0..n_jobs {
        let client = Arc::clone(&client);
        pool.execute(move || loop {
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
                                if let Err(err) = state.sync(client.get_http_client()) {
                                    error!("Failed to sync rules: {:#?}", err);
                                }
                            }
                        }

                        if let Err(err) = do_job(&client, job) {
                            error!("Unexpected error occured: {:#?}", err);
                        } else {
                            info!("No job found! Trying again in {} seconds...", WAIT_DURATION);
                            thread::sleep(Duration::from_secs(WAIT_DURATION));
                        }
                    }
                }
                Err(err) => println!("Unexpected HTTP error: {:#?}", err),
            }
        });
    }

    pool.join();

    Ok(())
}
