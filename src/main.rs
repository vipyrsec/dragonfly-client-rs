mod api;
mod error;
mod scanner;

use std::{path::Path, thread, time::Duration, sync::{Arc, Mutex}, ops::DerefMut};

use api::{DragonflyClient, Job};
use error::DragonflyError;
use scanner::{scan_distribution, DistributionScanResults};

use crate::api::SubmitJobResultsBody;

const WAIT_DURATION: u64 = 60;

fn create_inspector_url(name: &String, version: &String, download_url: &String, path: &Path) -> String {
    let mut url = reqwest::Url::parse(download_url).unwrap();
    let new_path = format!(
        "project/{}/{}/{}/{}", 
        name, 
        version, 
        url.path().strip_prefix("/").unwrap(), 
        path.display()
    );

    url.set_host(Some("inspector.pypi.io")).unwrap();
    url.set_path(&new_path);

    url.into()
}

fn do_job(client: &DragonflyClient, job: Job) -> Result<(), DragonflyError> {
        let mut distribution_results: Vec<DistributionScanResults> = Vec::new();

        for download_url in job.distributions {
            match scan_distribution(&client, &download_url) {
                Ok(result) => distribution_results.push(result),
                Err(DragonflyError::DownloadTooLarge(_)) => println!("Distribution {} is too large, skipping...", download_url),
                Err(err) => println!("Error while scanning distribution {}: {:#?}, skipping...", download_url, err),
            }
        }
        
        let highest_score_distribution = distribution_results.iter().max_by_key(|distrib| distrib.get_total_score()).unwrap();

        let inspector_url = if let Some(most_malicious_file) = &highest_score_distribution.get_most_malicious_file() {
            let url = create_inspector_url(
                &job.name, 
                &job.version, 
                highest_score_distribution.download_url(), 
                &most_malicious_file.path);

            Some(url)

        } else {
            None
        };
        
        println!("Finished job {}@{}! Submitting results...", job.name, job.version);
        println!("{}", "-".repeat(10));
        client.submit_job_results(SubmitJobResultsBody{ 
            name: &job.name,
            version: &job.version,
            score: if inspector_url.is_some() { Some(highest_score_distribution.get_total_score()) } else { None },
            inspector_url: inspector_url.as_ref(),
            rules_matched: &highest_score_distribution.get_all_rules(),

        })?;

        Ok(())
}

fn main() -> Result<(), DragonflyError> {
    let client = Arc::new(Mutex::new(DragonflyClient::new()?));
    
    let mut handles = Vec::new();

    for _ in 0..5 {
        let client = Arc::clone(&client);
        let handle = thread::spawn(move || {
            loop {
                let mut lock = client.lock().unwrap();
                let job_response = lock.get_job();
                match job_response {
                    Ok(response) => match response {
                        Some(job) => { 
                            println!("Found job! Scanning {}@{}", job.name, job.version);
                            if lock.state.hash != job.hash {
                                if let Err(err) = lock.sync_rules() {
                                    println!("Failed to sync rules: {:#?}", err);
                                }
                            }

                            if let Err(err) = do_job(&lock, job) {
                                println!("Unexpected error occured: {:#?}", err)
                            }

                        },
                        None => {
                            println!("No job found! Trying again in {WAIT_DURATION} seconds...");
                            thread::sleep(Duration::from_secs(WAIT_DURATION));
                        }
                    }
                    Err(err) => println!("Unexpected HTTP error: {:#?}", err),
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
