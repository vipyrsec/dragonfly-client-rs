use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use color_eyre::eyre::{ensure, Result};
use dragonfly_client_rs::{
    app_config::APP_CONFIG,
    client::{Job, OpenGrepScanResult},
    opengrep::OpenGrepClient,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

fn run_job(client: &OpenGrepClient, job: &Job) {
    let started_at = Instant::now();
    let result = client.run_job(job);
    match &result {
        OpenGrepScanResult::Success(success) => info!(
            event = "opengrep_scan_completed",
            package = %job.name,
            version = %job.version,
            elapsed_ms = started_at.elapsed().as_millis(),
            finding_count = success.findings.len(),
            partial = success.partial_reason.is_some(),
            "Completed OpenGrep shadow scan"
        ),
        OpenGrepScanResult::Error(failure) => error!(
            event = "opengrep_scan_failed",
            package = %job.name,
            version = %job.version,
            elapsed_ms = started_at.elapsed().as_millis(),
            reason = %failure.reason,
            "OpenGrep shadow scan failed"
        ),
    }
    if let Err(error) = client.submit_result(&result) {
        error!(
            event = "opengrep_result_submission_failed",
            package = %job.name,
            version = %job.version,
            error = %error,
            "Failed to submit OpenGrep shadow result"
        );
    }
}

fn run_jobs(client: &OpenGrepClient, jobs: Vec<Job>) {
    if APP_CONFIG.threads == 1 {
        for job in jobs {
            run_job(client, &job);
        }
        return;
    }
    std::thread::scope(|scope| {
        for job in jobs {
            scope.spawn(move || run_job(client, &job));
        }
    });
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let default_env_filter = EnvFilter::builder()
        .parse("warn,opengrep_shadow=info,dragonfly_client_rs=info")
        .unwrap();
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(default_env_filter);
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    ensure!(
        APP_CONFIG.threads > 0,
        "DRAGONFLY_THREADS must be greater than zero"
    );
    ensure!(
        APP_CONFIG.bulk_size > 0,
        "DRAGONFLY_BULK_SIZE must be greater than zero"
    );
    let binary = std::env::var_os("OPENGREP_BIN")
        .map_or_else(|| PathBuf::from("/usr/local/bin/opengrep"), PathBuf::from);
    let mut client = OpenGrepClient::new(binary)?;
    let batch_size = APP_CONFIG.bulk_size.min(APP_CONFIG.threads);

    loop {
        match client.get_jobs(batch_size) {
            Ok(jobs) if jobs.is_empty() => {
                info!("No OpenGrep shadow jobs found");
                std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
            }
            Ok(jobs) => {
                if jobs.iter().any(|job| job.hash != client.rules_hash) {
                    if let Err(error) = client.refresh_rules() {
                        error!(error = %error, "Failed to refresh OpenGrep rules");
                        std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
                        continue;
                    }
                }
                let matching_jobs: Vec<Job> = jobs
                    .into_iter()
                    .filter(|job| {
                        let matches = job.hash == client.rules_hash;
                        if !matches {
                            warn!(
                                required_rules_commit = %job.hash,
                                loaded_rules_commit = %client.rules_hash,
                                "Deferring OpenGrep job with a mismatched rule commit"
                            );
                        }
                        matches
                    })
                    .collect();
                run_jobs(&client, matching_jobs);
            }
            Err(error) => {
                error!(error = %error, "Failed to fetch OpenGrep shadow jobs");
                std::thread::sleep(Duration::from_secs(APP_CONFIG.load_duration));
            }
        }
    }
}
