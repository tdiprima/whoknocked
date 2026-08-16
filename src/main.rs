//! LogHound entry point.
//!
//! Orchestration only: resolve the log file, load and filter events, run the
//! detection engine, and print the report. All real work lives in the modules
//! below so each piece stays small and testable.

mod cli;
mod config;
mod detections;
mod event;
mod finding;
mod loader;
mod os_detect;
mod parser;
mod report;
mod summary;

use anyhow::{Context, Result};
use chrono::Local;
use cli::Args;
use config::DetectorConfig;
use std::path::PathBuf;
use std::process::ExitCode;

/// Environment variable that overrides the auto-detected log file path.
const LOG_FILE_ENV: &str = "LOGHOUND_FILE";

fn main() -> ExitCode {
    init_logging();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // One clear line to stderr, with the full context chain.
            eprintln!("loghound: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Configure logging from the `RUST_LOG` environment variable, defaulting to
/// warnings and above so normal runs stay quiet.
fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
}

/// The real program flow, returning errors for `main` to render.
fn run() -> Result<()> {
    let args = Args::parse_args();
    let detector_config = DetectorConfig::resolve(&args)?;

    let log_path = resolve_log_path(&args)?;
    let now = Local::now().naive_local();

    let outcome = loader::load_events(&log_path, now)
        .with_context(|| format!("failed to analyze {}", log_path.display()))?;

    if outcome.parse_errors > 0 {
        log::warn!("{} line(s) could not be parsed", outcome.parse_errors);
    }

    let events = loader::filter_events(outcome.events, &args, now)?;
    let source_label = log_path.display().to_string();

    if events.is_empty() {
        println!("No matching authentication events found in {source_label}.");
        return Ok(());
    }

    let event_summary = summary::Summary::from_events(&events);

    let findings = if args.summary_only {
        Vec::new()
    } else {
        let detectors = detections::all_detectors(detector_config);
        let mut produced = detections::run_all(&detectors, &events);
        report::sort_findings(&mut produced);
        produced
    };

    report::print_report(&source_label, &event_summary, &findings, args.summary_only);
    Ok(())
}

/// Decide which log file to read.
///
/// Precedence: explicit `--file`, then the `LOGHOUND_FILE` environment
/// variable, then auto-detection based on the Linux distribution.
fn resolve_log_path(args: &Args) -> Result<PathBuf> {
    if let Some(path) = &args.file {
        return Ok(path.clone());
    }

    if let Ok(from_env) = std::env::var(LOG_FILE_ENV) {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    os_detect::default_log_path()
        .context("could not determine the log file automatically; pass --file")
}
