//! whoknocked entry point.
//!
//! Orchestration only: resolve the log file, load and filter events, run the
//! detection engine, and print the report. All real work lives in the modules
//! below so each piece stays small and testable.

mod attackers;
mod cli;
mod config;
mod detections;
mod enrich;
mod event;
mod finding;
mod follow;
mod loader;
mod os_detect;
mod parser;
mod report;
mod source;
mod summary;

use anyhow::{Context, Result};
use chrono::Local;
use cli::Args;
use config::DetectorConfig;
use source::LogSource;
use std::collections::HashMap;
use std::process::ExitCode;

fn main() -> ExitCode {
    init_logging();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // One clear line to stderr, with the full context chain.
            eprintln!("whoknocked: {error:#}");
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
    let color = report::use_color(args.color);

    let log_source = LogSource::resolve(&args)?;
    let source_label = log_source.label();
    let now = Local::now().naive_local();

    let reader = log_source.open()?;
    let outcome = loader::load_events(reader, &source_label, now)
        .with_context(|| format!("failed to analyze {source_label}"))?;

    if outcome.parse_errors > 0 {
        log::warn!("{} line(s) could not be parsed", outcome.parse_errors);
    }

    let events = loader::filter_events(outcome.events, &args, now)?;

    if events.is_empty() && !args.follow {
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

    let mut sources = attackers::top_sources(&events, args.top);

    // Enrichment: one lookup per distinct IP across the table and findings.
    let info: HashMap<_, _> = if args.enrich {
        let ips = sources
            .iter()
            .map(|s| s.ip)
            .chain(findings.iter().filter_map(|f| f.source_ip));
        enrich::lookup_many(ips)
    } else {
        HashMap::new()
    };
    for source in &mut sources {
        source.info = info.get(&source.ip).cloned();
    }

    let data = report::ReportData {
        source_label: &source_label,
        summary: &event_summary,
        findings: &findings,
        sources: &sources,
        info: &info,
        summary_only: args.summary_only,
    };

    if args.json {
        println!("{}", report::build_json(&data));
    } else {
        report::print_report(&data, color);
    }

    if args.follow {
        let mut follower = follow::Follower::new(&args, detector_config, events, &findings, color);
        follower.run(&log_source)?;
    }
    Ok(())
}
