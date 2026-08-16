//! Read a log file from disk and turn it into filtered [`AuthEvent`]s.
//!
//! This is the one module that touches the filesystem for log data. Parsing
//! and filtering are kept as pure helpers so they can be tested without any
//! I/O or elevated privileges.

use crate::cli::Args;
use crate::event::AuthEvent;
use crate::parser;
use anyhow::{Context, Result};
use chrono::{Datelike, Duration, NaiveDateTime};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Small clock skew tolerance when deciding a timestamp is "in the future".
const FUTURE_SKEW: Duration = Duration::hours(25);

/// The result of loading a log file: the events plus counts of what was
/// ignored, so the caller can surface parsing health instead of hiding it.
pub struct LoadOutcome {
    pub events: Vec<AuthEvent>,
    pub non_event_lines: usize,
    pub parse_errors: usize,
}

/// Read and parse every line of `path` into auth events.
///
/// `now` anchors the assumed year for syslog's yearless timestamps, and is
/// taken as a parameter (not read from the clock here) so the logic stays
/// pure and testable.
pub fn load_events(path: &Path, now: NaiveDateTime) -> Result<LoadOutcome> {
    validate_readable(path)?;

    let file = File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let reader = BufReader::new(file);

    let assumed_year = now.year();
    let mut outcome = LoadOutcome {
        events: Vec::new(),
        non_event_lines: 0,
        parse_errors: 0,
    };

    for (line_number, line_result) in reader.lines().enumerate() {
        let line = line_result
            .with_context(|| format!("error reading {} at line {}", path.display(), line_number + 1))?;

        match parser::parse_line(&line, assumed_year) {
            Ok(Some(mut event)) => {
                event.timestamp = correct_year(event.timestamp, now);
                outcome.events.push(event);
            }
            Ok(None) => outcome.non_event_lines += 1,
            Err(error) => {
                outcome.parse_errors += 1;
                log::warn!("skipping line {}: {error}", line_number + 1);
            }
        }
    }

    log::info!(
        "parsed {} events ({} non-event lines, {} parse errors)",
        outcome.events.len(),
        outcome.non_event_lines,
        outcome.parse_errors
    );
    Ok(outcome)
}

/// Verify the path exists and is a regular file before opening it.
fn validate_readable(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "cannot access {} (does it exist, and do you have permission? \
             reading auth logs usually needs sudo or the adm group)",
            path.display()
        )
    })?;

    if !metadata.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    Ok(())
}

/// Correct a yearless syslog timestamp that lands in the future.
///
/// Logs written in December but read in January would otherwise be stamped
/// with the new year. If a timestamp is meaningfully ahead of `now`, assume
/// it belongs to the previous year.
fn correct_year(timestamp: NaiveDateTime, now: NaiveDateTime) -> NaiveDateTime {
    if timestamp <= now + FUTURE_SKEW {
        return timestamp;
    }

    timestamp
        .with_year(timestamp.year() - 1)
        .unwrap_or(timestamp)
}

/// Apply the CLI view filters (`--failed`, `--user`, `--ip`, `--since`).
///
/// Returns a new vector; the input is left untouched. Pure aside from reading
/// the parsed `Args`, so it is straightforward to test.
pub fn filter_events(events: Vec<AuthEvent>, args: &Args, now: NaiveDateTime) -> Result<Vec<AuthEvent>> {
    let since_cutoff = match args.since_duration()? {
        Some(duration) => Some(now - duration),
        None => None,
    };

    let filtered = events
        .into_iter()
        .filter(|event| !args.failed || event.event_type.is_failure())
        .filter(|event| match &args.user {
            Some(wanted) => event.username.as_deref() == Some(wanted.as_str()),
            None => true,
        })
        .filter(|event| match args.ip {
            Some(wanted) => event.source_ip == Some(wanted),
            None => true,
        })
        .filter(|event| match since_cutoff {
            Some(cutoff) => event.timestamp >= cutoff,
            None => true,
        })
        .collect();

    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;
    use chrono::NaiveDate;
    use std::net::IpAddr;

    fn now() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 1, 10)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
    }

    #[test]
    fn future_timestamp_rolls_back_a_year() {
        // A December event parsed with the January year is in the future.
        let december = NaiveDate::from_ymd_opt(2026, 12, 20)
            .unwrap()
            .and_hms_opt(3, 0, 0)
            .unwrap();
        let corrected = correct_year(december, now());
        assert_eq!(corrected.year(), 2025);
    }

    #[test]
    fn recent_past_timestamp_is_unchanged() {
        let recent = NaiveDate::from_ymd_opt(2026, 1, 9)
            .unwrap()
            .and_hms_opt(3, 0, 0)
            .unwrap();
        assert_eq!(correct_year(recent, now()), recent);
    }

    fn event(event_type: EventType, user: &str, ip: &str, hour: u32) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 1, 10)
                .unwrap()
                .and_hms_opt(hour, 0, 0)
                .unwrap(),
            event_type,
            username: Some(user.to_string()),
            source_ip: ip.parse::<IpAddr>().ok(),
            port: None,
            command: None,
            raw: String::new(),
        }
    }

    fn sample_events() -> Vec<AuthEvent> {
        vec![
            event(EventType::LoginFailure, "root", "10.0.0.1", 9),
            event(EventType::LoginSuccess, "alex", "10.0.0.2", 10),
            event(EventType::InvalidUser, "oracle", "10.0.0.1", 11),
        ]
    }

    fn args() -> Args {
        Args {
            file: None,
            failed: false,
            user: None,
            ip: None,
            since: None,
            summary_only: false,
            brute_threshold: None,
            window_minutes: None,
            spray_threshold: None,
        }
    }

    #[test]
    fn failed_filter_keeps_only_failures() {
        let mut a = args();
        a.failed = true;
        let filtered = filter_events(sample_events(), &a, now()).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.event_type.is_failure()));
    }

    #[test]
    fn user_filter_matches_exact_username() {
        let mut a = args();
        a.user = Some("alex".to_string());
        let filtered = filter_events(sample_events(), &a, now()).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].username.as_deref(), Some("alex"));
    }

    #[test]
    fn ip_filter_matches_exact_ip() {
        let mut a = args();
        a.ip = Some("10.0.0.1".parse().unwrap());
        let filtered = filter_events(sample_events(), &a, now()).unwrap();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn since_filter_rejects_bad_duration() {
        let mut a = args();
        a.since = Some("bogus".to_string());
        assert!(filter_events(sample_events(), &a, now()).is_err());
    }
}
