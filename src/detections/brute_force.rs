//! Detection #1: brute-force attempts.
//!
//! Rule: if a single source IP produces at least `brute_min_failures`
//! failed logins within any `window`-length span, flag it. This is the
//! classic "many failures, same IP, short time" pattern.

use super::{group_by_ip, Detection};
use crate::config::DetectorConfig;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};
use chrono::{Duration, NaiveDateTime};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct BruteForce {
    config: DetectorConfig,
}

impl BruteForce {
    pub fn new(config: DetectorConfig) -> Self {
        BruteForce { config }
    }
}

impl Detection for BruteForce {
    fn name(&self) -> &'static str {
        "brute_force"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        let window = chrono_window(&self.config);
        let failures_by_ip = group_by_ip(events, |event| event.event_type.is_failure());

        let mut findings = Vec::new();
        for (ip, failures) in failures_by_ip {
            if let Some(finding) = self.evaluate_ip(ip, &failures, window) {
                findings.push(finding);
            }
        }
        findings
    }
}

impl BruteForce {
    /// Decide whether one IP's failures constitute a brute-force burst.
    fn evaluate_ip(
        &self,
        ip: IpAddr,
        failures: &[&AuthEvent],
        window: Duration,
    ) -> Option<Finding> {
        let mut timestamps: Vec<NaiveDateTime> = failures.iter().map(|e| e.timestamp).collect();
        timestamps.sort_unstable();

        let peak = peak_window_count(&timestamps, window);
        if peak < self.config.brute_min_failures as usize {
            return None;
        }

        let first_seen = *timestamps.first()?;
        let last_seen = *timestamps.last()?;
        let users = count_usernames(failures);

        let detail = format!(
            "Source:       {ip}\n\
             Failures:     {total} (peak {peak} within {window_mins} min)\n\
             First seen:   {first}\n\
             Last seen:    {last}\n\
             Users tried:  {users_line}",
            total = failures.len(),
            window_mins = window.num_minutes(),
            first = first_seen.format("%H:%M:%S"),
            last = last_seen.format("%H:%M:%S"),
            users_line = format_username_counts(&users),
        );

        Some(Finding {
            severity: Severity::High,
            title: "Possible brute force".to_string(),
            detail,
            timestamp: Some(first_seen),
            source_ip: Some(ip),
            username: None,
        })
    }
}

/// The most failures observed within any single sliding `window`.
///
/// `timestamps` must be sorted ascending. Uses two pointers, so it is O(n).
fn peak_window_count(timestamps: &[NaiveDateTime], window: Duration) -> usize {
    let mut left = 0usize;
    let mut peak = 0usize;

    for right in 0..timestamps.len() {
        while timestamps[right] - timestamps[left] > window {
            left += 1;
        }
        let current = right - left + 1;
        if current > peak {
            peak = current;
        }
    }
    peak
}

/// Count failures per username for an IP, so the report can show what was
/// targeted. Uses a `BTreeMap` for stable ordering before sorting by count.
fn count_usernames(failures: &[&AuthEvent]) -> BTreeMap<String, u32> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for event in failures {
        let name = event.username.clone().unwrap_or_else(|| "?".to_string());
        *counts.entry(name).or_insert(0) += 1;
    }
    counts
}

/// Render the top targeted usernames, most-attempted first, capped at 6.
fn format_username_counts(counts: &BTreeMap<String, u32>) -> String {
    const MAX_SHOWN: usize = 6;

    let mut ranked: Vec<(&String, &u32)> = counts.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let shown: Vec<String> = ranked
        .iter()
        .take(MAX_SHOWN)
        .map(|(name, count)| format!("{name} ({count})"))
        .collect();

    let mut line = shown.join(", ");
    if ranked.len() > MAX_SHOWN {
        line.push_str(&format!(", +{} more", ranked.len() - MAX_SHOWN));
    }
    line
}

/// Convert the configured `std::time::Duration` window into a chrono one.
fn chrono_window(config: &DetectorConfig) -> Duration {
    Duration::seconds(config.window.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;
    use chrono::NaiveDate;
    use std::time::Duration as StdDuration;

    fn config() -> DetectorConfig {
        DetectorConfig {
            brute_min_failures: 5,
            window: StdDuration::from_secs(5 * 60),
            spray_min_users: 8,
            spray_max_per_user: 3,
            failures_before_success: 5,
            off_hours_start: 23,
            off_hours_end: 6,
        }
    }

    fn failure_at(second: u32, user: &str, ip: &str) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(9, 0, second)
                .unwrap(),
            event_type: EventType::LoginFailure,
            username: Some(user.to_string()),
            source_ip: ip.parse().ok(),
            port: None,
            command: None,
            raw: String::new(),
        }
    }

    #[test]
    fn flags_many_failures_from_one_ip() {
        let events: Vec<AuthEvent> = (0..6)
            .map(|i| failure_at(i * 2, "root", "10.4.2.81"))
            .collect();
        let findings = BruteForce::new(config()).analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].source_ip.unwrap().to_string(), "10.4.2.81");
    }

    #[test]
    fn does_not_flag_below_threshold() {
        let events: Vec<AuthEvent> = (0..4).map(|i| failure_at(i, "root", "10.4.2.81")).collect();
        assert!(BruteForce::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn does_not_flag_failures_spread_beyond_window() {
        // 6 failures, but 10 minutes apart: never 5 within a 5-minute window.
        let base = NaiveDate::from_ymd_opt(2026, 8, 16)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        let events: Vec<AuthEvent> = (0..6)
            .map(|i| {
                let ts = base + Duration::seconds(i * 600);
                AuthEvent {
                    timestamp: ts,
                    event_type: EventType::LoginFailure,
                    username: Some("root".to_string()),
                    source_ip: "10.4.2.81".parse().ok(),
                    port: None,
                    command: None,
                    raw: String::new(),
                }
            })
            .collect();
        assert!(BruteForce::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn empty_input_produces_no_findings() {
        assert!(BruteForce::new(config()).analyze(&[]).is_empty());
    }

    #[test]
    fn peak_window_count_counts_densest_burst() {
        let base = NaiveDate::from_ymd_opt(2026, 8, 16)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        let times: Vec<NaiveDateTime> = [0i64, 1, 2, 3, 4, 3600, 3601]
            .iter()
            .map(|s| base + Duration::seconds(*s))
            .collect();
        assert_eq!(peak_window_count(&times, Duration::minutes(5)), 5);
    }
}
