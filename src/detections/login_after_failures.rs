//! Detection #2: a successful login right after a burst of failures.
//!
//! Individual events are dull; their *relationship* is what matters. A login
//! that succeeds moments after many failures from the same source is far more
//! interesting than an ordinary login, so LogHound correlates the two.

use super::{group_by_ip, Detection};
use crate::config::DetectorConfig;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};
use chrono::{Duration, NaiveDateTime};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct LoginAfterFailures {
    config: DetectorConfig,
}

impl LoginAfterFailures {
    pub fn new(config: DetectorConfig) -> Self {
        LoginAfterFailures { config }
    }
}

impl Detection for LoginAfterFailures {
    fn name(&self) -> &'static str {
        "login_after_failures"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        let window = chrono_window(&self.config);
        let failure_times = failure_timeline_by_ip(events);

        let mut findings = Vec::new();
        for success in events.iter().filter(|e| e.event_type.is_success()) {
            let Some(ip) = success.source_ip else {
                continue;
            };
            let Some(times) = failure_times.get(&ip) else {
                continue;
            };

            if let Some(finding) = self.evaluate_success(success, ip, times, window) {
                findings.push(finding);
            }
        }
        findings
    }
}

impl LoginAfterFailures {
    /// Flag a success if enough failures from the same IP precede it within
    /// the window.
    fn evaluate_success(
        &self,
        success: &AuthEvent,
        ip: IpAddr,
        sorted_failure_times: &[NaiveDateTime],
        window: Duration,
    ) -> Option<Finding> {
        let window_start = success.timestamp - window;
        let preceding = failures_in_range(sorted_failure_times, window_start, success.timestamp);

        if (preceding.len() as u32) < self.config.failures_before_success {
            return None;
        }

        let last_failure = *preceding.last()?;
        let gap_seconds = (success.timestamp - last_failure).num_seconds().max(0);
        let user = success.username.clone().unwrap_or_else(|| "?".to_string());

        let detail = format!(
            "User:      {user}\n\
             Source:    {ip}\n\
             {count} failed attempts, then success after {gap}s\n\
             Time:      {time}\n\n\
             Recommendation:\n\
             Investigate whether this source and login were expected.",
            count = preceding.len(),
            gap = gap_seconds,
            time = success.timestamp.format("%H:%M:%S"),
        );

        Some(Finding {
            severity: Severity::High,
            title: "Login after repeated failures".to_string(),
            detail,
            timestamp: Some(success.timestamp),
            source_ip: Some(ip),
            username: Some(user),
        })
    }
}

/// Build a map of source IP to its sorted list of failure timestamps.
fn failure_timeline_by_ip(events: &[AuthEvent]) -> BTreeMap<IpAddr, Vec<NaiveDateTime>> {
    let failures_by_ip = group_by_ip(events, |event| event.event_type.is_failure());

    let mut timelines: BTreeMap<IpAddr, Vec<NaiveDateTime>> = BTreeMap::new();
    for (ip, failures) in failures_by_ip {
        let mut times: Vec<NaiveDateTime> = failures.iter().map(|e| e.timestamp).collect();
        times.sort_unstable();
        timelines.insert(ip, times);
    }
    timelines
}

/// Return the failure timestamps in `[start, end]`, inclusive.
///
/// `sorted_times` must be ascending; uses binary search, so it stays fast
/// even with tens of thousands of failures.
fn failures_in_range(
    sorted_times: &[NaiveDateTime],
    start: NaiveDateTime,
    end: NaiveDateTime,
) -> &[NaiveDateTime] {
    let lower = sorted_times.partition_point(|&time| time < start);
    let upper = sorted_times.partition_point(|&time| time <= end);
    &sorted_times[lower..upper]
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
            brute_min_failures: 10,
            window: StdDuration::from_secs(5 * 60),
            spray_min_users: 8,
            spray_max_per_user: 3,
            failures_before_success: 5,
        }
    }

    fn event(second: u32, event_type: EventType, user: &str, ip: &str) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(3, 12, second)
                .unwrap(),
            event_type,
            username: Some(user.to_string()),
            source_ip: ip.parse().ok(),
            port: None,
            command: None,
            raw: String::new(),
        }
    }

    #[test]
    fn flags_success_after_five_failures() {
        let ip = "203.0.113.17";
        let mut events: Vec<AuthEvent> = (0..5)
            .map(|i| event(i, EventType::LoginFailure, "alex", ip))
            .collect();
        events.push(event(30, EventType::LoginSuccess, "alex", ip));

        let findings = LoginAfterFailures::new(config()).analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].username.as_deref(), Some("alex"));
    }

    #[test]
    fn does_not_flag_clean_success() {
        let events = vec![event(30, EventType::LoginSuccess, "alex", "203.0.113.17")];
        assert!(LoginAfterFailures::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn does_not_flag_when_failures_are_from_a_different_ip() {
        let mut events: Vec<AuthEvent> = (0..5)
            .map(|i| event(i, EventType::LoginFailure, "alex", "203.0.113.17"))
            .collect();
        events.push(event(30, EventType::LoginSuccess, "alex", "10.0.0.9"));
        assert!(LoginAfterFailures::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn does_not_flag_failures_older_than_window() {
        let ip = "203.0.113.17";
        // Five failures at t=0..5, success 10 minutes later (outside 5m window).
        let mut events: Vec<AuthEvent> = (0..5)
            .map(|i| event(i, EventType::LoginFailure, "alex", ip))
            .collect();
        events.push(event(0, EventType::LoginSuccess, "alex", ip));
        // Move the success far ahead by rebuilding its timestamp.
        let mut late_success = event(0, EventType::LoginSuccess, "alex", ip);
        late_success.timestamp = late_success.timestamp + Duration::minutes(10);
        events.pop();
        events.push(late_success);

        assert!(LoginAfterFailures::new(config()).analyze(&events).is_empty());
    }
}
