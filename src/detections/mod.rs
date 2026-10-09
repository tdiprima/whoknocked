//! The detection engine: a set of independent rules over the same events.
//!
//! Each detector implements the [`Detection`] trait, gets the whole pile of
//! events, and answers one question: "anything interesting in here?" Adding a
//! new rule means adding a file and one line in [`all_detectors`]; nothing
//! else in the codebase needs to change.

pub mod brute_force;
pub mod login_after_failures;
pub mod new_source;
pub mod off_hours;
pub mod password_spray;
pub mod root_login;
pub mod sudo_after_suspicious;

use crate::config::DetectorConfig;
use crate::event::AuthEvent;
use crate::finding::Finding;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// A single detection rule.
pub trait Detection {
    /// Stable identifier for logs and debugging.
    fn name(&self) -> &'static str;

    /// Inspect all events and return any findings.
    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding>;
}

/// Build the full set of detectors from the resolved configuration.
pub fn all_detectors(config: DetectorConfig) -> Vec<Box<dyn Detection>> {
    vec![
        Box::new(brute_force::BruteForce::new(config)),
        Box::new(login_after_failures::LoginAfterFailures::new(config)),
        Box::new(password_spray::PasswordSpray::new(config)),
        Box::new(sudo_after_suspicious::SudoAfterSuspicious::new(config)),
        Box::new(root_login::RootLogin),
        Box::new(new_source::NewSource),
        Box::new(off_hours::OffHours::new(config)),
    ]
}

/// Run every detector over the events and collect all findings.
pub fn run_all(detectors: &[Box<dyn Detection>], events: &[AuthEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for detector in detectors {
        let produced = detector.analyze(events);
        log::debug!(
            "detector {} produced {} finding(s)",
            detector.name(),
            produced.len()
        );
        findings.extend(produced);
    }
    findings
}

/// Group event references by source IP, keeping only events that satisfy
/// `keep`. A `BTreeMap` gives deterministic (sorted) IP ordering so output is
/// stable across runs.
///
/// Shared by multiple detectors to avoid repeating the grouping logic.
pub(crate) fn group_by_ip<F>(events: &[AuthEvent], keep: F) -> BTreeMap<IpAddr, Vec<&AuthEvent>>
where
    F: Fn(&AuthEvent) -> bool,
{
    let mut groups: BTreeMap<IpAddr, Vec<&AuthEvent>> = BTreeMap::new();
    for event in events {
        if !keep(event) {
            continue;
        }
        if let Some(ip) = event.source_ip {
            groups.entry(ip).or_default().push(event);
        }
    }
    groups
}

/// Shared fixtures for detector unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::config::DetectorConfig;
    use crate::event::{AuthEvent, EventType};
    use chrono::NaiveDate;

    pub fn config() -> DetectorConfig {
        DetectorConfig {
            brute_min_failures: 10,
            window: std::time::Duration::from_secs(5 * 60),
            spray_min_users: 8,
            spray_max_per_user: 3,
            failures_before_success: 5,
            off_hours_start: 23,
            off_hours_end: 6,
        }
    }

    pub fn event(event_type: EventType, user: &str, ip: &str, hour: u32, minute: u32) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(hour, minute, 0)
                .unwrap(),
            event_type,
            username: Some(user.to_string()),
            source_ip: ip.parse().ok(),
            port: None,
            command: None,
            raw: String::new(),
        }
    }

    pub fn sudo(user: &str, command: &str, hour: u32, minute: u32) -> AuthEvent {
        let mut e = event(EventType::Sudo, user, "", hour, minute);
        e.command = Some(command.to_string());
        e
    }
}
