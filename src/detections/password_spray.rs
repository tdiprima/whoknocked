//! Detection #3: username / password spraying.
//!
//! One failure each against many accounts is not a classic brute force, but
//! the pattern is suspicious: a single source trying `admin`, `oracle`,
//! `postgres`, `jenkins`, ... a couple of times each. "38 attempts -> one
//! user" and "2 attempts -> 19 users" are different attacks.

use super::{group_by_ip, Detection};
use crate::config::DetectorConfig;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};
use chrono::NaiveDateTime;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct PasswordSpray {
    config: DetectorConfig,
}

impl PasswordSpray {
    pub fn new(config: DetectorConfig) -> Self {
        PasswordSpray { config }
    }
}

impl Detection for PasswordSpray {
    fn name(&self) -> &'static str {
        "password_spray"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        let failures_by_ip = group_by_ip(events, |event| event.event_type.is_failure());

        let mut findings = Vec::new();
        for (ip, failures) in failures_by_ip {
            if let Some(finding) = self.evaluate_ip(ip, &failures) {
                findings.push(finding);
            }
        }
        findings
    }
}

impl PasswordSpray {
    /// Flag an IP that touches many accounts with only a few tries each.
    fn evaluate_ip(&self, ip: IpAddr, failures: &[&AuthEvent]) -> Option<Finding> {
        let attempts_per_user = count_attempts_per_user(failures);

        let distinct_users = attempts_per_user.len() as u32;
        if distinct_users < self.config.spray_min_users {
            return None;
        }

        let max_attempts = attempts_per_user.values().copied().max().unwrap_or(0);
        // "Low and slow": if any single account was hammered, that is brute
        // force, not spraying, and the brute-force detector owns it.
        if max_attempts > self.config.spray_max_per_user {
            return None;
        }

        let (first_seen, last_seen) = time_bounds(failures)?;
        let duration_secs = (last_seen - first_seen).num_seconds().max(0);

        let detail = format!(
            "Source IP:         {ip}\n\
             Accounts tried:    {distinct_users}\n\
             Attempts/account:  1-{max_attempts}\n\
             Duration:          {duration}s",
            duration = duration_secs,
        );

        Some(Finding {
            severity: Severity::Medium,
            title: "Possible username/password spray".to_string(),
            detail,
            timestamp: Some(first_seen),
            source_ip: Some(ip),
            username: None,
        })
    }
}

/// Count how many failed attempts each username received from one IP.
fn count_attempts_per_user(failures: &[&AuthEvent]) -> BTreeMap<String, u32> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for event in failures {
        let Some(name) = event.username.as_deref() else {
            continue;
        };
        *counts.entry(name.to_string()).or_insert(0) += 1;
    }
    counts
}

/// The earliest and latest timestamps among a set of events.
fn time_bounds(failures: &[&AuthEvent]) -> Option<(NaiveDateTime, NaiveDateTime)> {
    let first = failures.iter().map(|e| e.timestamp).min()?;
    let last = failures.iter().map(|e| e.timestamp).max()?;
    Some((first, last))
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

    fn failure(second: u32, user: &str, ip: &str) -> AuthEvent {
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
    fn flags_many_accounts_with_few_attempts() {
        let ip = "45.20.10.2";
        let users = [
            "admin",
            "administrator",
            "ubuntu",
            "oracle",
            "postgres",
            "mysql",
            "backup",
            "test",
            "dev",
            "jenkins",
        ];
        let events: Vec<AuthEvent> = users
            .iter()
            .enumerate()
            .map(|(i, user)| failure(i as u32, user, ip))
            .collect();

        let findings = PasswordSpray::new(config()).analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn does_not_flag_single_account_hammering() {
        // 20 failures, but all against one account: that is brute force.
        let events: Vec<AuthEvent> = (0..20).map(|i| failure(i, "root", "45.20.10.2")).collect();
        assert!(PasswordSpray::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn does_not_flag_too_few_accounts() {
        let events: Vec<AuthEvent> = ["admin", "root", "test"]
            .iter()
            .enumerate()
            .map(|(i, user)| failure(i as u32, user, "45.20.10.2"))
            .collect();
        assert!(PasswordSpray::new(config()).analyze(&events).is_empty());
    }

    #[test]
    fn empty_input_produces_no_findings() {
        assert!(PasswordSpray::new(config()).analyze(&[]).is_empty());
    }
}
