//! Aggregate counts over a set of authentication events.
//!
//! This is the whoknocked v0.1 view: the "instead of thousands of lines, here
//! are the numbers that matter" summary. Pure computation, no I/O.

use crate::event::{AuthEvent, EventType};
use serde::Serialize;
use std::collections::HashSet;
use std::net::IpAddr;

/// High-level counts over a slice of events.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Summary {
    pub total_events: usize,
    pub successful_logins: usize,
    pub failed_logins: usize,
    pub invalid_users: usize,
    pub sudo_events: usize,
    pub unique_source_ips: usize,
    pub unique_usernames: usize,
}

impl Summary {
    /// Compute a summary from a slice of parsed events.
    pub fn from_events(events: &[AuthEvent]) -> Self {
        let mut source_ips: HashSet<IpAddr> = HashSet::new();
        let mut usernames: HashSet<&str> = HashSet::new();
        let mut summary = Summary {
            total_events: events.len(),
            ..Summary::default()
        };

        for event in events {
            match event.event_type {
                EventType::LoginSuccess => summary.successful_logins += 1,
                EventType::LoginFailure => summary.failed_logins += 1,
                EventType::InvalidUser => summary.invalid_users += 1,
                EventType::Sudo => summary.sudo_events += 1,
                EventType::SessionOpened | EventType::SessionClosed => {}
            }

            if let Some(ip) = event.source_ip {
                source_ips.insert(ip);
            }
            if let Some(username) = event.username.as_deref() {
                usernames.insert(username);
            }
        }

        summary.unique_source_ips = source_ips.len();
        summary.unique_usernames = usernames.len();
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use std::net::IpAddr;

    fn event(event_type: EventType, user: &str, ip: &str) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            event_type,
            username: Some(user.to_string()),
            source_ip: ip.parse::<IpAddr>().ok(),
            port: None,
            command: None,
            raw: String::new(),
        }
    }

    #[test]
    fn empty_input_yields_zero_counts() {
        let summary = Summary::from_events(&[]);
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.unique_source_ips, 0);
        assert_eq!(summary.unique_usernames, 0);
    }

    #[test]
    fn counts_by_event_type_and_dedups_ips_and_users() {
        let events = vec![
            event(EventType::LoginFailure, "root", "10.0.0.1"),
            event(EventType::LoginFailure, "root", "10.0.0.1"),
            event(EventType::InvalidUser, "oracle", "10.0.0.2"),
            event(EventType::LoginSuccess, "alex", "10.0.0.1"),
            event(EventType::Sudo, "alex", "10.0.0.1"),
        ];
        let summary = Summary::from_events(&events);

        assert_eq!(summary.total_events, 5);
        assert_eq!(summary.failed_logins, 2);
        assert_eq!(summary.invalid_users, 1);
        assert_eq!(summary.successful_logins, 1);
        assert_eq!(summary.sudo_events, 1);
        assert_eq!(summary.unique_source_ips, 2); // 10.0.0.1, 10.0.0.2
        assert_eq!(summary.unique_usernames, 3); // root, oracle, alex
    }
}
