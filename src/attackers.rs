//! The "Top sources" table: which IPs produced the most authentication noise.

use crate::enrich::IpInfo;
use crate::event::AuthEvent;
use chrono::NaiveDateTime;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

/// Per-IP activity rollup.
#[derive(Debug, Clone, Serialize)]
pub struct SourceActivity {
    pub ip: IpAddr,
    pub failures: usize,
    pub successes: usize,
    pub usernames: usize,
    pub first_seen: NaiveDateTime,
    pub last_seen: NaiveDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<IpInfo>,
}

/// Rank source IPs by failures (then successes), returning at most `limit`.
pub fn top_sources(events: &[AuthEvent], limit: usize) -> Vec<SourceActivity> {
    struct Acc<'a> {
        failures: usize,
        successes: usize,
        usernames: HashSet<&'a str>,
        first_seen: NaiveDateTime,
        last_seen: NaiveDateTime,
    }

    let mut by_ip: BTreeMap<IpAddr, Acc> = BTreeMap::new();
    for event in events {
        let Some(ip) = event.source_ip else { continue };
        let acc = by_ip.entry(ip).or_insert_with(|| Acc {
            failures: 0,
            successes: 0,
            usernames: HashSet::new(),
            first_seen: event.timestamp,
            last_seen: event.timestamp,
        });
        if event.event_type.is_failure() {
            acc.failures += 1;
        } else if event.event_type.is_success() {
            acc.successes += 1;
        }
        if let Some(user) = event.username.as_deref() {
            acc.usernames.insert(user);
        }
        acc.first_seen = acc.first_seen.min(event.timestamp);
        acc.last_seen = acc.last_seen.max(event.timestamp);
    }

    let mut ranked: Vec<SourceActivity> = by_ip
        .into_iter()
        .map(|(ip, acc)| SourceActivity {
            ip,
            failures: acc.failures,
            successes: acc.successes,
            usernames: acc.usernames.len(),
            first_seen: acc.first_seen,
            last_seen: acc.last_seen,
            info: None,
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.failures
            .cmp(&a.failures)
            .then_with(|| b.successes.cmp(&a.successes))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    ranked.truncate(limit);
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;
    use chrono::NaiveDate;

    fn event(event_type: EventType, user: &str, ip: &str, minute: u32) -> AuthEvent {
        AuthEvent {
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(9, minute, 0)
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
    fn ranks_by_failures_and_counts_users() {
        let events = vec![
            event(EventType::LoginFailure, "root", "1.1.1.1", 1),
            event(EventType::LoginFailure, "admin", "1.1.1.1", 2),
            event(EventType::LoginSuccess, "alex", "2.2.2.2", 3),
            event(EventType::InvalidUser, "x", "3.3.3.3", 4),
        ];
        let top = top_sources(&events, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].ip.to_string(), "1.1.1.1");
        assert_eq!(top[0].failures, 2);
        assert_eq!(top[0].usernames, 2);
        assert_eq!(top[0].first_seen.format("%M").to_string(), "01");
        assert_eq!(top[0].last_seen.format("%M").to_string(), "02");
        assert_eq!(top[1].ip.to_string(), "3.3.3.3");
    }
}
