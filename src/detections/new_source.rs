//! Detection #6: a known user logging in from a source they never use.
//!
//! If `alex` has logged in from the office IP a dozen times and then once
//! from somewhere new, that one login deserves a glance. "Established" means
//! at least `MIN_HISTORY` successes from one IP; "new" means a single success
//! from a different IP.

use super::Detection;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Successes from one IP needed before it counts as that user's usual source.
const MIN_HISTORY: usize = 2;

pub struct NewSource;

impl Detection for NewSource {
    fn name(&self) -> &'static str {
        "new_source_for_user"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        // user -> ip -> successful logins from that ip
        let mut history: BTreeMap<&str, BTreeMap<IpAddr, Vec<&AuthEvent>>> = BTreeMap::new();
        for event in events.iter().filter(|e| e.event_type.is_success()) {
            let (Some(user), Some(ip)) = (event.username.as_deref(), event.source_ip) else {
                continue;
            };
            history
                .entry(user)
                .or_default()
                .entry(ip)
                .or_default()
                .push(event);
        }

        let mut findings = Vec::new();
        for (user, by_ip) in history {
            let usual: Vec<IpAddr> = by_ip
                .iter()
                .filter(|(_, logins)| logins.len() >= MIN_HISTORY)
                .map(|(ip, _)| *ip)
                .collect();
            if usual.is_empty() {
                continue;
            }

            for (ip, logins) in &by_ip {
                if logins.len() != 1 {
                    continue;
                }
                let event = logins[0];
                let usual_list = usual
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: "Login from a new source".to_string(),
                    detail: format!(
                        "User:          {user}\n\
                         New source:    {ip}\n\
                         Usual source:  {usual_list}\n\
                         Time:          {time}",
                        time = event.timestamp.format("%H:%M:%S"),
                    ),
                    timestamp: Some(event.timestamp),
                    source_ip: Some(*ip),
                    username: Some(user.to_string()),
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::test_support::event;
    use crate::event::EventType;

    #[test]
    fn flags_single_login_from_unfamiliar_ip() {
        let events = vec![
            event(EventType::LoginSuccess, "alex", "10.0.0.5", 8, 0),
            event(EventType::LoginSuccess, "alex", "10.0.0.5", 9, 0),
            event(EventType::LoginSuccess, "alex", "45.20.13.8", 10, 0),
        ];
        let findings = NewSource.analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_ip.unwrap().to_string(), "45.20.13.8");
    }

    #[test]
    fn needs_an_established_source_first() {
        let events = vec![
            event(EventType::LoginSuccess, "alex", "10.0.0.5", 8, 0),
            event(EventType::LoginSuccess, "alex", "10.0.0.6", 9, 0),
        ];
        assert!(NewSource.analyze(&events).is_empty());
    }
}
