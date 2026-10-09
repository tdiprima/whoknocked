//! Detection #4: privileged commands after a suspicious login.
//!
//! `sudo` lines carry no source IP, but the session that ran them does. This
//! detector ties each sudo command back to the user's most recent SSH login
//! and flags it when that login came from an IP that had just produced a
//! burst of failures. Brute force followed by `cat /etc/shadow` is the whole
//! story in one finding.

use super::login_after_failures::{failure_timeline_by_ip, failures_in_range};
use super::Detection;
use crate::config::DetectorConfig;
use crate::event::{AuthEvent, EventType};
use crate::finding::{Finding, Severity};
use chrono::Duration;
use std::collections::BTreeMap;

/// How many commands to list in the finding before truncating.
const MAX_COMMANDS_SHOWN: usize = 5;

pub struct SudoAfterSuspicious {
    config: DetectorConfig,
}

impl SudoAfterSuspicious {
    pub fn new(config: DetectorConfig) -> Self {
        SudoAfterSuspicious { config }
    }
}

impl Detection for SudoAfterSuspicious {
    fn name(&self) -> &'static str {
        "sudo_after_suspicious_login"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        let window = Duration::from_std(self.config.window).unwrap_or(Duration::minutes(5));
        let failure_times = failure_timeline_by_ip(events);

        // Walk events in time order, remembering each user's latest login
        // and whether it was suspicious.
        let mut ordered: Vec<&AuthEvent> = events.iter().collect();
        ordered.sort_by_key(|e| e.timestamp);

        struct Session<'a> {
            login: &'a AuthEvent,
            preceding_failures: usize,
            commands: Vec<&'a AuthEvent>,
        }
        let mut sessions: BTreeMap<&str, Session> = BTreeMap::new();

        for event in ordered {
            let Some(user) = event.username.as_deref() else {
                continue;
            };
            match event.event_type {
                EventType::LoginSuccess => {
                    let preceding = event
                        .source_ip
                        .and_then(|ip| failure_times.get(&ip))
                        .map(|times| {
                            failures_in_range(times, event.timestamp - window, event.timestamp)
                                .len()
                        })
                        .unwrap_or(0);
                    sessions.insert(
                        user,
                        Session {
                            login: event,
                            preceding_failures: preceding,
                            commands: Vec::new(),
                        },
                    );
                }
                EventType::Sudo => {
                    if let Some(session) = sessions.get_mut(user) {
                        session.commands.push(event);
                    }
                }
                _ => {}
            }
        }

        sessions
            .into_iter()
            .filter(|(_, s)| {
                !s.commands.is_empty()
                    && s.preceding_failures as u32 >= self.config.failures_before_success
            })
            .map(|(user, session)| {
                let ip = session.login.source_ip;
                let shown: Vec<String> = session
                    .commands
                    .iter()
                    .take(MAX_COMMANDS_SHOWN)
                    .map(|e| {
                        format!(
                            "  {}  {}",
                            e.timestamp.format("%H:%M:%S"),
                            e.command.as_deref().unwrap_or("?")
                        )
                    })
                    .collect();
                let more = session.commands.len().saturating_sub(MAX_COMMANDS_SHOWN);
                let mut commands = shown.join("\n");
                if more > 0 {
                    commands.push_str(&format!("\n  +{more} more"));
                }
                let first = session.commands[0];
                Finding {
                    severity: Severity::High,
                    title: "Privileged commands after suspicious login".to_string(),
                    detail: format!(
                        "User:       {user}\n\
                         Source:     {source}\n\
                         Login:      {login} ({failures} failures just before it)\n\
                         Commands:\n{commands}\n\n\
                         Recommendation:\n\
                         Treat this host as potentially compromised until the \
                         commands are explained.",
                        source = ip.map(|i| i.to_string()).unwrap_or_else(|| "?".into()),
                        login = session.login.timestamp.format("%H:%M:%S"),
                        failures = session.preceding_failures,
                    ),
                    timestamp: Some(first.timestamp),
                    source_ip: ip,
                    username: Some(user.to_string()),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::test_support::{config, event, sudo};

    #[test]
    fn flags_sudo_after_brute_forced_login() {
        let mut events: Vec<AuthEvent> = (3..9)
            .map(|m| event(EventType::LoginFailure, "backup", "45.20.13.8", 9, m))
            .collect();
        events.push(event(EventType::LoginSuccess, "backup", "45.20.13.8", 9, 9));
        events.push(sudo("backup", "/usr/bin/cat /etc/shadow", 9, 10));
        events.push(sudo("backup", "/usr/sbin/useradd x", 9, 11));

        let findings = SudoAfterSuspicious::new(config()).analyze(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("/etc/shadow"));
        assert!(findings[0].detail.contains("5 failures"));
    }

    #[test]
    fn ignores_sudo_after_clean_login() {
        let events = vec![
            event(EventType::LoginSuccess, "alex", "10.0.0.5", 9, 0),
            sudo("alex", "/usr/bin/apt update", 9, 1),
        ];
        assert!(SudoAfterSuspicious::new(config())
            .analyze(&events)
            .is_empty());
    }
}
