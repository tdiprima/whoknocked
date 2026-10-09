//! Detection #5: a direct SSH login as `root`.
//!
//! Most hardening guides disable `PermitRootLogin`. A successful root login
//! over SSH is therefore either a policy gap or an attacker who found the one
//! account that matters, so it is always worth a look.

use super::Detection;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};

pub struct RootLogin;

impl Detection for RootLogin {
    fn name(&self) -> &'static str {
        "root_login"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        events
            .iter()
            .filter(|e| e.event_type.is_success() && e.username.as_deref() == Some("root"))
            .map(|event| {
                let source = event
                    .source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "?".to_string());
                Finding {
                    severity: Severity::Medium,
                    title: "Direct root login".to_string(),
                    detail: format!(
                        "Source:    {source}\n\
                         Time:      {time}\n\n\
                         Recommendation:\n\
                         Prefer a normal user plus sudo, and set PermitRootLogin no \
                         (or prohibit-password) in sshd_config.",
                        time = event.timestamp.format("%H:%M:%S"),
                    ),
                    timestamp: Some(event.timestamp),
                    source_ip: event.source_ip,
                    username: Some("root".to_string()),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::test_support::event;
    use crate::event::EventType;

    #[test]
    fn flags_root_success_only() {
        let events = vec![
            event(EventType::LoginSuccess, "root", "10.0.0.1", 9, 0),
            event(EventType::LoginFailure, "root", "10.0.0.1", 9, 1),
            event(EventType::LoginSuccess, "alex", "10.0.0.1", 9, 2),
        ];
        let findings = RootLogin.analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].username.as_deref(), Some("root"));
    }
}
