//! Detection #7: a successful login during off hours.
//!
//! A login at 03:00 is not an attack by itself, so this is a low-severity
//! "did you expect this?" nudge. The window defaults to 23:00-06:00 and can
//! be tuned with `WHOKNOCKED_OFF_HOURS_START` / `WHOKNOCKED_OFF_HOURS_END`.

use super::Detection;
use crate::config::DetectorConfig;
use crate::event::AuthEvent;
use crate::finding::{Finding, Severity};
use chrono::Timelike;

pub struct OffHours {
    start: u32,
    end: u32,
}

impl OffHours {
    pub fn new(config: DetectorConfig) -> Self {
        OffHours {
            start: config.off_hours_start,
            end: config.off_hours_end,
        }
    }

    /// Whether `hour` falls in the off-hours window, which may wrap midnight.
    fn is_off_hours(&self, hour: u32) -> bool {
        if self.start == self.end {
            return false;
        }
        if self.start < self.end {
            (self.start..self.end).contains(&hour)
        } else {
            hour >= self.start || hour < self.end
        }
    }
}

impl Detection for OffHours {
    fn name(&self) -> &'static str {
        "off_hours_login"
    }

    fn analyze(&self, events: &[AuthEvent]) -> Vec<Finding> {
        events
            .iter()
            .filter(|e| e.event_type.is_success() && self.is_off_hours(e.timestamp.hour()))
            .map(|event| {
                let user = event.username.clone().unwrap_or_else(|| "?".to_string());
                let source = event
                    .source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "?".to_string());
                Finding {
                    severity: Severity::Normal,
                    title: "Off-hours login".to_string(),
                    detail: format!(
                        "User:      {user}\n\
                         Source:    {source}\n\
                         Time:      {time} (off hours are {start:02}:00-{end:02}:00)",
                        time = event.timestamp.format("%H:%M:%S"),
                        start = self.start,
                        end = self.end,
                    ),
                    timestamp: Some(event.timestamp),
                    source_ip: event.source_ip,
                    username: Some(user),
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
    fn window_wraps_midnight() {
        let detector = OffHours { start: 23, end: 6 };
        assert!(detector.is_off_hours(23));
        assert!(detector.is_off_hours(3));
        assert!(!detector.is_off_hours(6));
        assert!(!detector.is_off_hours(12));
    }

    #[test]
    fn flags_only_successes_in_window() {
        let detector = OffHours { start: 23, end: 6 };
        let events = vec![
            event(EventType::LoginSuccess, "alex", "10.0.0.1", 3, 0),
            event(EventType::LoginFailure, "alex", "10.0.0.1", 3, 1),
            event(EventType::LoginSuccess, "alex", "10.0.0.1", 10, 0),
        ];
        let findings = detector.analyze(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Normal);
    }
}
