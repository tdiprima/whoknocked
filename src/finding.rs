//! A `Finding` is the output of a detector: something a human should look at.
//!
//! Findings are deliberately *not* called "alerts". Following the whoknocked
//! philosophy, the goal is to surface *interesting* activity and let the
//! analyst decide, rather than screaming "HACKER!!!" at every anomaly.

use chrono::NaiveDateTime;
use serde::Serialize;
use std::net::IpAddr;

/// How much attention a finding deserves. Ordering matters: `High` is the
/// most severe, so findings sort High-first for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Routine, expected activity. Shown for context, not concern.
    #[allow(dead_code)]
    Normal,
    /// Worth a glance. An anomaly, not necessarily an attack.
    Medium,
    /// Worth investigating now.
    High,
}

impl Severity {
    /// A colored circle emoji, matching the whoknocked report style.
    pub fn emoji(self) -> &'static str {
        match self {
            Severity::High => "\u{1F534}",   // red circle
            Severity::Medium => "\u{1F7E1}", // yellow circle
            Severity::Normal => "\u{1F7E2}", // green circle
        }
    }

    /// A short uppercase label for table rows.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Normal => "NORMAL",
        }
    }
}

/// A single interesting observation produced by a detector.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Short headline, e.g. "Possible brute force".
    pub title: String,
    /// Multi-line human-readable explanation and recommendation.
    pub detail: String,
    /// When the interesting activity happened (used for sorting/timeline).
    pub timestamp: Option<NaiveDateTime>,
    pub source_ip: Option<IpAddr>,
    pub username: Option<String>,
}
