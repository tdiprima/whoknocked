//! The detection engine: a set of independent rules over the same events.
//!
//! Each detector implements the [`Detection`] trait, gets the whole pile of
//! events, and answers one question: "anything interesting in here?" Adding a
//! new rule means adding a file and one line in [`all_detectors`]; nothing
//! else in the codebase needs to change.

pub mod brute_force;
pub mod login_after_failures;
pub mod password_spray;

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
    ]
}

/// Run every detector over the events and collect all findings.
pub fn run_all(detectors: &[Box<dyn Detection>], events: &[AuthEvent]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for detector in detectors {
        let produced = detector.analyze(events);
        log::debug!("detector {} produced {} finding(s)", detector.name(), produced.len());
        findings.extend(produced);
    }
    findings
}

/// Group event references by source IP, keeping only events that satisfy
/// `keep`. A `BTreeMap` gives deterministic (sorted) IP ordering so output is
/// stable across runs.
///
/// Shared by multiple detectors to avoid repeating the grouping logic.
pub(crate) fn group_by_ip<'a, F>(
    events: &'a [AuthEvent],
    keep: F,
) -> BTreeMap<IpAddr, Vec<&'a AuthEvent>>
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
