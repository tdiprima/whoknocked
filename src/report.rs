//! Render the human-facing report: banner, summary, and findings.
//!
//! `build_report` is a pure function returning a `String`, so its output can
//! be snapshot-tested. `print_report` is the thin I/O wrapper `main` calls.

use crate::finding::{Finding, Severity};
use crate::summary::Summary;
use std::io::IsTerminal;

/// Overall risk level derived from the most severe finding.
fn overall_risk(findings: &[Finding]) -> &'static str {
    let highest = findings.iter().map(|f| f.severity).max();
    match highest {
        Some(Severity::High) => "ELEVATED \u{26A0}\u{FE0F}", // warning sign
        Some(Severity::Medium) => "GUARDED",
        _ => "NORMAL \u{2705}", // check mark
    }
}

/// Build the full report text for the given data.
///
/// `source_label` is what was analyzed (e.g. the log path). When
/// `summary_only` is set, the findings section is omitted.
pub fn build_report(
    source_label: &str,
    summary: &Summary,
    findings: &[Finding],
    summary_only: bool,
) -> String {
    let mut out = String::new();

    out.push_str("\u{1F9AE} LOGHOUND\n"); // dog emoji
    out.push_str(&format!("Authentication activity \u{2014} {source_label}\n\n"));
    out.push_str(&format!("Risk: {}\n\n", overall_risk(findings)));

    push_summary(&mut out, summary);

    if summary_only {
        return out;
    }

    out.push('\n');
    push_findings(&mut out, findings);
    out
}

/// Append the aggregate counts block.
fn push_summary(out: &mut String, summary: &Summary) {
    let rows = [
        (summary.successful_logins, "successful logins"),
        (summary.failed_logins, "failed logins"),
        (summary.invalid_users, "invalid users"),
        (summary.sudo_events, "sudo events"),
        (summary.unique_source_ips, "unique source IPs"),
        (summary.unique_usernames, "unique usernames"),
    ];

    for (count, label) in rows {
        out.push_str(&format!("  {count:>7}   {label}\n"));
    }
}

/// Append the findings section, most-severe first.
fn push_findings(out: &mut String, findings: &[Finding]) {
    out.push_str("Interesting activity\n");
    out.push_str(&"\u{2500}".repeat(52));
    out.push('\n');

    if findings.is_empty() {
        out.push_str("\n\u{1F7E2} Nothing unusual detected.\n");
        return;
    }

    for finding in findings {
        out.push('\n');
        let time = finding
            .timestamp
            .map(|t| t.format("%H:%M:%S ").to_string())
            .unwrap_or_default();
        out.push_str(&format!(
            "{} {}{}\n",
            finding.severity.emoji(),
            time,
            finding.title
        ));
        for line in finding.detail.lines() {
            out.push_str(&format!("   {line}\n"));
        }
    }
}

/// Sort findings in place: most severe first, then earliest first.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });
}

/// Print the report to stdout.
///
/// The report itself is the tool's primary output, so it goes to stdout by
/// design (diagnostics go to the logger / stderr instead).
pub fn print_report(source_label: &str, summary: &Summary, findings: &[Finding], summary_only: bool) {
    let report = build_report(source_label, summary, findings, summary_only);
    print!("{report}");
    // A trailing newline only when stdout is a terminal, for a tidy prompt.
    if std::io::stdout().is_terminal() {
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn finding(severity: Severity, title: &str) -> Finding {
        Finding {
            severity,
            title: title.to_string(),
            detail: "detail line".to_string(),
            timestamp: NaiveDate::from_ymd_opt(2026, 8, 16)
                .unwrap()
                .and_hms_opt(9, 0, 0),
            source_ip: None,
            username: None,
        }
    }

    #[test]
    fn risk_reflects_highest_severity() {
        assert_eq!(overall_risk(&[]), "NORMAL \u{2705}");
        assert_eq!(
            overall_risk(&[finding(Severity::Medium, "m")]),
            "GUARDED"
        );
        assert!(overall_risk(&[finding(Severity::High, "h")]).starts_with("ELEVATED"));
    }

    #[test]
    fn sort_puts_high_severity_first() {
        let mut findings = vec![
            finding(Severity::Medium, "medium"),
            finding(Severity::High, "high"),
        ];
        sort_findings(&mut findings);
        assert_eq!(findings[0].title, "high");
    }

    #[test]
    fn summary_only_omits_findings_section() {
        let summary = Summary::default();
        let report = build_report("test.log", &summary, &[finding(Severity::High, "x")], true);
        assert!(!report.contains("Interesting activity"));
        assert!(report.contains("LOGHOUND"));
    }

    #[test]
    fn full_report_includes_findings() {
        let summary = Summary::default();
        let report = build_report("test.log", &summary, &[finding(Severity::High, "brute force")], false);
        assert!(report.contains("Interesting activity"));
        assert!(report.contains("brute force"));
    }
}
