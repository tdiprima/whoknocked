//! Render the human-facing report: banner, summary, and findings.
//!
//! `build_report` is a pure function returning a `String`, so its output can
//! be snapshot-tested. `print_report` is the thin I/O wrapper `main` calls.

use crate::cli::ColorMode;
use crate::finding::{Finding, Severity};
use crate::summary::Summary;
use std::io::IsTerminal;

// --- ANSI styling ------------------------------------------------------------
//
// A tiny hand-rolled palette keeps the dependency list short. Every style is
// gated on the `color` flag so piped/CI output stays plain text.

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";

/// Wrap `text` in `style` when color is enabled.
fn paint(color: bool, style: &str, text: &str) -> String {
    if color {
        format!("{style}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Decide whether to emit color, honoring `--color` and `NO_COLOR`.
pub fn use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    }
}

/// The color that goes with a severity level.
fn severity_style(severity: Severity) -> &'static str {
    match severity {
        Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Normal => GREEN,
    }
}

/// Overall risk level derived from the most severe finding.
fn overall_risk(findings: &[Finding]) -> &'static str {
    let highest = findings.iter().map(|f| f.severity).max();
    match highest {
        Some(Severity::High) => "ELEVATED \u{26A0}\u{FE0F}", // warning sign
        Some(Severity::Medium) => "GUARDED",
        _ => "NORMAL \u{2705}", // check mark
    }
}

/// Style for the overall risk line.
fn risk_style(findings: &[Finding]) -> &'static str {
    findings
        .iter()
        .map(|f| f.severity)
        .max()
        .map(severity_style)
        .unwrap_or(GREEN)
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
    color: bool,
) -> String {
    let mut out = String::new();

    out.push_str(&format!("\u{1F6AA} {}\n", paint(color, BOLD, "WHOKNOCKED"))); // door emoji
    out.push_str(&paint(
        color,
        DIM,
        &format!("Authentication activity \u{2014} {source_label}"),
    ));
    out.push_str("\n\n");
    let risk = paint(color, risk_style(findings), overall_risk(findings));
    let risk = paint(color, BOLD, &risk);
    out.push_str(&format!("Risk: {risk}\n\n"));

    push_summary(&mut out, summary, color);

    if summary_only {
        return out;
    }

    out.push('\n');
    push_findings(&mut out, findings, color);
    out
}

/// Append the aggregate counts block.
fn push_summary(out: &mut String, summary: &Summary, color: bool) {
    let rows = [
        (summary.total_events, "total events"),
        (summary.successful_logins, "successful logins"),
        (summary.failed_logins, "failed logins"),
        (summary.invalid_users, "invalid users"),
        (summary.sudo_events, "sudo events"),
        (summary.unique_source_ips, "unique source IPs"),
        (summary.unique_usernames, "unique usernames"),
    ];

    for (count, label) in rows {
        let count = paint(color, BOLD, &format!("{count:>7}"));
        out.push_str(&format!("  {count}   {label}\n"));
    }
}

/// Append the findings section, most-severe first.
fn push_findings(out: &mut String, findings: &[Finding], color: bool) {
    out.push_str(&paint(color, BOLD, "Interesting activity"));
    out.push('\n');
    out.push_str(&paint(color, DIM, &"\u{2500}".repeat(52)));
    out.push('\n');

    if findings.is_empty() {
        out.push_str(&format!(
            "\n\u{1F7E2} {}\n",
            paint(color, GREEN, "Nothing unusual detected.")
        ));
        return;
    }

    for finding in findings {
        out.push('\n');
        let time = finding
            .timestamp
            .map(|t| t.format("%H:%M:%S ").to_string())
            .unwrap_or_default();
        let title = paint(color, BOLD, &finding.title);
        let title = paint(color, severity_style(finding.severity), &title);
        out.push_str(&format!(
            "{} {}{}\n",
            finding.severity.emoji(),
            paint(color, DIM, &time),
            title
        ));
        for line in finding.detail.lines() {
            out.push_str(&format!("   {}\n", style_detail_line(color, line)));
        }
    }
}

/// Highlight the `Label:` prefix of a detail line so findings scan quickly.
///
/// A label is a short phrase starting with a letter, e.g. `Source:` or
/// `Users tried:`. Free-text lines pass through untouched.
fn style_detail_line(color: bool, line: &str) -> String {
    match line.split_once(':') {
        Some((label, rest))
            if label.len() <= 20 && label.chars().next().is_some_and(char::is_alphabetic) =>
        {
            format!("{}:{}", paint(color, CYAN, label), rest)
        }
        _ => line.to_string(),
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
pub fn print_report(
    source_label: &str,
    summary: &Summary,
    findings: &[Finding],
    summary_only: bool,
    color: bool,
) {
    let report = build_report(source_label, summary, findings, summary_only, color);
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
        assert_eq!(overall_risk(&[finding(Severity::Medium, "m")]), "GUARDED");
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
        let report = build_report(
            "test.log",
            &summary,
            &[finding(Severity::High, "x")],
            true,
            false,
        );
        assert!(!report.contains("Interesting activity"));
        assert!(report.contains("WHOKNOCKED"));
    }

    #[test]
    fn color_is_omitted_when_disabled() {
        let summary = Summary::default();
        let report = build_report(
            "test.log",
            &summary,
            &[finding(Severity::High, "x")],
            false,
            false,
        );
        assert!(!report.contains("\x1b["));
    }

    #[test]
    fn color_is_present_when_enabled() {
        let summary = Summary::default();
        let report = build_report(
            "test.log",
            &summary,
            &[finding(Severity::High, "x")],
            false,
            true,
        );
        assert!(report.contains(RED));
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn full_report_includes_findings() {
        let summary = Summary::default();
        let report = build_report(
            "test.log",
            &summary,
            &[finding(Severity::High, "brute force")],
            false,
            false,
        );
        assert!(report.contains("Interesting activity"));
        assert!(report.contains("brute force"));
    }
}
