//! Command-line interface definition and input validation.
//!
//! Parsing is handled by `clap`; this module only declares the surface and
//! validates the free-form values (like `--since 2h`) that `clap` cannot
//! check on its own.

use anyhow::{anyhow, Result};
use chrono::Duration;
use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

/// whoknocked: a tiny local SIEM-style analyzer for Linux auth logs.
///
/// With no filters it prints a summary and any interesting findings for the
/// detected auth log (`/var/log/auth.log` on Ubuntu/Debian,
/// `/var/log/secure` on RHEL/Rocky).
#[derive(Parser, Debug)]
#[command(name = "whoknocked", version, about, long_about = None)]
pub struct Args {
    /// Log file to analyze. Overrides distribution auto-detection.
    #[arg(short, long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Show only failed / invalid-user events.
    #[arg(long)]
    pub failed: bool,

    /// Show only events for this username.
    #[arg(long, value_name = "NAME")]
    pub user: Option<String>,

    /// Show only events from this source IP address.
    #[arg(long, value_name = "IP")]
    pub ip: Option<IpAddr>,

    /// Only consider events newer than this, e.g. 90m, 2h, 3d.
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,

    /// Print the summary only; skip the detection engine.
    #[arg(long)]
    pub summary_only: bool,

    /// Brute-force threshold: failures from one IP within the window.
    #[arg(long, value_name = "N")]
    pub brute_threshold: Option<u32>,

    /// Detection window length, in minutes.
    #[arg(long, value_name = "MINUTES")]
    pub window_minutes: Option<u64>,

    /// Password-spray threshold: distinct usernames tried from one IP.
    #[arg(long, value_name = "N")]
    pub spray_threshold: Option<u32>,

    /// When to use ANSI color in the report.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto, value_name = "WHEN")]
    pub color: ColorMode,
}

/// Color policy for the report. `Auto` colors only when stdout is a terminal
/// and `NO_COLOR` is unset (see <https://no-color.org>).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl Args {
    /// Parse the process arguments.
    pub fn parse_args() -> Self {
        Args::parse()
    }

    /// The `--since` value as a `chrono::Duration`, if provided.
    pub fn since_duration(&self) -> Result<Option<Duration>> {
        match &self.since {
            None => Ok(None),
            Some(raw) => parse_duration(raw).map(Some),
        }
    }
}

/// Parse a short human duration like `30s`, `90m`, `2h`, or `3d`.
///
/// Validates the format strictly: a positive integer followed by a single
/// unit suffix. Anything else is rejected with a clear message.
fn parse_duration(input: &str) -> Result<Duration> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--since value is empty"));
    }

    // Split off the final character as the unit. Using `char` length rather
    // than a raw byte index avoids a panic on multibyte trailing input.
    let unit = trimmed
        .chars()
        .last()
        .ok_or_else(|| anyhow!("--since value is empty"))?;
    let number_part = &trimmed[..trimmed.len() - unit.len_utf8()];

    let quantity: i64 = number_part
        .parse()
        .map_err(|_| anyhow!("invalid --since value {input:?}; expected e.g. 90m, 2h, 3d"))?;

    if quantity <= 0 {
        return Err(anyhow!("--since value must be positive, got {input:?}"));
    }

    match unit {
        's' => Ok(Duration::seconds(quantity)),
        'm' => Ok(Duration::minutes(quantity)),
        'h' => Ok(Duration::hours(quantity)),
        'd' => Ok(Duration::days(quantity)),
        other => Err(anyhow!(
            "unknown --since unit {other:?}; use s, m, h, or d (e.g. 2h)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::seconds(30));
        assert_eq!(parse_duration("90m").unwrap(), Duration::minutes(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::hours(2));
        assert_eq!(parse_duration("3d").unwrap(), Duration::days(3));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_duration("  2h ").unwrap(), Duration::hours(2));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("2x").is_err());
        assert!(parse_duration("-5m").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
