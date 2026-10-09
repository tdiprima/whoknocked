//! Detector thresholds, resolved from defaults, environment, then CLI flags.
//!
//! Precedence (lowest to highest): built-in default -> environment variable
//! -> explicit CLI flag. This keeps configuration out of the code while still
//! giving every knob a sane default, per the project configuration standard.

use crate::cli::Args;
use anyhow::{anyhow, Result};
use std::time::Duration;

// Built-in defaults. Named constants, not magic numbers scattered in logic.
const DEFAULT_BRUTE_MIN_FAILURES: u32 = 10;
const DEFAULT_WINDOW_MINUTES: u64 = 5;
const DEFAULT_SPRAY_MIN_USERS: u32 = 8;
const DEFAULT_SPRAY_MAX_PER_USER: u32 = 3;
const DEFAULT_FAILURES_BEFORE_SUCCESS: u32 = 5;
const DEFAULT_OFF_HOURS_START: u32 = 23;
const DEFAULT_OFF_HOURS_END: u32 = 6;

/// Tunable thresholds shared by the detection engine.
#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    /// Minimum failures from one IP within the window to flag brute force.
    pub brute_min_failures: u32,
    /// Sliding time window used by the brute-force and correlation detectors.
    pub window: Duration,
    /// Minimum distinct usernames from one IP to flag a spray.
    pub spray_min_users: u32,
    /// Maximum attempts per username still considered "spraying" (low and slow).
    pub spray_max_per_user: u32,
    /// Failures preceding a success (same IP, within window) to flag it.
    pub failures_before_success: u32,
    /// Hour (0-23) at which "off hours" begin for the off-hours detector.
    pub off_hours_start: u32,
    /// Hour (0-23) at which "off hours" end (exclusive).
    pub off_hours_end: u32,
}

impl DetectorConfig {
    /// Resolve configuration from CLI flags, environment, then defaults.
    pub fn resolve(args: &Args) -> Result<Self> {
        let brute_min_failures = pick_u32(
            args.brute_threshold,
            "WHOKNOCKED_BRUTE_MIN_FAILURES",
            DEFAULT_BRUTE_MIN_FAILURES,
        )?;

        let window_minutes = pick_u64(
            args.window_minutes,
            "WHOKNOCKED_WINDOW_MINUTES",
            DEFAULT_WINDOW_MINUTES,
        )?;

        let spray_min_users = pick_u32(
            args.spray_threshold,
            "WHOKNOCKED_SPRAY_MIN_USERS",
            DEFAULT_SPRAY_MIN_USERS,
        )?;

        let off_hours_start =
            read_env_parsed("WHOKNOCKED_OFF_HOURS_START", DEFAULT_OFF_HOURS_START)?;
        let off_hours_end = read_env_parsed("WHOKNOCKED_OFF_HOURS_END", DEFAULT_OFF_HOURS_END)?;

        let config = DetectorConfig {
            brute_min_failures,
            window: Duration::from_secs(window_minutes.saturating_mul(60)),
            spray_min_users,
            spray_max_per_user: DEFAULT_SPRAY_MAX_PER_USER,
            failures_before_success: DEFAULT_FAILURES_BEFORE_SUCCESS,
            off_hours_start,
            off_hours_end,
        };

        config.validate()?;
        Ok(config)
    }

    /// Reject nonsensical thresholds early, before any analysis runs.
    fn validate(&self) -> Result<()> {
        if self.brute_min_failures == 0 {
            anyhow::bail!("brute-force threshold must be at least 1");
        }
        if self.spray_min_users == 0 {
            anyhow::bail!("spray threshold must be at least 1");
        }
        if self.window.is_zero() {
            anyhow::bail!("detection window must be greater than zero minutes");
        }
        if self.off_hours_start > 23 || self.off_hours_end > 23 {
            anyhow::bail!("off-hours start/end must be hours between 0 and 23");
        }
        Ok(())
    }
}

/// Choose a `u32`: CLI flag if present, else env var if set, else default.
fn pick_u32(cli_value: Option<u32>, env_key: &str, default: u32) -> Result<u32> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    read_env_parsed(env_key, default)
}

/// Choose a `u64`: CLI flag if present, else env var if set, else default.
fn pick_u64(cli_value: Option<u64>, env_key: &str, default: u64) -> Result<u64> {
    if let Some(value) = cli_value {
        return Ok(value);
    }
    read_env_parsed(env_key, default)
}

/// Read and parse an environment variable, falling back to `default`.
///
/// A malformed value is a configuration error and is reported, not silently
/// ignored.
fn read_env_parsed<T>(env_key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    match std::env::var(env_key) {
        Ok(raw) => raw
            .trim()
            .parse::<T>()
            .map_err(|err| anyhow!("invalid value for {env_key}: {raw:?} ({err})")),
        Err(_) => Ok(default),
    }
}
