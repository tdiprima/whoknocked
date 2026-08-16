//! Detect the Linux distribution family and pick the correct auth log file.
//!
//! Debian-family systems (Ubuntu, Debian) log SSH/sudo activity to
//! `/var/log/auth.log`. RHEL-family systems (RHEL, Rocky, AlmaLinux,
//! CentOS, Fedora, Oracle Linux) use `/var/log/secure` instead.
//!
//! Detection reads `/etc/os-release`, the freedesktop-standard file present
//! on every modern distribution. The parsing itself is a pure function so it
//! can be unit-tested without touching the filesystem.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

const OS_RELEASE_PATH: &str = "/etc/os-release";
const DEBIAN_AUTH_LOG: &str = "/var/log/auth.log";
const RHEL_AUTH_LOG: &str = "/var/log/secure";

/// The family of distributions that share an auth log location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroFamily {
    /// Ubuntu, Debian, and derivatives. Logs to `/var/log/auth.log`.
    Debian,
    /// RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle Linux. Logs to
    /// `/var/log/secure`.
    Rhel,
}

impl DistroFamily {
    /// The default authentication log path for this family.
    pub fn auth_log_path(self) -> &'static str {
        match self {
            DistroFamily::Debian => DEBIAN_AUTH_LOG,
            DistroFamily::Rhel => RHEL_AUTH_LOG,
        }
    }

    /// A human-friendly name for reports and error messages.
    pub fn display_name(self) -> &'static str {
        match self {
            DistroFamily::Debian => "Debian/Ubuntu",
            DistroFamily::Rhel => "RHEL/Rocky",
        }
    }
}

// `ID` / `ID_LIKE` values that map to each family. Kept as data so adding a
// new distribution is a one-line change.
const DEBIAN_IDS: &[&str] = &["ubuntu", "debian"];
const RHEL_IDS: &[&str] = &[
    "rhel",
    "rocky",
    "almalinux",
    "centos",
    "fedora",
    "ol", // Oracle Linux
];

/// Detect the running distribution and return its default auth log path.
///
/// Returns an error if `/etc/os-release` cannot be read or the distribution
/// is unrecognized; the caller should then require an explicit `--file`.
pub fn default_log_path() -> Result<PathBuf> {
    let contents = std::fs::read_to_string(OS_RELEASE_PATH).with_context(|| {
        format!("cannot read {OS_RELEASE_PATH} to detect the Linux distribution")
    })?;

    let family = detect_family(&contents).ok_or_else(|| {
        anyhow!(
            "unrecognized Linux distribution in {OS_RELEASE_PATH}; \
             pass the log file explicitly with --file"
        )
    })?;

    log::info!(
        "detected {} system; using {}",
        family.display_name(),
        family.auth_log_path()
    );
    Ok(PathBuf::from(family.auth_log_path()))
}

/// Classify an `/etc/os-release` file body into a distribution family.
///
/// Pure function: no filesystem access, so it is fully unit-testable.
/// Both `ID` and `ID_LIKE` are consulted so derivatives (Linux Mint,
/// Pop!_OS, etc.) resolve to the right family via `ID_LIKE`.
pub fn detect_family(os_release: &str) -> Option<DistroFamily> {
    let ids = collect_distribution_ids(os_release);

    if ids.iter().any(|id| DEBIAN_IDS.contains(&id.as_str())) {
        return Some(DistroFamily::Debian);
    }
    if ids.iter().any(|id| RHEL_IDS.contains(&id.as_str())) {
        return Some(DistroFamily::Rhel);
    }
    None
}

/// Extract every distribution identifier from `ID` and `ID_LIKE` lines.
///
/// `ID_LIKE` may hold a space-separated list, and values may be quoted, e.g.
/// `ID_LIKE="rhel centos fedora"`. All tokens are lowercased for matching.
fn collect_distribution_ids(os_release: &str) -> Vec<String> {
    let mut ids = Vec::new();

    for line in os_release.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if key != "ID" && key != "ID_LIKE" {
            continue;
        }

        let cleaned = value.trim().trim_matches('"').trim_matches('\'');
        for token in cleaned.split_whitespace() {
            ids.push(token.to_ascii_lowercase());
        }
    }

    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ubuntu_from_id() {
        let os_release = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n";
        assert_eq!(detect_family(os_release), Some(DistroFamily::Debian));
    }

    #[test]
    fn detects_rocky_from_id() {
        let os_release = "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n";
        assert_eq!(detect_family(os_release), Some(DistroFamily::Rhel));
    }

    #[test]
    fn detects_rhel_family_via_id_like_only() {
        // A derivative whose own ID is unknown but ID_LIKE points at rhel.
        let os_release = "ID=customdistro\nID_LIKE=\"fedora\"\n";
        assert_eq!(detect_family(os_release), Some(DistroFamily::Rhel));
    }

    #[test]
    fn debian_maps_to_auth_log_and_rhel_to_secure() {
        assert_eq!(DistroFamily::Debian.auth_log_path(), "/var/log/auth.log");
        assert_eq!(DistroFamily::Rhel.auth_log_path(), "/var/log/secure");
    }

    #[test]
    fn unknown_distribution_returns_none() {
        let os_release = "ID=plan9\nID_LIKE=\"inferno\"\n";
        assert_eq!(detect_family(os_release), None);
    }

    #[test]
    fn empty_file_returns_none() {
        assert_eq!(detect_family(""), None);
    }
}
