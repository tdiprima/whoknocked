//! Optional context for source IPs: country, network owner, hostname.
//!
//! Enabled with `--enrich`. Lookups go to ipinfo.io over HTTPS, which works
//! without an API key for light use. Private and loopback addresses are
//! never sent anywhere; they are labeled locally.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// What we know about a source address.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl IpInfo {
    /// One-line summary for the text report, e.g. `🇳🇱 NL · AS1234 Example · host`.
    pub fn one_line(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(country) = &self.country {
            let place = match &self.city {
                Some(city) => format!("{} {country}, {city}", flag(country)),
                None => format!("{} {country}", flag(country)),
            };
            parts.push(place);
        }
        if let Some(org) = &self.org {
            parts.push(org.clone());
        }
        if let Some(hostname) = &self.hostname {
            parts.push(hostname.clone());
        }
        parts.join(" \u{00B7} ")
    }
}

/// Regional-indicator flag emoji for a two-letter country code.
fn flag(country: &str) -> String {
    let code = country.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return String::new();
    }
    code.bytes()
        .filter_map(|b| char::from_u32(0x1F1E6 + u32::from(b - b'A')))
        .collect()
}

/// Whether an address is private, loopback, or otherwise not worth asking about.
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) // CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local
        }
    }
}

/// Look up one address. Returns `None` when the lookup fails; the report
/// simply omits the extra line in that case.
pub fn lookup(ip: IpAddr) -> Option<IpInfo> {
    if is_internal(ip) {
        return Some(IpInfo {
            org: Some("private network".to_string()),
            ..IpInfo::default()
        });
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(LOOKUP_TIMEOUT))
        .user_agent(concat!("whoknocked/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();

    let url = format!("https://ipinfo.io/{ip}/json");
    match agent.get(&url).call() {
        Ok(mut response) => match response.body_mut().read_json::<IpInfo>() {
            Ok(info) => Some(info),
            Err(error) => {
                log::warn!("could not parse enrichment for {ip}: {error}");
                None
            }
        },
        Err(error) => {
            log::warn!("enrichment lookup failed for {ip}: {error}");
            None
        }
    }
}

/// Look up many addresses, deduplicated, keeping only successful results.
pub fn lookup_many<I>(ips: I) -> HashMap<IpAddr, IpInfo>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut results = HashMap::new();
    for ip in ips {
        if results.contains_key(&ip) {
            continue;
        }
        if let Some(info) = lookup(ip) {
            results.insert(ip, info);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_addresses_are_labeled_without_network() {
        let info = lookup("10.0.0.5".parse().unwrap()).unwrap();
        assert_eq!(info.org.as_deref(), Some("private network"));
        assert!(lookup("fd00::1".parse().unwrap()).is_some());
    }

    #[test]
    fn flag_builds_regional_indicators() {
        assert_eq!(flag("nl"), "\u{1F1F3}\u{1F1F1}");
        assert_eq!(flag("USA"), "");
    }

    #[test]
    fn one_line_joins_known_parts() {
        let info = IpInfo {
            hostname: Some("host.example".into()),
            country: Some("NL".into()),
            city: None,
            org: Some("AS1 Example".into()),
        };
        assert_eq!(
            info.one_line(),
            "\u{1F1F3}\u{1F1F1} NL \u{00B7} AS1 Example \u{00B7} host.example"
        );
    }
}
