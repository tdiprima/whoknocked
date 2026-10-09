//! Turn raw syslog auth lines into structured [`AuthEvent`] values.
//!
//! Both Debian's `/var/log/auth.log` and RHEL's `/var/log/secure` use the
//! traditional BSD syslog line format written by `sshd` and `sudo`:
//!
//! ```text
//! Aug 16 09:17:21 server sshd[18321]: Failed password for root from 192.0.2.44 port 51234 ssh2
//! ```
//!
//! The traditional format has no year, so the caller supplies the assumed
//! year. Parsing is pure (no I/O), which keeps it easy to test.

use crate::event::{AuthEvent, EventType};
use anyhow::{anyhow, Result};
use chrono::NaiveDateTime;
use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Parse one log line into an [`AuthEvent`].
///
/// Returns `Ok(None)` for lines that are valid syslog but not an auth event
/// we care about (e.g. `sshd` connection-closed noise). Returns `Err` only
/// when a line looks like an auth event but its timestamp cannot be parsed.
pub fn parse_line(line: &str, assumed_year: i32) -> Result<Option<AuthEvent>> {
    let Some(parts) = split_syslog_line(line) else {
        return Ok(None);
    };

    // Only sshd and sudo lines carry authentication events.
    let is_sshd = parts.process.starts_with("sshd");
    let is_sudo = parts.process.starts_with("sudo");
    if !is_sshd && !is_sudo {
        return Ok(None);
    }

    let Some(parsed) = classify_message(parts.message, is_sudo) else {
        return Ok(None);
    };

    let timestamp = parse_timestamp(parts.month, parts.day, parts.time, assumed_year)?;

    Ok(Some(AuthEvent {
        timestamp,
        event_type: parsed.event_type,
        username: parsed.username,
        source_ip: parsed.source_ip,
        port: parsed.port,
        command: parsed.command,
        raw: line.to_string(),
    }))
}

/// The fixed syslog prefix fields, plus the free-form message body.
struct SyslogParts<'a> {
    month: &'a str,
    day: &'a str,
    time: &'a str,
    process: &'a str,
    message: &'a str,
}

/// Split a syslog line into its timestamp, process, and message parts.
///
/// Returns `None` if the line does not match the expected shape at all.
fn split_syslog_line(line: &str) -> Option<SyslogParts<'_>> {
    let captures = syslog_prefix_regex().captures(line)?;

    Some(SyslogParts {
        month: captures.name("mon")?.as_str(),
        day: captures.name("day")?.as_str(),
        time: captures.name("time")?.as_str(),
        process: captures.name("proc")?.as_str(),
        message: captures.name("msg")?.as_str(),
    })
}

/// The event details extracted from a message body.
struct ParsedMessage {
    event_type: EventType,
    username: Option<String>,
    source_ip: Option<IpAddr>,
    port: Option<u16>,
    command: Option<String>,
}

/// Match a message body against the known sshd/sudo patterns.
///
/// Patterns are tried most-specific first (invalid-user before generic
/// failure) so a line is never misclassified by an over-broad rule.
fn classify_message(message: &str, is_sudo: bool) -> Option<ParsedMessage> {
    if is_sudo {
        return classify_sudo(message);
    }

    if let Some(caps) = re_failed_invalid().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::InvalidUser,
            username: named(&caps, "user"),
            source_ip: named_ip(&caps, "ip"),
            port: named_port(&caps, "port"),
            command: None,
        });
    }

    if let Some(caps) = re_failed().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::LoginFailure,
            username: named(&caps, "user"),
            source_ip: named_ip(&caps, "ip"),
            port: named_port(&caps, "port"),
            command: None,
        });
    }

    if let Some(caps) = re_accepted().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::LoginSuccess,
            username: named(&caps, "user"),
            source_ip: named_ip(&caps, "ip"),
            port: named_port(&caps, "port"),
            command: None,
        });
    }

    if let Some(caps) = re_invalid_user().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::InvalidUser,
            username: named(&caps, "user"),
            source_ip: named_ip(&caps, "ip"),
            port: None,
            command: None,
        });
    }

    if let Some(caps) = re_session_opened().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::SessionOpened,
            username: named(&caps, "user"),
            source_ip: None,
            port: None,
            command: None,
        });
    }

    if let Some(caps) = re_session_closed().captures(message) {
        return Some(ParsedMessage {
            event_type: EventType::SessionClosed,
            username: named(&caps, "user"),
            source_ip: None,
            port: None,
            command: None,
        });
    }

    None
}

/// Match a `sudo` message body, e.g. `alex : ... COMMAND=/usr/bin/vim ...`.
fn classify_sudo(message: &str) -> Option<ParsedMessage> {
    let caps = re_sudo().captures(message)?;
    Some(ParsedMessage {
        event_type: EventType::Sudo,
        username: named(&caps, "user"),
        source_ip: None,
        port: None,
        command: named(&caps, "cmd").map(|value| value.trim().to_string()),
    })
}

/// Build a `NaiveDateTime` from syslog's yearless month/day/time fields.
fn parse_timestamp(month: &str, day: &str, time: &str, year: i32) -> Result<NaiveDateTime> {
    // `%d` accepts one- or two-digit days, which is what `split_whitespace`
    // produces, so single-digit days like "Aug  6" parse cleanly.
    let candidate = format!("{year} {month} {day} {time}");
    NaiveDateTime::parse_from_str(&candidate, "%Y %b %d %H:%M:%S")
        .map_err(|err| anyhow!("unparseable timestamp {candidate:?}: {err}"))
}

// --- Capture-group helpers -------------------------------------------------

fn named(caps: &regex::Captures, name: &str) -> Option<String> {
    caps.name(name).map(|m| m.as_str().to_string())
}

fn named_ip(caps: &regex::Captures, name: &str) -> Option<IpAddr> {
    caps.name(name)
        .and_then(|m| m.as_str().parse::<IpAddr>().ok())
}

fn named_port(caps: &regex::Captures, name: &str) -> Option<u16> {
    caps.name(name).and_then(|m| m.as_str().parse::<u16>().ok())
}

// --- Lazily compiled regexes ----------------------------------------------
//
// Each pattern is a compile-time constant, so `expect` here only fires if a
// developer edits the pattern into something invalid — it is not reachable
// from external input.

fn syslog_prefix_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<proc>[\w./-]+(?:\[\d+\])?):\s+(?P<msg>.*)$",
        )
        .expect("syslog prefix regex is valid")
    })
}

fn re_failed_invalid() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
        )
        .expect("failed-invalid regex is valid")
    })
}

fn re_failed() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^Failed password for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
        )
        .expect("failed regex is valid")
    })
}

fn re_accepted() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^Accepted \w+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
        )
        .expect("accepted regex is valid")
    })
}

fn re_invalid_user() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
            .expect("invalid-user regex is valid")
    })
}

fn re_session_opened() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"session opened for user (?P<user>[\w.$-]+)")
            .expect("session-opened regex is valid")
    })
}

fn re_session_closed() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"session closed for user (?P<user>[\w.$-]+)")
            .expect("session-closed regex is valid")
    })
}

fn re_sudo() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*(?P<user>[\w.$-]+)\s+:.*COMMAND=(?P<cmd>.+)$")
            .expect("sudo regex is valid")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const YEAR: i32 = 2026;

    fn parse(line: &str) -> Option<AuthEvent> {
        parse_line(line, YEAR).expect("line should parse without timestamp error")
    }

    #[test]
    fn parses_failed_password_for_valid_user() {
        let event = parse(
            "Aug 16 09:17:24 server sshd[18323]: Failed password for root from 192.0.2.44 port 51234 ssh2",
        )
        .expect("should be an event");
        assert_eq!(event.event_type, EventType::LoginFailure);
        assert_eq!(event.username.as_deref(), Some("root"));
        assert_eq!(event.source_ip.unwrap().to_string(), "192.0.2.44");
        assert_eq!(event.port, Some(51234));
    }

    #[test]
    fn parses_failed_password_for_invalid_user() {
        let event = parse(
            "Aug 16 09:17:21 server sshd[18321]: Failed password for invalid user admin from 192.0.2.44 port 51231 ssh2",
        )
        .expect("should be an event");
        assert_eq!(event.event_type, EventType::InvalidUser);
        assert_eq!(event.username.as_deref(), Some("admin"));
    }

    #[test]
    fn parses_accepted_publickey() {
        let event = parse(
            "Aug 16 09:19:03 server sshd[18401]: Accepted publickey for backup from 192.0.2.44 port 51442 ssh2",
        )
        .expect("should be an event");
        assert_eq!(event.event_type, EventType::LoginSuccess);
        assert_eq!(event.username.as_deref(), Some("backup"));
    }

    #[test]
    fn parses_single_digit_day() {
        let event = parse(
            "Aug  6 03:14:00 server sshd[10]: Accepted password for alex from 10.0.0.5 port 2200 ssh2",
        )
        .expect("should be an event");
        assert_eq!(event.timestamp.format("%m-%d").to_string(), "08-06");
    }

    #[test]
    fn parses_sudo_command() {
        let event = parse(
            "Aug 16 10:21:00 server sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/vim /etc/ssh/sshd_config",
        )
        .expect("should be an event");
        assert_eq!(event.event_type, EventType::Sudo);
        assert_eq!(event.username.as_deref(), Some("alex"));
        assert_eq!(
            event.command.as_deref(),
            Some("/usr/bin/vim /etc/ssh/sshd_config")
        );
    }

    #[test]
    fn parses_ipv6_source() {
        let event = parse(
            "Aug 16 09:00:00 server sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2",
        )
        .expect("should be an event");
        assert_eq!(event.source_ip.unwrap().to_string(), "2001:db8::1");
    }

    #[test]
    fn ignores_unrelated_process() {
        // Only sshd and sudo lines are auth events; cron and systemd are noise.
        assert!(parse(
            "Aug 16 09:00:00 server CRON[999]: pam_unix(cron:session): session opened for user root"
        )
        .is_none());
        assert!(
            parse("Aug 16 09:00:00 server systemd[1]: Started Session 5 of user alex.").is_none()
        );
    }

    #[test]
    fn ignores_empty_and_malformed_lines() {
        assert!(parse("").is_none());
        assert!(parse("not a syslog line at all").is_none());
        assert!(parse("Aug 16 sshd broken").is_none());
    }

    #[test]
    fn reports_error_on_bad_timestamp() {
        // Valid prefix shape and a real auth message, but an impossible month.
        let result = parse_line(
            "Zzz 16 09:17:24 server sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
            YEAR,
        );
        // "Zzz" fails the [A-Z][a-z]{2} month word? It matches the shape, so
        // the timestamp parse must fail and surface an error.
        assert!(result.is_err());
    }
}
