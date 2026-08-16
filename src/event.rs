//! Structured representation of a single authentication event.
//!
//! Raw log lines are ugly strings. Everything downstream (summaries,
//! detectors, reports) works on these typed values instead, so the messy
//! string parsing stays in one place: `parser.rs`.

use chrono::NaiveDateTime;
use std::net::IpAddr;

/// The kind of authentication event a log line represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    LoginSuccess,
    LoginFailure,
    InvalidUser,
    Sudo,
    SessionOpened,
    SessionClosed,
}

impl EventType {
    /// A failed attempt to authenticate (a real user with a bad password,
    /// or an attempt against a username that does not exist).
    pub fn is_failure(self) -> bool {
        matches!(self, EventType::LoginFailure | EventType::InvalidUser)
    }

    /// A successful interactive login.
    pub fn is_success(self) -> bool {
        matches!(self, EventType::LoginSuccess)
    }
}

/// One authentication event parsed from a single log line.
///
/// Fields are `Option` because not every log line carries every detail
/// (a `session closed` line has no source IP, for example).
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub timestamp: NaiveDateTime,
    pub event_type: EventType,
    pub username: Option<String>,
    pub source_ip: Option<IpAddr>,
    #[allow(dead_code)]
    pub port: Option<u16>,
    /// The command for `sudo` events; `None` for everything else.
    #[allow(dead_code)]
    pub command: Option<String>,
    /// The original log line, kept for timeline/detail views.
    #[allow(dead_code)]
    pub raw: String,
}
