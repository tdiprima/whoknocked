//! `--follow`: keep reading new lines and print findings as they appear.
//!
//! The strategy is deliberately simple: keep a rolling buffer of recent
//! events, re-run the (fast, pure) detectors after each new event, and print
//! any finding whose identity has not been printed before. A finding's
//! identity is its title, source IP, user, and anchor timestamp, which stay
//! stable as a burst grows.

use crate::attackers;
use crate::cli::Args;
use crate::config::DetectorConfig;
use crate::detections::{self, Detection};
use crate::enrich::{self, IpInfo};
use crate::event::AuthEvent;
use crate::finding::Finding;
use crate::loader;
use crate::report;
use crate::source::{JournalStream, LogSource};
use anyhow::{Context, Result};
use chrono::{Duration, Local, NaiveDateTime};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

/// Events older than this (relative to the newest event) are dropped from
/// the rolling buffer. Measured against event time, not the wall clock, so
/// replaying an old log still works.
const RETENTION: Duration = Duration::hours(24);
/// How often to poll a file for new bytes.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Identity of a finding, used to avoid printing the same one twice.
type FindingKey = (
    String,
    Option<IpAddr>,
    Option<String>,
    Option<NaiveDateTime>,
);

fn key_of(finding: &Finding) -> FindingKey {
    (
        finding.title.clone(),
        finding.source_ip,
        finding.username.clone(),
        finding.timestamp,
    )
}

/// Live state for follow mode.
pub struct Follower<'a> {
    args: &'a Args,
    detectors: Vec<Box<dyn Detection>>,
    events: Vec<AuthEvent>,
    seen: HashSet<FindingKey>,
    info_cache: HashMap<IpAddr, IpInfo>,
    color: bool,
}

impl<'a> Follower<'a> {
    /// Start from the events and findings already reported, so only new
    /// activity is printed from here on.
    pub fn new(
        args: &'a Args,
        config: DetectorConfig,
        initial_events: Vec<AuthEvent>,
        already_reported: &[Finding],
        color: bool,
    ) -> Self {
        Follower {
            args,
            detectors: detections::all_detectors(config),
            events: initial_events,
            seen: already_reported.iter().map(key_of).collect(),
            info_cache: HashMap::new(),
            color,
        }
    }

    /// Block, printing new findings until the source ends or Ctrl-C.
    pub fn run(&mut self, source: &LogSource) -> Result<()> {
        if !self.args.json {
            println!(
                "\n\u{1F440} Watching {} for new activity (Ctrl-C to stop)\u{2026}\n",
                source.label()
            );
        }

        match source {
            LogSource::File(path) => self.tail_file(path),
            LogSource::Stdin => {
                let stdin = std::io::stdin();
                self.consume(stdin.lock())
            }
            LogSource::Journal => self.consume(JournalStream::spawn(true)?),
        }
    }

    /// Feed every line from a reader until EOF.
    fn consume<R: BufRead>(&mut self, reader: R) -> Result<()> {
        for line in reader.lines() {
            let line = line.context("error reading live input")?;
            self.ingest(&line)?;
        }
        Ok(())
    }

    /// Tail a file from its current end, surviving truncation and rotation.
    fn tail_file(&mut self, path: &Path) -> Result<()> {
        let mut file =
            File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mut position = file.seek(SeekFrom::End(0))?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();

        loop {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read > 0 {
                position += read as u64;
                self.ingest(line.trim_end_matches(['\n', '\r']))?;
                continue;
            }

            // At EOF: check for truncation or logrotate, then wait.
            if let Some(new_file) =
                reopen_if_rotated(path, &reader.get_ref().metadata()?, position)?
            {
                reader = BufReader::new(new_file);
                position = 0;
                continue;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Parse one line, apply the view filters, and report anything new.
    fn ingest(&mut self, line: &str) -> Result<()> {
        let now = Local::now().naive_local();
        let event = match loader::parse_event(line, now) {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(()),
            Err(error) => {
                log::warn!("skipping line: {error}");
                return Ok(());
            }
        };

        let mut kept = loader::filter_events(vec![event], self.args, now)?;
        let Some(event) = kept.pop() else {
            return Ok(());
        };

        let cutoff = event.timestamp - RETENTION;
        self.events.push(event);
        self.events.retain(|e| e.timestamp >= cutoff);

        let mut findings = detections::run_all(&self.detectors, &self.events);
        report::sort_findings(&mut findings);

        for finding in findings {
            if !self.seen.insert(key_of(&finding)) {
                continue;
            }
            self.emit(&finding);
        }
        Ok(())
    }

    /// Print a single new finding in text or JSON form.
    fn emit(&mut self, finding: &Finding) {
        let info = match (self.args.enrich, finding.source_ip) {
            (true, Some(ip)) => {
                if let std::collections::hash_map::Entry::Vacant(slot) = self.info_cache.entry(ip) {
                    if let Some(found) = enrich::lookup(ip) {
                        slot.insert(found);
                    }
                }
                self.info_cache.get(&ip).cloned()
            }
            _ => None,
        };

        if self.args.json {
            let sources = attackers::top_sources(&self.events, self.args.top);
            let line = report::finding_json_line(finding, info.as_ref(), &sources);
            println!("{line}");
        } else {
            let stamp = Local::now().format("%H:%M:%S");
            let text = report::render_finding(finding, info.as_ref(), self.color);
            println!("[{stamp}] {text}");
        }
    }
}

/// If the file at `path` has been truncated or replaced, reopen it.
fn reopen_if_rotated(
    path: &Path,
    open_meta: &std::fs::Metadata,
    position: u64,
) -> Result<Option<File>> {
    let Ok(current) = std::fs::metadata(path) else {
        // Rotated away and not yet recreated; try again next poll.
        return Ok(None);
    };

    let truncated = current.len() < position;
    let replaced = !same_file(open_meta, &current);
    if truncated || replaced {
        log::info!("{} rotated or truncated; reopening", path.display());
        let file = File::open(path).with_context(|| format!("cannot reopen {}", path.display()))?;
        return Ok(Some(file));
    }
    Ok(None)
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.ino() == b.ino() && a.dev() == b.dev()
}

#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    true
}
