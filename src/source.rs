//! Where auth events come from: a log file, stdin, or the systemd journal.
//!
//! Resolution order: `--journal`, then `--file` (`-` means stdin), then the
//! `WHOKNOCKED_FILE` environment variable, then auto-detection. Auto-detection
//! picks the distribution's log file, and falls back to `journalctl` when
//! that file does not exist (Fedora, Arch, and many RHEL hosts no longer
//! write `/var/log/secure` without rsyslog installed).

use crate::cli::Args;
use crate::loader;
use crate::os_detect;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Environment variable that overrides the auto-detected log file path.
const LOG_FILE_ENV: &str = "WHOKNOCKED_FILE";

/// Syslog identifiers that carry authentication events in the journal.
/// `sshd-session` is what OpenSSH 9.8+ logs under.
const JOURNAL_IDENTIFIERS: &[&str] = &["sshd", "sshd-session", "sudo"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    File(PathBuf),
    Stdin,
    Journal,
}

impl LogSource {
    /// Decide where to read from, following the documented precedence.
    pub fn resolve(args: &Args) -> Result<Self> {
        if args.journal {
            return Ok(LogSource::Journal);
        }

        if let Some(path) = &args.file {
            if path.as_os_str() == "-" {
                return Ok(LogSource::Stdin);
            }
            return Ok(LogSource::File(path.clone()));
        }

        if let Ok(from_env) = std::env::var(LOG_FILE_ENV) {
            let trimmed = from_env.trim();
            if !trimmed.is_empty() {
                return Ok(LogSource::File(PathBuf::from(trimmed)));
            }
        }

        match os_detect::default_log_path() {
            Ok(path) if path.exists() => Ok(LogSource::File(path)),
            Ok(path) => {
                if journalctl_available() {
                    log::info!("{} not found; reading the systemd journal", path.display());
                    Ok(LogSource::Journal)
                } else {
                    anyhow::bail!(
                        "{} does not exist and journalctl is not available; pass --file",
                        path.display()
                    )
                }
            }
            Err(error) => {
                if journalctl_available() {
                    log::info!("{error:#}; falling back to the systemd journal");
                    Ok(LogSource::Journal)
                } else {
                    Err(error).context("could not determine the log source; pass --file")
                }
            }
        }
    }

    /// Human-readable name for the report header.
    pub fn label(&self) -> String {
        match self {
            LogSource::File(path) => path.display().to_string(),
            LogSource::Stdin => "stdin".to_string(),
            LogSource::Journal => "systemd journal (journalctl)".to_string(),
        }
    }

    /// Open the source for a one-shot read of everything available now.
    pub fn open(&self) -> Result<Box<dyn BufRead>> {
        match self {
            LogSource::File(path) => {
                loader::validate_readable(path)?;
                let file =
                    File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
                Ok(Box::new(BufReader::new(file)))
            }
            LogSource::Stdin => Ok(Box::new(BufReader::new(std::io::stdin()))),
            LogSource::Journal => Ok(Box::new(JournalStream::spawn(false)?)),
        }
    }
}

/// Whether `journalctl` can be executed on this host.
fn journalctl_available() -> bool {
    Command::new("journalctl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// A running `journalctl` whose stdout is read line by line.
///
/// Output format `short` is the classic syslog layout the parser expects.
pub struct JournalStream {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl JournalStream {
    /// Start `journalctl`. With `follow`, it tails new entries only.
    pub fn spawn(follow: bool) -> Result<Self> {
        let mut command = Command::new("journalctl");
        command.args(["-o", "short", "-q", "--no-pager"]);
        for identifier in JOURNAL_IDENTIFIERS {
            command.args(["-t", identifier]);
        }
        if follow {
            command.args(["-f", "-n", "0"]);
        }

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("cannot run journalctl (is systemd-journald in use here?)")?;
        let stdout = child
            .stdout
            .take()
            .context("journalctl produced no stdout pipe")?;

        Ok(JournalStream {
            child,
            stdout: BufReader::new(stdout),
        })
    }
}

impl Read for JournalStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl BufRead for JournalStream {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.stdout.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.stdout.consume(amt)
    }
}

impl Drop for JournalStream {
    fn drop(&mut self) {
        // Reap the child so a Ctrl-C in follow mode leaves no zombie behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ColorMode;

    fn args() -> Args {
        Args {
            file: None,
            journal: false,
            follow: false,
            enrich: false,
            json: false,
            top: 5,
            failed: false,
            user: None,
            ip: None,
            since: None,
            summary_only: false,
            brute_threshold: None,
            window_minutes: None,
            spray_threshold: None,
            color: ColorMode::Auto,
        }
    }

    #[test]
    fn dash_means_stdin() {
        let mut a = args();
        a.file = Some(PathBuf::from("-"));
        assert_eq!(LogSource::resolve(&a).unwrap(), LogSource::Stdin);
    }

    #[test]
    fn journal_flag_wins() {
        let mut a = args();
        a.journal = true;
        assert_eq!(LogSource::resolve(&a).unwrap(), LogSource::Journal);
    }

    #[test]
    fn explicit_file_is_used_verbatim() {
        let mut a = args();
        a.file = Some(PathBuf::from("/tmp/x.log"));
        assert_eq!(
            LogSource::resolve(&a).unwrap(),
            LogSource::File(PathBuf::from("/tmp/x.log"))
        );
    }
}
