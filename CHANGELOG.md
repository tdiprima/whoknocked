# Changelog

## v0.5.0

- Four new detectors: **privileged commands after a suspicious login** (sudo
  correlated back to a brute-forced SSH session), **direct root login**,
  **login from a new source** for a known user, and **off-hours login**
  (`WHOKNOCKED_OFF_HOURS_START` / `_END`).
- **systemd journal support.** `--journal` reads sshd/sshd-session/sudo
  entries via `journalctl`; auto-detection falls back to it when the
  distribution's log file is missing. `--file -` reads stdin.
- **`--follow`** live mode: prints new findings as they happen, survives
  logrotate, and emits JSON lines with `--json`.
- **`--enrich`**: country, city, ASN/org, and hostname for source IPs via
  ipinfo.io, shown in the Top sources table and on each finding.
- **Top sources** table in every report (`--top N`, default 5).
- **`--json`** output for the full report.

## v0.4.0

- Renamed the project from LogHound to **whoknocked**. The binary and all
  `LOGHOUND_*` environment variables are now `whoknocked` / `WHOKNOCKED_*`.
- Color output with `--color auto|always|never`; honors `NO_COLOR`.
- Restored the bundled `examples/sample-auth.log` so `cargo test` and the
  no-root demo work again.
- Prebuilt release binaries for Linux (x86_64, aarch64) and macOS, plus an
  `install.sh` one-liner.
- GitHub Actions CI (fmt, clippy, tests, MSRV check).
