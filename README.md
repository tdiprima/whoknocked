# LogHound

A tiny, local, SIEM-style analyzer for Linux authentication logs, written in Rust.

Point it at your SSH/sudo auth log and, instead of scrolling through thousands
of lines, LogHound turns the raw text into structured events, runs a small set
of detection rules, and shows you the **interesting** activity: brute-force
bursts, logins that succeed right after a wall of failures, and username sprays.

The emphasis is on *interesting*, not "everything is an attack". LogHound
raises the priority of anomalies and lets you decide.

```text
LOGHOUND
Authentication activity — /var/log/auth.log

Risk: ELEVATED ⚠️

        3   successful logins
       21   failed logins
       13   invalid users
        2   sudo events
        3   unique source IPs
       15   unique usernames

Interesting activity
────────────────────────────────────────────────────

🔴 09:14:02 Possible brute force
   Source:       45.20.13.8
   Failures:     12 (peak 12 within 5 min)
   First seen:   09:14:02
   Last seen:    09:18:00
   Users tried:  root (4), admin (3), backup (1), oracle (1), postgres (1), test (1), +1 more

🔴 09:18:47 Login after repeated failures
   User:      backup
   Source:    45.20.13.8
   12 failed attempts, then success after 47s
   Time:      09:18:47

   Recommendation:
   Investigate whether this source and login were expected.

🟡 10:02:01 Possible username/password spray
   Source IP:         45.20.10.2
   Accounts tried:    9
   Attempts/account:  1-1
   Duration:          109s
```

## Automatic log-file detection (Ubuntu vs. RHEL)

Different distributions write SSH/sudo activity to different files. LogHound
reads `/etc/os-release` and picks the right one for you:

| Distribution family                         | Auth log            |
| ------------------------------------------- | ------------------- |
| Ubuntu, Debian (and derivatives)            | `/var/log/auth.log` |
| RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle Linux | `/var/log/secure`   |

Detection uses both the `ID` and `ID_LIKE` fields in `/etc/os-release`, so
derivatives resolve to the correct family automatically. You can always
override the choice with `--file` (see below).

## Requirements

- **Rust** 1.74 or newer (install via [rustup](https://rustup.rs/)).
- A Linux host running **Ubuntu/Debian** or **RHEL/Rocky/AlmaLinux/CentOS/Fedora**.
- Permission to read the auth log. These files are usually restricted, so you
  will typically run LogHound with `sudo`, or as a user in the `adm` group
  (Debian/Ubuntu) or with the appropriate group on RHEL.

## Install

Clone and build a release binary:

```bash
git clone https://github.com/tdiprima/LogHound.git
cd LogHound
cargo build --release
```

The binary lands at `target/release/loghound`. Copy it somewhere on your
`PATH` if you like:

```bash
sudo install -m 0755 target/release/loghound /usr/local/bin/loghound
```

Or install straight from the source tree with Cargo:

```bash
cargo install --path .
```

## Usage

### Analyze the auto-detected log

```bash
sudo loghound
```

LogHound detects your distribution, reads the correct auth log, and prints the
summary plus any findings.

### Analyze a specific file

Handy for testing, for reading a copied/rotated log, or when auto-detection
can't help:

```bash
loghound --file /var/log/auth.log
loghound --file ./examples/sample-auth.log      # try it without sudo
```

### Filters

Filters narrow the events *before* the summary and detectors run.

```bash
loghound --failed                 # only failed / invalid-user events
loghound --user alex              # only events for user "alex"
loghound --ip 45.20.13.8          # only events from one source IP
loghound --since 2h               # only the last 2 hours (s / m / h / d)
loghound --summary-only           # counts only, skip the detection engine
```

Filters combine, so this shows failed logins for `root` in the last day:

```bash
loghound --failed --user root --since 1d
```

### All options

```text
Usage: loghound [OPTIONS]

Options:
  -f, --file <PATH>              Log file to analyze (overrides auto-detection)
      --failed                   Show only failed / invalid-user events
      --user <NAME>              Show only events for this username
      --ip <IP>                  Show only events from this source IP
      --since <DURATION>         Only events newer than this, e.g. 90m, 2h, 3d
      --summary-only             Print the summary only; skip detection
      --brute-threshold <N>      Brute-force threshold (default 10)
      --window-minutes <MINUTES> Detection window in minutes (default 5)
      --spray-threshold <N>      Spray threshold: distinct users (default 8)
  -h, --help                     Print help
  -V, --version                  Print version
```

## What it detects

Each detector receives the same list of events and independently answers
"anything interesting here?"

1. **Brute force** — at least *N* failed logins from one source IP inside the
   detection window (default: 10 failures / 5 minutes). Reports the IP, total
   and peak failure counts, time span, and which usernames were targeted.

2. **Login after repeated failures** — a *successful* login from an IP that just
   produced a burst of failures (default: 5+ within the window). A normal login
   is dull; this correlation is not, so it is flagged **High**.

3. **Username / password spray** — one source IP touching many distinct
   accounts with only a couple of tries each (default: 8+ users, ≤3 per user).
   This "low and slow" pattern is different from hammering a single account.

Findings are sorted most-severe first and rendered with a risk indicator:
🔴 High, 🟡 Medium, 🟢 Normal.

## Configuration

Every threshold has a sane default and can be set two ways. Precedence, lowest
to highest: **built-in default → environment variable → command-line flag.**

| Setting                  | CLI flag             | Environment variable          | Default |
| ------------------------ | -------------------- | ----------------------------- | ------- |
| Brute-force min failures | `--brute-threshold`  | `LOGHOUND_BRUTE_MIN_FAILURES` | `10`    |
| Detection window (min)   | `--window-minutes`   | `LOGHOUND_WINDOW_MINUTES`     | `5`     |
| Spray min distinct users | `--spray-threshold`  | `LOGHOUND_SPRAY_MIN_USERS`    | `8`     |
| Default log file         | `--file`             | `LOGHOUND_FILE`               | auto    |

Example — make the brute-force rule more sensitive for one run:

```bash
LOGHOUND_BRUTE_MIN_FAILURES=5 loghound
# or
loghound --brute-threshold 5 --window-minutes 10
```

### Logging

Diagnostic logging is controlled by `RUST_LOG` and goes to **stderr**, keeping
the report itself clean on stdout. Normal runs are quiet (warnings only).

```bash
RUST_LOG=info loghound --file ./examples/sample-auth.log
```

## A note on timestamps

Traditional syslog lines (`Aug 16 09:17:21 ...`) do not include a year.
LogHound assumes the current year and automatically rolls a timestamp back a
year if it would otherwise land in the future — so logs written in December and
read in January are dated correctly.

## Development

Run the full test suite (unit tests for the parser, detectors, config, and
filters, plus end-to-end tests that run the binary against
`examples/sample-auth.log`):

```bash
cargo test
```

Try it end to end without root using the bundled sample:

```bash
cargo run -- --file ./examples/sample-auth.log
```

### Project layout

```text
src/
├── main.rs          Orchestration only: wire the pieces together
├── cli.rs           Argument definitions and --since validation
├── config.rs        Detector thresholds (defaults → env → flags)
├── os_detect.rs     Distribution detection → auth log path
├── loader.rs        File I/O, year correction, and view filters
├── parser.rs        Raw syslog line → structured AuthEvent
├── event.rs         AuthEvent and EventType definitions
├── summary.rs       Aggregate counts
├── finding.rs       Finding and Severity types
├── report.rs        Human-readable report rendering
└── detections/
    ├── mod.rs                    Detection trait + registry
    ├── brute_force.rs            Detection #1
    ├── login_after_failures.rs   Detection #2 (correlation)
    └── password_spray.rs         Detection #3
```

The parsing and detection logic is pure (no I/O), so it is fully unit-testable
without elevated privileges. All filesystem access is isolated in `loader.rs`
and `os_detect.rs`.

### Adding a new detector

1. Create `src/detections/your_rule.rs` implementing the `Detection` trait.
2. Register it in `all_detectors()` in `src/detections/mod.rs`.

That's the only wiring required.

## License

[MIT](LICENSE) © 2026 Tammy DiPrima

<br>
