# Contributing to whoknocked

Thanks for stopping by. The best contributions are new detectors, new log
formats, and real-world logs that broke the parser.

## Ground rules

- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`
  must pass. CI runs all three.
- Detectors are pure functions of `&[AuthEvent]`. No I/O inside a detector.
- Every detector ships with unit tests. Use the fixtures in
  `src/detections/mod.rs` (`test_support`) to build events in one line.
- Prefer fewer, higher-confidence findings over noise. A finding should tell
  the reader what happened, where it came from, and what to do next.

## Adding a detector in five minutes

1. Copy `src/detections/root_login.rs` to `src/detections/your_rule.rs`.
2. Implement `Detection`: a `name()` and an `analyze(&self, events)` that
   returns `Vec<Finding>`. Pick a `Severity`: `High` means "act now",
   `Medium` means "look today", `Normal` means "for your information".
3. Register it in `all_detectors()` in `src/detections/mod.rs`.
4. If it needs a threshold, add a field to `DetectorConfig` in
   `src/config.rs` with a default and a `WHOKNOCKED_*` environment variable.
5. Add a line to the "What it detects" list in `README.md`.

If the sample log in `examples/sample-auth.log` should trigger your rule,
extend the story there and update the expected output in the README.

## Detector ideas

- Impossible travel: the same user from two countries minutes apart (needs
  `--enrich`).
- Successful login with a password when the user normally uses a key.
- `sudo` failures ("3 incorrect password attempts").
- A new username appearing in successful logins for the first time.
- Session durations that are unusually long or short.
- Known-bad usernames (`admin`, `oracle`, `pi`) succeeding at all.

## Supporting another log format

`src/parser.rs` holds every regex. Add a pattern, a test with a real log line,
and a short note in the module docs. Anonymize IPs and hostnames in fixtures.

## Reporting a parsing miss

Open an issue with the raw line (anonymized) and what you expected. That is
the single most useful bug report this project can get.
