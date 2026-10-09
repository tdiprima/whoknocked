# Changelog

## v0.4.0

- Renamed the project from LogHound to **whoknocked**. The binary and all
  `LOGHOUND_*` environment variables are now `whoknocked` / `WHOKNOCKED_*`.
- Color output with `--color auto|always|never`; honors `NO_COLOR`.
- Restored the bundled `examples/sample-auth.log` so `cargo test` and the
  no-root demo work again.
- Prebuilt release binaries for Linux (x86_64, aarch64) and macOS, plus an
  `install.sh` one-liner.
- GitHub Actions CI (fmt, clippy, tests, MSRV check).
