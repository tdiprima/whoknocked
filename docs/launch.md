# Launch kit

Draft posts for each channel. Edit freely; the voice should be yours.
Post the Show HN and r/rust on a weekday morning US time, a day apart.

## Show HN

**Title:** Show HN: whoknocked – who tried to get into your SSH server, in one screen

**Text:**

I run a few Linux boxes and got tired of `grep "Failed password" /var/log/auth.log | wc -l`
telling me a number but not a story. whoknocked is a small Rust CLI that parses
the auth log (or the systemd journal, or stdin) and prints only what matters:
brute-force bursts, password sprays, and the one that keeps me up at night: a
wall of failures followed by a *successful* login, then `sudo cat /etc/shadow`.

It correlates across lines, so that last case comes out as a single finding
with the commands listed. There is a `--follow` mode that prints findings live,
`--json` for piping into jq or a webhook, and `--enrich` that adds country,
ASN, and hostname for the IPs in the report.

Single static binary, no daemon, no database, no agent. MIT.

Try it without root on the bundled attack story:
`cargo install whoknocked && whoknocked --file examples/sample-auth.log`

Happy to hear which detectors you would want next. Impossible travel is on
the list.

## r/rust

**Title:** whoknocked: a tiny Rust CLI that turns Linux auth logs into security findings

Built this to answer "did anyone get in?" without a SIEM. It parses
`auth.log` / `secure` / journald, runs seven pure detectors over the events,
and prints a short report with a Top sources table. Highlights for this crowd:

- Zero async. Blocking I/O, `std` only for file tailing, ureq for the one
  optional network call.
- Detectors are pure functions of `&[AuthEvent]`, so every rule is unit
  tested with no fixtures on disk. Adding one is a file plus a line in a vec.
- `--follow` re-runs the detectors over a rolling 24 h event buffer on each
  new line; it is fast enough that incremental state was not worth the
  complexity.
- Static musl binaries for Linux via GitHub Actions, `cargo install
  whoknocked` on crates.io.

Would love feedback on the detector design, and on parsing edge cases from
distros I do not run.

## r/selfhosted and r/homelab

**Title:** Made a one-binary tool that tells you who's been knocking on your SSH port

If you expose SSH (even behind a non-standard port) your auth log is full of
bots. whoknocked boils it down to: who, how hard, did they get in, and what
did they do after. Runs in milliseconds, no install beyond one binary.

```
curl -fsSL https://raw.githubusercontent.com/tdiprima/whoknocked/main/install.sh | sh
sudo whoknocked --enrich
```

`--follow` makes a nice always-on pane in tmux. `--json` feeds into
Home Assistant or a Discord webhook if you want a ping when something
actually succeeds. Not a replacement for fail2ban; it is the "what happened"
view fail2ban does not give you.

## This Week in Rust

Submit under "Crate of the Week" via the weekly thread on r/rust, or open a
PR against `rust-lang/this-week-in-rust` adding to the Updates section:

> * [whoknocked](https://github.com/tdiprima/whoknocked) - a tiny CLI that
>   turns Linux SSH/sudo auth logs into security findings: brute force,
>   sprays, and privileged commands after a suspicious login.

## Short blog post outline

1. The 3 a.m. question: "did they get in?"
2. Why `grep | wc -l` is the wrong tool (counts, not correlation).
3. The one finding that matters: failures, then success, then sudo.
4. How the detectors stay pure and testable.
5. What is next: impossible travel, key-vs-password drift, sudo failures.

## Checklist before posting

- [ ] Tag `v0.5.0` so release binaries exist and `install.sh` works.
- [ ] `cargo publish` so the crates.io badge and `cargo install` work.
- [ ] Upload `docs/social-preview.png` in repo Settings → Social preview.
- [ ] Pin the repo on your GitHub profile.
- [ ] Reply to every comment in the first two hours.
