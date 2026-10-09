//! End-to-end tests that run the compiled binary against the sample log.
//!
//! These exercise the whole pipeline (path -> parse -> detect -> report)
//! without needing root, by pointing `--file` at a fixture in `examples/`.

use std::process::Command;

/// Path to the binary Cargo built for this test run.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_whoknocked")
}

/// Path to the checked-in sample auth log.
fn sample_log() -> String {
    format!("{}/examples/sample-auth.log", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn reports_findings_from_sample_log() {
    let output = Command::new(binary())
        .args(["--file", &sample_log()])
        .output()
        .expect("failed to run whoknocked");

    assert!(output.status.success(), "process should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("WHOKNOCKED"), "banner missing");
    assert!(
        stdout.contains("Possible brute force"),
        "brute force not detected"
    );
    assert!(
        stdout.contains("Login after repeated failures"),
        "correlation not detected"
    );
    assert!(
        stdout.contains("Possible username/password spray"),
        "spray not detected"
    );
}

#[test]
fn summary_only_skips_detection_section() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--summary-only"])
        .output()
        .expect("failed to run whoknocked");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("successful logins"));
    assert!(!stdout.contains("Interesting activity"));
}

#[test]
fn ip_filter_narrows_the_view() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--ip", "45.20.13.8"])
        .output()
        .expect("failed to run whoknocked");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The brute-force IP is present; the spray IP was filtered out.
    assert!(stdout.contains("Possible brute force"));
    assert!(!stdout.contains("Possible username/password spray"));
}

#[test]
fn missing_file_fails_cleanly() {
    let output = Command::new(binary())
        .args(["--file", "/nonexistent/path/to/auth.log"])
        .output()
        .expect("failed to run whoknocked");

    assert!(!output.status.success(), "should exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("whoknocked:"), "should print an error");
}

#[test]
fn rejects_invalid_since_value() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--since", "banana"])
        .output()
        .expect("failed to run whoknocked");

    assert!(!output.status.success());
}

#[test]
fn reads_from_stdin_with_dash() {
    use std::io::Write;
    use std::process::Stdio;

    let sample = std::fs::read(sample_log()).expect("sample log exists");
    let mut child = Command::new(binary())
        .args(["--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run whoknocked");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&sample)
        .expect("write sample");
    let output = child.wait_with_output().expect("wait");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authentication activity \u{2014} stdin"));
    assert!(stdout.contains("Possible brute force"));
}

#[test]
fn json_output_is_valid_and_structured() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--json"])
        .output()
        .expect("failed to run whoknocked");

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    assert_eq!(value["risk"], "elevated");
    assert_eq!(value["top_sources"][0]["ip"], "45.20.13.8");
    assert_eq!(value["findings"][0]["severity"], "high");
}

#[test]
fn top_sources_table_ranks_attackers_first() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--top", "2"])
        .output()
        .expect("failed to run whoknocked");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let table_start = stdout.find("Top sources").expect("table present");
    let table = &stdout[table_start..];
    let first = table.find("45.20.13.8").expect("brute-force IP listed");
    let second = table.find("45.20.10.2").expect("spray IP listed");
    assert!(first < second);
    assert!(!table.contains("10.0.0.5"), "--top 2 should cut the list");
}
