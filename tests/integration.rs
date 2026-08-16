//! End-to-end tests that run the compiled binary against the sample log.
//!
//! These exercise the whole pipeline (path -> parse -> detect -> report)
//! without needing root, by pointing `--file` at a fixture in `examples/`.

use std::process::Command;

/// Path to the binary Cargo built for this test run.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_loghound")
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
        .expect("failed to run loghound");

    assert!(output.status.success(), "process should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("LOGHOUND"), "banner missing");
    assert!(stdout.contains("Possible brute force"), "brute force not detected");
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
        .expect("failed to run loghound");

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
        .expect("failed to run loghound");

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
        .expect("failed to run loghound");

    assert!(!output.status.success(), "should exit non-zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("loghound:"), "should print an error");
}

#[test]
fn rejects_invalid_since_value() {
    let output = Command::new(binary())
        .args(["--file", &sample_log(), "--since", "banana"])
        .output()
        .expect("failed to run loghound");

    assert!(!output.status.success());
}
