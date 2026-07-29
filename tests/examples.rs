//! Smoke tests for the narrative examples under `examples/`: each one is
//! run via `cargo run --quiet --example NAME` and must exit successfully
//! with its key guarantee lines on stdout. Output is captured (not
//! inherited) so the suite stays quiet on success; on failure the
//! captured stdout/stderr is printed for debuggability.

use std::process::Command;

/// Run `cargo run --quiet --example NAME`; return its stdout. Panics with
/// the full captured output if the example fails to build or run.
fn run_example(name: &str) -> String {
    let out = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--example", name])
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn cargo for example {name}: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "example {name} exited with {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
    stdout
}

/// Every `needle` must appear in the example's stdout.
fn assert_guarantees(name: &str, stdout: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            stdout.contains(needle),
            "example {name}: stdout missing {needle:?}\n--- stdout ---\n{stdout}"
        );
    }
}

#[test]
fn example_wallet_2_of_3() {
    let stdout = run_example("wallet_2_of_3");
    assert_guarantees(
        "wallet_2_of_3",
        &stdout,
        &[
            "signature verifies under X",
            "nonce reuse prevented",
            "the 2-of-3 threshold held",
        ],
    );
}

#[test]
fn example_consortium_custody() {
    let stdout = run_example("consortium_custody");
    assert_guarantees(
        "consortium_custody",
        &stdout,
        &[
            "signature verifies under X",
            "signature verifies under X' = X + tau*G",
        ],
    );
}

#[test]
fn example_identifiable_abort() {
    let stdout = run_example("identifiable_abort");
    assert_guarantees(
        "identifiable_abort",
        &stdout,
        &["Error::Abort", "blamed: [2]", "signature verifies under X"],
    );
}

#[test]
fn example_epoch_refresh() {
    let stdout = run_example("epoch_refresh");
    assert_guarantees(
        "epoch_refresh",
        &stdout,
        &[
            "X unchanged: true",
            "every share re-randomized: true",
            "signature verifies under X",
        ],
    );
}

#[test]
fn example_blame_token() {
    let stdout = run_example("blame_token");
    assert_guarantees(
        "blame_token",
        &stdout,
        &[
            "blamed: [2]",
            "auditor verifies the blame token: true",
            "forgery rejected by the auditor: true",
        ],
    );
}
