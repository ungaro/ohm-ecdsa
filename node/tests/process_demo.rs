//! M2 process-level tests: the `spawn-demo` mode of the node binary
//! launches three CHILD PROCESSES — each holding only its own seed file —
//! and runs keygen + sign across them. These tests assert on the demo's
//! RESULT lines; they are the process-separation counterpart of the
//! thread-level `party_mesh` tests.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ohm-ecdsa-node");
const DEMO_TIMEOUT: Duration = Duration::from_secs(180);

/// Run `spawn-demo` with extra args; returns its stdout. Panics (after
/// killing the child) if the demo hangs.
fn run_spawn_demo(extra: &[&str]) -> String {
    let mut child = Command::new(BIN)
        .arg("spawn-demo")
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the node binary");
    let deadline = Instant::now() + DEMO_TIMEOUT;
    loop {
        if child.try_wait().expect("poll child").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("spawn-demo {extra:?} timed out");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().expect("collect output");
    assert!(
        out.status.success(),
        "spawn-demo {extra:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

#[test]
fn process_demo_honest_keygen_and_sign() {
    let out = run_spawn_demo(&[]);
    assert!(
        out.contains("RESULT keygen: all 3 processes agree on X"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT sign: all 3 processes agree; signature verifies under X: true"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
    assert!(!out.contains("BLAME"), "stdout:\n{out}");
}

#[test]
fn process_demo_sign_cheater_named_and_signature_delivered() {
    // Node 2's process broadcasts a wrong signature share: the other two
    // PROCESSES both name it, and all three still deliver the signature
    // (§10.4 robust combine).
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-sign-share"]);
    for node in ["1", "2", "3"] {
        assert!(
            out.contains(&format!(
                "RESULT blame: node {node} reports \"BLAME sign 2\""
            )),
            "stdout:\n{out}"
        );
    }
    assert!(
        out.contains("RESULT sign: all 3 processes agree; signature verifies under X: true"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_dkg_cheater_named_by_all_via_wire_complaints() {
    // Node 2's process deals a wrong share to party 1: the §6.1 complaint
    // and defense travel between PROCESSES; every process names dealer 2,
    // and the (independent, seeded) sign phase still delivers.
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-deal:1"]);
    assert!(
        out.contains(
            "RESULT keygen: aborted consistently — every process reports \"BLAME keygen 2\""
        ),
        "stdout:\n{out}"
    );
    for node in ["1", "2", "3"] {
        assert!(
            out.contains(&format!(
                "RESULT blame: node {node} reports \"BLAME keygen 2\""
            )),
            "stdout:\n{out}"
        );
    }
    assert!(
        out.contains("RESULT sign: all 3 processes agree; signature verifies under X: true"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_false_accuser_named_by_all() {
    // Node 3's process accuses honest dealer 1: the dealer's defense
    // verifies everywhere, so every process names the accuser.
    let out = run_spawn_demo(&["--cheat-node", "3", "--cheat", "false-accuse:1"]);
    assert!(
        out.contains(
            "RESULT keygen: aborted consistently — every process reports \"BLAME keygen 3\""
        ),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}
