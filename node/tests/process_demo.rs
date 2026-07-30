//! M2/M3a process-level tests: the `spawn-demo` mode of the node binary
//! launches three CHILD PROCESSES — each holding only its own seed file —
//! and runs the full arc keygen → presign → sign across them (M3a
//! default; `--seeded` keeps the M2 seeded-sign fallback). These tests
//! assert on the demo's RESULT lines; they are the process-separation
//! counterpart of the thread-level `party_mesh` / `party_offline` tests.
//! The M3b tests add `--persist`: durable stores, the transcript/blame
//! archive, and the offline `auditor` subcommand (SPEC §8.6, §A.4).
//! The H3 tests cover the DISTRIBUTED committee ceremony: three separate
//! `init` runs + a public `assemble` boot a full-arc committee from
//! per-party identity files, and the fail-closed backstops against
//! duplicate/tampered bundles.

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use ohm_ecdsa_node::ceremony;
use ohm_ecdsa_node::persist::read_transcript;

const BIN: &str = env!("CARGO_BIN_EXE_ohm-ecdsa-node");
/// Watchdog per `spawn-demo` run. Generous on purpose: under a parallel
/// full-workspace test run each demo spawns 3 real OS processes whose
/// localhost rounds compete for CPU with every other test binary — a
/// tight timeout here fails the test for load, not for a real hang.
const DEMO_TIMEOUT: Duration = Duration::from_secs(300);

/// Serialization for the process-level tests. Every test in this binary
/// spawns 3 child `node` processes (plus their mesh threads); running all
/// of them concurrently under an already-loaded parallel workspace suite
/// starves the echo-broadcast rounds and trips the watchdog. A plain
/// static `Mutex` serializes ONLY within this test binary — which is the
/// dominant contention source, since the process-spawning tests all live
/// here. Cross-binary parallelism (thread-level tests in the other test
/// binaries) does not spawn OS processes and stays cheap; no new
/// dependency (no `serial_test`, no file locks) is needed for it.
static DEMO_LOCK: Mutex<()> = Mutex::new(());

/// A fresh empty temp directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-process-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run `spawn-demo` with extra args; returns its stdout. Panics (after
/// killing the child) if the demo hangs. Serialized across this binary's
/// tests (see `DEMO_LOCK`).
fn run_spawn_demo(extra: &[&str]) -> String {
    let _serial = DEMO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

/// Every process reports the same blame line (via the RESULT summary).
fn assert_blame_line(out: &str, line: &str) {
    for node in ["1", "2", "3"] {
        assert!(
            out.contains(&format!("RESULT blame: node {node} reports \"{line}\"")),
            "stdout:\n{out}"
        );
    }
}

#[test]
fn process_demo_honest_full_arc() {
    // M3a full arc: keygen → presign → sign, all under the key the
    // processes' OWN keygen produced (no ceremony presignature).
    let out = run_spawn_demo(&[]);
    assert!(
        out.contains("RESULT keygen: all 3 processes agree on X"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT presign: all 3 processes agree on PRESIG"),
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
fn process_demo_tls_full_arc() {
    // M3c: the full arc across 3 child processes over mTLS — per-party
    // self-signed certs generated by spawn-demo, every node pinning the
    // committee set (--tls CERT KEY --pinned DIR). Same guarantees as
    // the plaintext arc; the wire format inside TLS is unchanged.
    let out = run_spawn_demo(&["--tls"]);
    assert!(
        out.contains("mTLS (M3c): TLS 1.3, per-party self-signed certs pinned to the committee"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT keygen: all 3 processes agree on X"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT presign: all 3 processes agree on PRESIG"),
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
fn process_demo_ki_full_arc() {
    // §8.7 KI mode across 3 child processes: keygen → KEY-FREE pool
    // record (P1–P3 only) → 2-round online KI sign, bound to the key the
    // processes' OWN keygen produced. All processes agree on X, on the
    // pool record's public nonce, and on a signature that verifies.
    let out = run_spawn_demo(&["--ki"]);
    assert!(
        out.contains("KEY-FREE pool record → 2-round KI sign"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT keygen: all 3 processes agree on X"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT presign: all 3 processes agree on PRESIG"),
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
    assert_blame_line(&out, "BLAME sign 2");
    assert!(
        out.contains("RESULT sign: all 3 processes agree; signature verifies under X: true"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_dkg_cheater_named_by_all_via_wire_complaints() {
    // Node 2's process deals a wrong share to party 1: the §6.1 complaint
    // and defense travel between PROCESSES; every process names dealer 2.
    // In the full arc a keygen abort ends the arc — presign and sign are
    // skipped (no key to presign under).
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-deal:1"]);
    assert!(
        out.contains(
            "RESULT keygen: aborted consistently — every process reports \"BLAME keygen 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME keygen 2");
    assert!(
        out.contains("RESULT presign: skipped (keygen aborted)"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_dkg_cheater_seeded_sign_still_delivers() {
    // The M2 seeded fallback: keygen aborts naming dealer 2, and the
    // (independent, ceremony-seeded) sign phase still delivers.
    let out = run_spawn_demo(&["--seeded", "--cheat-node", "2", "--cheat", "bad-deal:1"]);
    assert!(
        out.contains(
            "RESULT keygen: aborted consistently — every process reports \"BLAME keygen 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME keygen 2");
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

#[test]
fn process_demo_triples_bad_dleq_named_by_all() {
    // Node 2's process broadcasts an invalid DLEQ product proof in the
    // FIRST triple session of presign (F3): every process names it, and
    // the arc stops before signing.
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-product-proof"]);
    assert!(
        out.contains(
            "RESULT presign: aborted consistently — every process reports \"BLAME triples 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME triples 2");
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_triples_bad_reshare_named_by_all() {
    // Node 2's process sends a wrong re-shared share to party 1 (F2):
    // the §6.1 complaint/defense rounds travel between PROCESSES inside
    // the triple factory; every process names dealer 2.
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-reshare:1"]);
    assert!(
        out.contains(
            "RESULT presign: aborted consistently — every process reports \"BLAME triples 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME triples 2");
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_presign_bad_nonce_point_named_by_all() {
    // Node 2's process broadcasts a wrong nonce point R_j (F5): it fails
    // the EvalCom(A[k], 2) check at every process.
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-nonce-point"]);
    assert!(
        out.contains(
            "RESULT presign: aborted consistently — every process reports \"BLAME presign 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME presign 2");
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_presign_bad_open_share_named_by_all() {
    // Node 2's process broadcasts a wrong v opening share: it fails the
    // point-equality opening check at every process (fail-fast, §4.6).
    let out = run_spawn_demo(&["--cheat-node", "2", "--cheat", "bad-open-share"]);
    assert!(
        out.contains(
            "RESULT presign: aborted consistently — every process reports \"BLAME presign 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME presign 2");
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_restart_open_share_cheater_named_and_signature_delivered() {
    // H4 (`--restart`, §10.4): node 2's process broadcasts a wrong `v`
    // opening share in presign — the ROBUST driver filters it, every
    // process names party 2, the presign still COMPLETES at all three
    // processes, and the signature is delivered and verifies (a single
    // cheater causes blame + continued service, not an outage).
    let out = run_spawn_demo(&[
        "--restart",
        "--cheat-node",
        "2",
        "--cheat",
        "bad-open-share",
    ]);
    assert!(
        out.contains("§10.4 robust + §10.3 restart"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains("RESULT presign: all 3 processes agree on PRESIG"),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME presign 2");
    assert!(
        out.contains("RESULT sign: all 3 processes agree; signature verifies under X: true"),
        "stdout:\n{out}"
    );
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

#[test]
fn process_demo_restart_dealing_cheater_refused_zero_slack() {
    // H4 (`--restart`, §10.3): node 2's process broadcasts an invalid
    // DLEQ product proof (F3, dealing phase — not continuable). The
    // expel-and-restart policy is REFUSED (2-of-3 is zero-slack: any
    // expulsion leaves n′ < 2t−1 — `t` is never silently lowered), so
    // every process names party 2 and the arc stops, as in fail-fast.
    let out = run_spawn_demo(&[
        "--restart",
        "--cheat-node",
        "2",
        "--cheat",
        "bad-product-proof",
    ]);
    assert!(
        out.contains(
            "RESULT presign: aborted consistently — every process reports \"BLAME triples 2\""
        ),
        "stdout:\n{out}"
    );
    assert_blame_line(&out, "BLAME triples 2");
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
}

/// Run the `auditor` subcommand; returns (exit-ok, stdout).
fn run_auditor(token: &std::path::Path, committee: &std::path::Path) -> (bool, String) {
    let out = Command::new(BIN)
        .arg("auditor")
        .arg(token)
        .arg(committee)
        .output()
        .expect("spawn the auditor");
    (
        out.status.success(),
        String::from_utf8(out.stdout).expect("utf8 stdout"),
    )
}

#[test]
fn process_demo_persist_full_arc() {
    // M3b: the full arc with `--persist` — every process runs with a
    // per-node --data-dir. The signature is delivered; afterwards each
    // node's store shows the fsync'd consume tombstone (the `.presig`
    // file is gone, §8.6) and each node's transcript archive decodes.
    let dir = tmpdir("persist-arc");
    let out = run_spawn_demo(&["--dir", dir.to_str().unwrap(), "--persist"]);
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
    for id in 1..=3usize {
        let store = dir.join(format!("node-{id}/store"));
        assert!(store.join("0.consumed").exists(), "node {id} tombstone");
        assert!(!store.join("0.presig").exists(), "node {id} live record");
        let transcript = dir.join(format!("node-{id}/archive/transcript.log"));
        let entries = read_transcript(&transcript).unwrap();
        assert!(!entries.is_empty(), "node {id} transcript");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn process_demo_auditor_verifies_and_rejects_token() {
    // M3b, SPEC §A.4: node 2's process deals a wrong share to party 1 in
    // keygen; every process names dealer 2, and the accuser's process
    // archives a blame-token file. The offline auditor verifies it
    // (exit 0, VERDICT: VALID) and rejects a tampered copy (exit 1).
    let dir = tmpdir("auditor");
    let out = run_spawn_demo(&[
        "--dir",
        dir.to_str().unwrap(),
        "--persist",
        "--cheat-node",
        "2",
        "--cheat",
        "bad-deal:1",
    ]);
    assert_blame_line(&out, "BLAME keygen 2");
    let token = dir.join("node-1/archive/blame-keygen-2.tok");
    assert!(token.exists());
    let committee = dir.join("committee.hex");
    let (ok, stdout) = run_auditor(&token, &committee);
    assert!(ok, "auditor rejected the honest token:\n{stdout}");
    assert!(stdout.contains("VERDICT: VALID"), "stdout:\n{stdout}");
    // Flip one byte: the auditor must reject.
    let mut bytes = std::fs::read(&token).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let tampered = dir.join("tampered.tok");
    std::fs::write(&tampered, &bytes).unwrap();
    let (ok, stdout) = run_auditor(&tampered, &committee);
    assert!(!ok, "auditor accepted a tampered token:\n{stdout}");
    assert!(stdout.contains("VERDICT: INVALID"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn process_demo_factory_concurrent_signing() {
    // H2 Phase 3 (concurrent sessions) at the process level: each child
    // process runs a BACKGROUND presignature factory (target 2 in the
    // pool) while its main thread signs 3 messages against consumed
    // records — factory presign sessions and online sign sessions
    // overlap on the same mesh, demultiplexed by sid. Asserts the
    // factory's progress line and every signature verifying under the
    // fresh X, plus a clean shutdown at the end of each child.
    let out = run_spawn_demo(&["--factory", "2"]);
    assert!(
        out.contains("RESULT keygen: all 3 processes agree on X"),
        "stdout:\n{out}"
    );
    assert!(
        out.contains(
            "RESULT factory: all 3 processes kept the pool at 2 while signing (produced >= 5)"
        ),
        "stdout:\n{out}"
    );
    for i in 1..=3 {
        assert!(
            out.contains(&format!(
                "RESULT sign {i}: all 3 processes agree; signature verifies under X: true"
            )),
            "stdout:\n{out}"
        );
    }
    assert!(out.contains("RESULT demo: SUCCESS"), "stdout:\n{out}");
    assert!(!out.contains("BLAME"), "stdout:\n{out}");
}

// --- H3: the distributed committee ceremony (init → assemble → node --identity) ---

/// The default `--message` the demo signs (kept in sync with main.rs).
const DEMO_MESSAGE: &[u8] = b"ohm-ecdsa-node M2 demo: signed across real OS processes";

/// Run any subcommand to completion; returns (exit-ok, stdout, stderr).
fn run_cmd(args: &[String]) -> (bool, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn the node binary");
    (
        out.status.success(),
        String::from_utf8(out.stdout).expect("utf8 stdout"),
        String::from_utf8(out.stderr).expect("utf8 stderr"),
    )
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hexdigits checked"))
            .collect(),
    )
}

/// Boot the three distributed-ceremony node processes (`--identity` +
/// `--rendezvous`), wire the peer set exactly as `spawn-demo` does, wait
/// for all of them under the demo watchdog, and collect their per-node
/// stdout lines.
fn run_distributed_nodes(dir: &std::path::Path) -> Vec<Vec<String>> {
    let committee = dir.join("committee").join("committee.hex");
    let mut children = Vec::new();
    for id in 1..=3usize {
        let child = Command::new(BIN)
            .arg("node")
            .arg("--identity")
            .arg(ceremony::identity_file(
                &dir.join(format!("party-{id}")),
                id,
            ))
            .arg("--committee")
            .arg(&committee)
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--rendezvous")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn a node process");
        children.push(child);
    }
    let mut readers = Vec::new();
    let mut addrs: Vec<(usize, SocketAddr)> = Vec::new();
    for (i, child) in children.iter_mut().enumerate() {
        let id = i + 1;
        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read READY");
        assert!(
            line.starts_with("READY"),
            "node {id} did not report READY: {line:?}"
        );
        let addr: SocketAddr = line
            .split_whitespace()
            .nth(2)
            .and_then(|a| a.parse().ok())
            .expect("READY carries an address");
        addrs.push((id, addr));
        readers.push(reader);
    }
    let peers = format!(
        "PEERS {}\n",
        addrs
            .iter()
            .map(|(id, a)| format!("{id}@{a}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    for child in &mut children {
        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(peers.as_bytes())
            .expect("write PEERS");
    }
    let deadline = Instant::now() + DEMO_TIMEOUT;
    for child in &mut children {
        loop {
            if child.try_wait().expect("poll node").is_some() {
                break;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("distributed-ceremony node timed out");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    readers
        .into_iter()
        .map(|r| r.lines().map_while(Result::ok).collect())
        .collect()
}

#[test]
fn process_demo_distributed_ceremony_full_arc() {
    // H3: three SEPARATE `init` runs (separate dirs, as on separate
    // machines — no process ever holds another party's secret), one
    // PUBLIC `assemble`, then three node processes booting from their
    // own identity files complete the full arc keygen → presign → sign.
    let _serial = DEMO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tmpdir("distributed");
    for id in 1..=3usize {
        let (ok, stdout, _) = run_cmd(&[
            "init".into(),
            "--id".into(),
            id.to_string(),
            "--dir".into(),
            dir.join(format!("party-{id}"))
                .to_string_lossy()
                .into_owned(),
            "--addr".into(),
            "127.0.0.1:0".into(),
        ]);
        assert!(ok, "init {id} failed:\n{stdout}");
        assert!(stdout.contains("FINGERPRINT "), "stdout:\n{stdout}");
        assert!(ceremony::identity_file(&dir.join(format!("party-{id}")), id).exists());
        assert!(ceremony::pub_file(&dir.join(format!("party-{id}")), id).exists());
    }
    let inputs = (1..=3usize)
        .map(|id| {
            ceremony::pub_file(&dir.join(format!("party-{id}")), id)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>()
        .join(",");
    let (ok, stdout, _) = run_cmd(&[
        "assemble".into(),
        "--committee".into(),
        dir.join("committee").to_string_lossy().into_owned(),
        "--inputs".into(),
        inputs,
    ]);
    assert!(ok, "assemble failed:\n{stdout}");
    for id in 1..=3usize {
        assert!(
            stdout.contains(&format!("party {id} fingerprint ")),
            "stdout:\n{stdout}"
        );
    }

    let lines = run_distributed_nodes(&dir);
    let xs: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.iter().find(|l| l.starts_with("X ")))
        .map(String::as_str)
        .collect();
    assert!(xs.len() == 3 && xs.iter().all(|x| *x == xs[0]), "xs={xs:?}");
    let sigs: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.iter().find(|l| l.starts_with("SIG ")))
        .map(String::as_str)
        .collect();
    assert!(
        sigs.len() == 3 && sigs.iter().all(|s| *s == sigs[0]),
        "sigs={sigs:?}"
    );
    // The signature verifies under the FRESH key the processes' own
    // keygen produced.
    let vk = hex_decode(&xs[0][2..]).and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok());
    let sig = hex_decode(&sigs[0].replace("SIG ", "").replace(' ', ""))
        .and_then(|b| Signature::from_slice(&b).ok());
    match (vk, sig) {
        (Some(vk), Some(sig)) => assert!(
            vk.verify(DEMO_MESSAGE, &sig).is_ok(),
            "signature does not verify under X"
        ),
        _ => panic!("unparseable X/SIG lines: xs={xs:?} sigs={sigs:?}"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn process_ceremony_assemble_rejects_duplicate_id() {
    // Two `init`s with the same id (two machines both claiming to be
    // party 1): assembly must fail, loudly.
    let dir = tmpdir("dup-id");
    for (id, name) in [(1, "a"), (1, "b"), (2, "c")] {
        let (ok, _, _) = run_cmd(&[
            "init".into(),
            "--id".into(),
            id.to_string(),
            "--dir".into(),
            dir.join(name).to_string_lossy().into_owned(),
        ]);
        assert!(ok);
    }
    let inputs = ["a/party-1.pub", "b/party-1.pub", "c/party-2.pub"]
        .iter()
        .map(|p| dir.join(p).to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(",");
    let (ok, _, stderr) = run_cmd(&[
        "assemble".into(),
        "--committee".into(),
        dir.join("committee").to_string_lossy().into_owned(),
        "--inputs".into(),
        inputs,
    ]);
    assert!(!ok, "assemble accepted a duplicate party id");
    assert!(stderr.contains("duplicate party id"), "stderr:\n{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn process_ceremony_node_fails_closed_on_tampered_pub() {
    // A .pub bundle tampered after the out-of-band check is well-formed
    // (assembly succeeds) but must not let the node boot: a mismatched
    // TLS certificate fails the pinned-set check, a mismatched transport
    // key fails the registry self-check. Both fail closed at startup.
    let dir = tmpdir("tampered");
    for id in 1..=3usize {
        let (ok, _, _) = run_cmd(&[
            "init".into(),
            "--id".into(),
            id.to_string(),
            "--dir".into(),
            dir.join(format!("party-{id}"))
                .to_string_lossy()
                .into_owned(),
            "--tls".into(),
        ]);
        assert!(ok);
    }
    let read =
        |id: usize| ceremony::read_pub(&ceremony::pub_file(&dir.join(format!("party-{id}")), id));
    let p2 = read(2).unwrap();
    let p3 = read(3).unwrap();
    let path_of = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let assemble = |p2file: &str, outdir: &str| {
        let inputs = [
            ceremony::pub_file(&dir.join("party-1"), 1)
                .to_string_lossy()
                .into_owned(),
            path_of(p2file),
            ceremony::pub_file(&dir.join("party-3"), 3)
                .to_string_lossy()
                .into_owned(),
        ]
        .join(",");
        run_cmd(&[
            "assemble".into(),
            "--committee".into(),
            path_of(outdir),
            "--inputs".into(),
            inputs,
        ])
    };

    // Scenario 1: party 2's certificate swapped for party 3's. Assembly
    // accepts the well-formed bundle …
    let mut bad_cert = p2.clone();
    bad_cert.cert_pem = p3.cert_pem.clone();
    ceremony::write_pub(&dir.join("bad-cert.pub"), &bad_cert).unwrap();
    let (ok, _, _) = assemble("bad-cert.pub", "committee-tls");
    assert!(ok, "assembly should accept a well-formed bundle");
    // … but node 2's own cert no longer matches its pinned entry.
    let (ok, _, stderr) = run_cmd(&[
        "node".into(),
        "--identity".into(),
        ceremony::identity_file(&dir.join("party-2"), 2)
            .to_string_lossy()
            .into_owned(),
        "--committee".into(),
        path_of("committee-tls/committee.hex"),
        "--bind".into(),
        "127.0.0.1:0".into(),
        "--tls".into(),
        path_of("party-2/party-2.crt.pem"),
        path_of("party-2/party-2.key.pem"),
        "--pinned".into(),
        path_of("committee-tls"),
        "--rendezvous".into(),
    ]);
    assert!(!ok, "node booted with a tampered pinned certificate");
    assert!(
        stderr.contains("loading TLS material failed"),
        "stderr:\n{stderr}"
    );

    // Scenario 2: party 2's transport verifying key swapped for party
    // 3's. Node 2's own secret key no longer matches its registry entry.
    let mut bad_key = p2.clone();
    bad_key.verifying_key = p3.verifying_key;
    ceremony::write_pub(&dir.join("bad-key.pub"), &bad_key).unwrap();
    let (ok, _, _) = assemble("bad-key.pub", "committee-plain");
    assert!(ok, "assembly should accept a well-formed bundle");
    let (ok, _, stderr) = run_cmd(&[
        "node".into(),
        "--identity".into(),
        ceremony::identity_file(&dir.join("party-2"), 2)
            .to_string_lossy()
            .into_owned(),
        "--committee".into(),
        path_of("committee-plain/committee.hex"),
        "--bind".into(),
        "127.0.0.1:0".into(),
        "--rendezvous".into(),
    ]);
    assert!(!ok, "node booted with a tampered registry entry");
    assert!(
        stderr.contains("does not match the committee registry"),
        "stderr:\n{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
