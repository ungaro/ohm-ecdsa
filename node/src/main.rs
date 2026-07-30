//! OHM-ECDSA node binary (M2/M3a): per-party processes plus the M1 demo.
//!
//! Subcommands:
//!
//! * `node` — run as ONE party (its own OS process, holding only its own
//!   seed): fresh keygen through the M2 per-node driver (§6 + §6.1
//!   complaints over the wire), then — the M3a default — the full arc:
//!   per-node presign (§7.2 triples + §8 over the wire) under the key its
//!   own keygen just produced, then one online signature (§9, §10.4
//!   robust) with that presignature. `--seeded` keeps the M2 fallback:
//!   sign with a ceremony-seeded presignature ([`ohm_ecdsa_node::seed`])
//!   under the ceremony key. `--tls CERT KEY --pinned DIR` (M3c, §13.1)
//!   wraps the mesh in mTLS with committee-pinned certs.
//! * `setup` — the demo ceremony: one orchestrated run writing the public
//!   committee file and one SECRET seed file per party; `--tls` also
//!   writes per-party self-signed certs for the M3c mTLS mesh.
//! * `spawn-demo` — the showcase: set up a 2-of-3 committee and launch
//!   three child `node` processes on localhost, keygen → presign → sign
//!   across real processes, printing per-process logs, per-phase timings,
//!   the joint key, the signature, and any blame. `--cheat-node K
//!   --cheat C` drives child K into a cheater; `--seeded` falls back to
//!   the M2 seeded-sign demo; `--tls` (M3c) generates per-party certs
//!   and runs the arc over mTLS.
//! * `m1-demo [port_base]` — the original M1 orchestrator demo (one
//!   process, all keys, `drive_dkg_signed` over `MeshTransport`).
//! * `auditor TOKEN_FILE COMMITTEE_FILE` — the M3b offline evidence
//!   check (SPEC §A.4): re-verify a blame-token file against the
//!   committee's public transport keys; exit 0 iff VALID.
//!
//! With `--data-dir DIR` (or `spawn-demo --persist`, M3b) a node opens a
//! durable presignature store (§8.6) and the transcript/blame archive
//! (§4.7, §10.2) under `DIR`.
//!
//! Run `… --help`-less: wrong usage prints the usage text.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ohm_ecdsa::transport::{drive_dkg_signed, SigningTransport};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::persist::{self, PersistError};
use ohm_ecdsa_node::seed::{self, CommitteeInfo};
use ohm_ecdsa_node::tls::{self, CommitteeTls};
use ohm_ecdsa_node::{Cheat, MeshTransport, PartyNode, DEFAULT_ROUND_TIMEOUT};
use rand::rngs::OsRng;

/// Genesis anchor for the demo sids (SPEC §13.1).
const GENESIS: &[u8] = b"ohm-ecdsa-node/m2-demo";
/// The message the demo committee signs.
const DEMO_MESSAGE: &[u8] = b"ohm-ecdsa-node M2 demo: signed across real OS processes";
/// DKG commit tag for the per-node keygen driver.
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/dkg";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("m1-demo") => m1_demo(args.get(1).and_then(|a| a.parse().ok()).unwrap_or(0)),
        Some("setup") => setup(&args[1..]),
        Some("node") => node_mode(&args[1..]),
        Some("spawn-demo") => spawn_demo(&args[1..]),
        Some("auditor") => auditor(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  \
                 ohm-ecdsa-node m1-demo [PORT_BASE]\n  \
                 ohm-ecdsa-node setup --dir DIR [--presigs K] [--seed S] [--tls]\n  \
                 ohm-ecdsa-node node --seed FILE --committee FILE --bind ADDR \\\n    \
                 [--rendezvous | --peers id@host:port,...] [--delay-ms D] [--seeded] \\\n    \
                 [--round-timeout-secs S] [--cheat C] [--presig-id K] [--message MSG] \\\n    \
                 [--data-dir DIR] [--tls CERT KEY --pinned DIR]\n  \
                 ohm-ecdsa-node spawn-demo [--dir DIR] [--delay-ms D] [--seeded] [--persist] \\\n    \
                 [--tls] [--cheat-node K --cheat C]\n  \
                 ohm-ecdsa-node auditor TOKEN_FILE COMMITTEE_FILE\n  \
                 cheats: bad-deal:V | false-accuse:D | bad-sign-share | \\\n    \
                 bad-product-proof | bad-reshare:V | bad-nonce-point | bad-open-share"
            );
            ExitCode::FAILURE
        }
    }
}

// --- tiny CLI helpers --------------------------------------------------------

/// Pop the value of `--flag` (the next argument).
fn flag_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.remove(pos);
    if pos < args.len() {
        Some(args.remove(pos))
    } else {
        None
    }
}

/// Pop the TWO values of `--tls CERT KEY`.
fn tls_flag(args: &mut Vec<String>) -> Option<(String, String)> {
    let pos = args.iter().position(|a| a == "--tls")?;
    args.remove(pos);
    if pos + 1 < args.len() {
        let key = args.remove(pos + 1);
        let cert = args.remove(pos);
        Some((cert, key))
    } else {
        None
    }
}

fn has_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn parse_cheat(s: &str) -> Option<Cheat> {
    match s {
        "bad-sign-share" => return Some(Cheat::BadSignShare),
        "bad-product-proof" => return Some(Cheat::BadProductProof),
        "bad-nonce-point" => return Some(Cheat::BadNoncePoint),
        "bad-open-share" => return Some(Cheat::BadOpenShare),
        _ => {}
    }
    let (kind, arg) = s.split_once(':')?;
    let id: PartyId = arg.parse().ok()?;
    match kind {
        "bad-deal" => Some(Cheat::BadDeal { victim: id }),
        "false-accuse" => Some(Cheat::FalseAccuse { dealer: id }),
        "bad-reshare" => Some(Cheat::BadReshare { victim: id }),
        _ => None,
    }
}

/// Parse `id@host:port,id@host:port,…`.
fn parse_peers(s: &str) -> Option<Vec<(PartyId, SocketAddr)>> {
    s.split(',')
        .map(|entry| {
            let (id, addr) = entry.split_once('@')?;
            Some((id.parse().ok()?, addr.parse().ok()?))
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

// --- setup -------------------------------------------------------------------

fn setup(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let Some(dir) = flag_value(&mut args, "--dir").map(PathBuf::from) else {
        eprintln!("setup: --dir DIR is required");
        return ExitCode::FAILURE;
    };
    let presigs: u64 = flag_value(&mut args, "--presigs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let seed: u64 = flag_value(&mut args, "--seed")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| rand::RngCore::next_u64(&mut OsRng));
    let with_tls = has_flag(&mut args, "--tls");
    let params = Params::new(3, 2).expect("valid params");
    let (info, seeds) = seed::ceremony(&params, presigs, seed);
    if let Err(e) = seed::write_all(&dir, &info, &seeds) {
        eprintln!("setup: writing seed files failed: {e}");
        return ExitCode::FAILURE;
    }
    let x = info.x.to_affine().to_encoded_point(true);
    println!("ceremony complete (2-of-3, {presigs} presignature(s) per party)");
    println!("  joint public key X = {}", hex(x.as_bytes()));
    println!(
        "  public committee file: {}",
        dir.join(seed::COMMITTEE_FILE).display()
    );
    for s in &seeds {
        println!(
            "  secret seed for party {}: {} (ONLY that party may read it)",
            s.id,
            seed::seed_file(&dir, s.id).display()
        );
    }
    if with_tls {
        // M3c: per-party self-signed certs for the mTLS mesh. The certs
        // are PUBLIC (every node pins the whole committee set); the keys
        // are SECRET per party. Real deployments substitute their own
        // PKI (SPEC §13.1).
        let ids: Vec<PartyId> = seeds.iter().map(|s| s.id).collect();
        if let Err(e) = tls::write_committee_certs(&dir, &ids) {
            eprintln!("setup: writing TLS certificates failed: {e}");
            return ExitCode::FAILURE;
        }
        for id in ids {
            println!(
                "  TLS cert for party {}: {} (public); key: {} (SECRET)",
                id,
                tls::cert_file(&dir, id).display(),
                tls::key_file(&dir, id).display()
            );
        }
        println!(
            "  run nodes with: node ... --tls CERT KEY --pinned {}",
            dir.display()
        );
    }
    ExitCode::SUCCESS
}

// --- node mode: one party, one process ----------------------------------------

fn node_mode(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let (Some(seed_path), Some(committee_path), Some(bind)) = (
        flag_value(&mut args, "--seed").map(PathBuf::from),
        flag_value(&mut args, "--committee").map(PathBuf::from),
        flag_value(&mut args, "--bind"),
    ) else {
        eprintln!("node: --seed, --committee and --bind are required");
        return ExitCode::FAILURE;
    };
    let rendezvous = has_flag(&mut args, "--rendezvous");
    let seeded = has_flag(&mut args, "--seeded");
    let peers_arg = flag_value(&mut args, "--peers");
    let delay_ms: u64 = flag_value(&mut args, "--delay-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let timeout_secs: u64 = flag_value(&mut args, "--round-timeout-secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ROUND_TIMEOUT.as_secs());
    let presig_id: u64 = flag_value(&mut args, "--presig-id")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let message = flag_value(&mut args, "--message")
        .map(String::into_bytes)
        .unwrap_or_else(|| DEMO_MESSAGE.to_vec());
    let data_dir = flag_value(&mut args, "--data-dir").map(PathBuf::from);
    let tls_args = tls_flag(&mut args);
    let pinned_dir = flag_value(&mut args, "--pinned").map(PathBuf::from);
    let cheat = flag_value(&mut args, "--cheat").and_then(|c| {
        let parsed = parse_cheat(&c);
        if parsed.is_none() {
            eprintln!("node: unknown cheat {c:?}");
        }
        parsed
    });

    // This process reads ONLY its own secret seed file plus the public
    // committee file — key separation by construction.
    let my_seed = match seed::read_seed(&seed_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("node: reading {} failed: {e}", seed_path.display());
            return ExitCode::FAILURE;
        }
    };
    let info = match seed::read_committee(&committee_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("node: reading {} failed: {e}", committee_path.display());
            return ExitCode::FAILURE;
        }
    };
    let me = my_seed.id;
    let registry: BTreeMap<PartyId, VerifyingKey> = info.registry.iter().cloned().collect();
    // M3c: --tls CERT KEY --pinned DIR enables mTLS on the mesh (SPEC
    // §13.1). All-or-nothing: partial flags are a usage error, never a
    // silent plaintext fallback.
    let tls = match (tls_args, pinned_dir) {
        (Some((cert, key)), Some(pinned)) => {
            match CommitteeTls::from_pem_files(
                me,
                &PathBuf::from(cert),
                &PathBuf::from(key),
                &pinned,
            ) {
                Ok(t) => {
                    eprintln!("[node {me}] mTLS enabled (committee-pinned certs, TLS 1.3)");
                    Some(Arc::new(t))
                }
                Err(e) => {
                    eprintln!("node {me}: loading TLS material failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        (None, None) => None,
        _ => {
            eprintln!("node: --tls CERT KEY and --pinned DIR must be given together");
            return ExitCode::FAILURE;
        }
    };
    let bind_addr: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("node: bad --bind address: {e}");
            return ExitCode::FAILURE;
        }
    };
    let node = match PartyNode::bind_with_tls(
        me,
        info.params,
        &my_seed.transport_key,
        registry,
        bind_addr,
        Duration::from_secs(timeout_secs),
        tls,
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("node {me}: bind failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    node.set_send_delay(Duration::from_millis(delay_ms));

    // M3b (§10.2, §A.4): with `--data-dir`, archive every accepted
    // signed envelope (the §4.7 transcript) plus blame tokens, from the
    // first keygen round on.
    if let Some(dir) = &data_dir {
        if let Err(e) = node.set_archive(&dir.join("archive")) {
            eprintln!(
                "node {me}: opening the archive under {} failed: {e}",
                dir.display()
            );
            return ExitCode::FAILURE;
        }
    }

    // Rendezvous (used by spawn-demo and the process tests): report the
    // bound address on stdout, then read the peer set from stdin.
    let peers = if rendezvous {
        println!("READY {me} {}", node.local_addr());
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            eprintln!("node {me}: reading PEERS from stdin failed");
            return ExitCode::FAILURE;
        }
        match line.trim().strip_prefix("PEERS ").and_then(parse_peers) {
            Some(p) => p,
            None => {
                eprintln!("node {me}: malformed PEERS line: {line:?}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match peers_arg.as_deref().and_then(parse_peers) {
            Some(p) => p,
            None => {
                eprintln!("node: --rendezvous or --peers id@addr,... is required");
                return ExitCode::FAILURE;
            }
        }
    };
    if let Err(e) = node.connect(&peers) {
        eprintln!("node {me}: mesh connect failed: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("[node {me}] mesh up ({} peers)", peers.len() - 1);

    // The committee file's X anchors the demo sids (SPEC §13.1). In the
    // default full-arc mode it is only an anchor — presign and sign run
    // under the FRESH key this process's own keygen produces below.
    let anchor_x = info
        .x
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Phase 1: fresh keygen through the per-node driver (§6 + §6.1
    // complaints/defenses over the wire).
    let phase_start = Instant::now();
    let kg_sid = session_id(GENESIS, &anchor_x, None, b"keygen");
    let mut rng = OsRng;
    let fresh = match node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat) {
        Ok(share) => {
            let x = share.com.points[0].to_affine().to_encoded_point(true);
            println!("X {}", hex(x.as_bytes()));
            eprintln!("[node {me}] keygen complete in {:?}", phase_start.elapsed());
            Some(share)
        }
        Err(Error::Abort { abort }) => {
            println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
            eprintln!("[node {me}] keygen aborted: {}", abort.detail);
            None
        }
        Err(e) => {
            eprintln!("[node {me}] keygen failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Phases 2–3. Default (M3a): the full arc runs under the key THIS
    // keygen just produced — per-node presign (§8 over the wire) yields
    // one in-memory presignature, consumed by one online signature (§9).
    // `--seeded` keeps the M2 fallback: sign with a ceremony-seeded
    // presignature under the ceremony key (the sign phase is then
    // independent of the keygen above).
    if !seeded {
        let Some(share) = fresh else {
            eprintln!("[node {me}] keygen aborted — presign and sign skipped");
            return ExitCode::SUCCESS;
        };
        let x_bytes = share.com.points[0]
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        // M3b (§8.6): with `--data-dir`, open the durable presignature
        // store bound to the FRESH key this keygen just produced; the
        // presign driver persists every record it produces and the sign
        // driver consumes durably (fsync'd tombstone BEFORE the share is
        // broadcast).
        let stored = if let Some(dir) = &data_dir {
            if let Err(e) = node.set_store(&dir.join("store"), &share.com.points[0].to_affine()) {
                eprintln!("node {me}: opening the presignature store failed: {e}");
                return ExitCode::FAILURE;
            }
            true
        } else {
            false
        };

        // Phase 2: per-node presign — two triple sessions (§7.2) plus the
        // §8 P1–P4 rounds, all over the wire.
        let phase_start = Instant::now();
        let ps_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"presign");
        let presig = match node.presign_stored(&ps_sid, presig_id, &share, &mut rng, cheat) {
            Ok(p) => {
                println!("PRESIG {} {}", p.id, hex(&p.r.to_bytes()));
                eprintln!(
                    "[node {me}] presign complete in {:?}",
                    phase_start.elapsed()
                );
                p
            }
            Err(PersistError::Protocol(Error::Abort { abort })) => {
                println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
                eprintln!("[node {me}] presign aborted: {}", abort.detail);
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[node {me}] presign failed: {e}");
                return ExitCode::FAILURE;
            }
        };

        // Phase 3: online signing (§9, §10.4 robust) with the
        // presignature this process just produced — one broadcast round.
        let sign_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"sign");
        return finish_sign(
            &node,
            me,
            &sign_sid,
            &presig,
            stored,
            &message,
            cheat,
            Instant::now(),
        );
    }

    // Seeded fallback (M2): sign with a ceremony-seeded presignature —
    // one broadcast round. With `--data-dir` the records are offered to
    // the durable store first (already-persisted ids are a no-op), so the
    // single-use guarantee holds across restarts here too (§8.6).
    let Some(presig) = my_seed.presigs.iter().find(|p| p.id == presig_id) else {
        eprintln!("node {me}: no presignature id {presig_id} in the seed");
        return ExitCode::FAILURE;
    };
    let mut stored = false;
    if let Some(dir) = &data_dir {
        if let Err(e) = node.set_store(&dir.join("store"), &info.x.to_affine()) {
            eprintln!("node {me}: opening the presignature store failed: {e}");
            return ExitCode::FAILURE;
        }
        for p in &my_seed.presigs {
            if let Err(e) = node.store_offer(p) {
                eprintln!("node {me}: persisting the seeded presignatures failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        stored = true;
    }
    let sign_sid = session_id(GENESIS, &anchor_x, Some(presig_id), b"sign");
    finish_sign(
        &node,
        me,
        &sign_sid,
        presig,
        stored,
        &message,
        cheat,
        Instant::now(),
    )
}

/// The sign phase's outcome handling (shared by the full-arc and seeded
/// paths): print the signature / blame lines and the process exit code.
/// With `stored`, the presignature is CONSUMED from the node's durable
/// store (M3b, §8.6) instead of using the in-memory record.
#[allow(clippy::too_many_arguments)] // the sign phase's full context
fn finish_sign(
    node: &PartyNode,
    me: PartyId,
    sign_sid: &[u8],
    presig: &ohm_ecdsa::presign::Presignature,
    stored: bool,
    message: &[u8],
    cheat: Option<Cheat>,
    started: Instant,
) -> ExitCode {
    let out = if stored {
        node.sign_stored(sign_sid, presig.id, message, cheat)
    } else {
        node.sign(sign_sid, presig, message, cheat)
            .map_err(PersistError::from)
    };
    match out {
        Ok((sig, blamed)) => {
            let (r, s) = sig.split_bytes();
            println!("SIG {} {}", hex(&r), hex(&s));
            if !blamed.is_empty() {
                println!("BLAME sign {}", ids_str(&blamed));
            }
            eprintln!("[node {me}] signature delivered in {:?}", started.elapsed());
            ExitCode::SUCCESS
        }
        Err(PersistError::Protocol(Error::Abort { abort })) => {
            println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
            eprintln!("[node {me}] signing aborted: {}", abort.detail);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[node {me}] signing failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn ids_str(ids: &[PartyId]) -> String {
    ids.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// --- auditor: offline blame-token verification (SPEC §10.2, §A.4) -------------

/// `auditor TOKEN_FILE COMMITTEE_FILE` — the §A.4 evidence flow: load a
/// blame-token file (as archived by a node's `--data-dir`) and verify it
/// OFFLINE against the committee's PUBLIC transport keys. Prints every
/// check and a final verdict; exit 0 iff the token substantiates the
/// blame. No secret material is read.
fn auditor(args: &[String]) -> ExitCode {
    let (Some(token_path), Some(committee_path)) = (args.first(), args.get(1)) else {
        eprintln!("auditor: TOKEN_FILE and COMMITTEE_FILE are required");
        return ExitCode::FAILURE;
    };
    let bytes = match std::fs::read(token_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("auditor: reading {token_path} failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let info = match seed::read_committee(std::path::Path::new(committee_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auditor: reading {committee_path} failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = persist::audit_token(&bytes, &info.registry);
    println!("auditing {token_path} ({} bytes)", bytes.len());
    println!(
        "  claimed: phase {}, blamed parties [{}]",
        report.phase,
        ids_str(&report.blamed)
    );
    for (what, ok) in &report.checks {
        println!("  [{}] {what}", if *ok { "ok" } else { "FAIL" });
    }
    if report.verdict() {
        println!("VERDICT: VALID — the token substantiates the blame (SPEC §A.4)");
        ExitCode::SUCCESS
    } else {
        println!("VERDICT: INVALID — the token does NOT substantiate the blame");
        ExitCode::FAILURE
    }
}

// --- spawn-demo: three child processes -----------------------------------------

fn spawn_demo(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let dir = flag_value(&mut args, "--dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            std::env::temp_dir().join(format!("ohm-m2-demo-{}-{nanos}", std::process::id()))
        });
    let delay_ms: u64 = flag_value(&mut args, "--delay-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let cheat_node: Option<PartyId> =
        flag_value(&mut args, "--cheat-node").and_then(|v| v.parse().ok());
    let cheat = flag_value(&mut args, "--cheat").and_then(|c| parse_cheat(&c));
    let seeded = has_flag(&mut args, "--seeded");
    let persist = has_flag(&mut args, "--persist");
    let with_tls = has_flag(&mut args, "--tls");

    if seeded {
        println!("== ohm-ecdsa-node M2/M3a demo (SEEDED fallback): 2-of-3 keygen + sign across 3 OS processes ==");
    } else if with_tls {
        println!(
            "== ohm-ecdsa-node M3c demo: 2-of-3 keygen → presign → sign across 3 OS processes over mTLS =="
        );
    } else {
        println!(
            "== ohm-ecdsa-node M3a demo: 2-of-3 keygen → presign → sign across 3 OS processes =="
        );
    }
    let params = Params::new(3, 2).expect("valid params");
    let ceremony_seed = rand::RngCore::next_u64(&mut OsRng);
    let (info, seeds) = seed::ceremony(&params, 1, ceremony_seed);
    if let Err(e) = seed::write_all(&dir, &info, &seeds) {
        eprintln!("spawn-demo: writing seed files failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("  ceremony seeds written to {}", dir.display());
    if with_tls {
        // M3c: per-party self-signed certs; every child pins the whole
        // committee set (--pinned DIR) and presents its own cert+key.
        if let Err(e) = tls::write_committee_certs(&dir, &[1, 2, 3]) {
            eprintln!("spawn-demo: writing TLS certificates failed: {e}");
            return ExitCode::FAILURE;
        }
        println!("  mTLS (M3c): TLS 1.3, per-party self-signed certs pinned to the committee");
    }
    if !seeded {
        println!("  full arc: each process presigns under the key its OWN keygen produced");
    }
    if let (Some(k), Some(c)) = (cheat_node, cheat) {
        println!("  fault injection: node {k} runs with --cheat {c:?}");
    }
    if persist {
        println!(
            "  persistence (M3b): per-node --data-dir under {} (durable presig store + transcript/blame archive)",
            dir.display()
        );
    }

    // Launch the children; each prints READY with its ephemeral address.
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("spawn-demo: locating the node binary failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut children = Vec::new();
    for i in 1..=3usize {
        let mut cmd = Command::new(&exe);
        cmd.arg("node")
            .arg("--seed")
            .arg(seed::seed_file(&dir, i))
            .arg("--committee")
            .arg(dir.join(seed::COMMITTEE_FILE))
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--rendezvous")
            .arg("--delay-ms")
            .arg(delay_ms.to_string());
        if seeded {
            cmd.arg("--seeded");
        }
        if persist {
            cmd.arg("--data-dir").arg(dir.join(format!("node-{i}")));
        }
        if with_tls {
            cmd.arg("--tls")
                .arg(tls::cert_file(&dir, i))
                .arg(tls::key_file(&dir, i))
                .arg("--pinned")
                .arg(&dir);
        }
        if cheat_node == Some(i) {
            if let Some(c) = cheat {
                cmd.arg("--cheat").arg(cheat_arg(c));
            }
        }
        let child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn();
        match child {
            Ok(c) => children.push(c),
            Err(e) => {
                eprintln!("spawn-demo: launching node {i} failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Read each child's READY line, then hand every child the full peer
    // set over its stdin.
    let mut readers = Vec::new();
    let mut addrs: Vec<(PartyId, SocketAddr)> = Vec::new();
    for (i, child) in children.iter_mut().enumerate() {
        let id = i + 1;
        let stdout = child.stdout.take().expect("stdout piped");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(_) if line.starts_with("READY") => {
                let addr: SocketAddr = line
                    .split_whitespace()
                    .nth(2)
                    .and_then(|a| a.parse().ok())
                    .expect("READY carries an address");
                println!("[node {id}] {}", line.trim());
                addrs.push((id, addr));
            }
            other => {
                eprintln!("spawn-demo: node {id} did not report READY ({other:?})");
                return ExitCode::FAILURE;
            }
        }
        readers.push(reader);
    }
    let peers_line = format!(
        "PEERS {}\n",
        addrs
            .iter()
            .map(|(id, a)| format!("{id}@{a}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    for child in &mut children {
        let mut stdin = child.stdin.take().expect("stdin piped");
        if let Err(e) = stdin.write_all(peers_line.as_bytes()) {
            eprintln!("spawn-demo: writing PEERS failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Forward the remaining per-process output with a [node i] prefix,
    // collecting it for the summary below.
    let mut forwarders = Vec::new();
    for (i, reader) in readers.into_iter().enumerate() {
        let id = i + 1;
        forwarders.push(std::thread::spawn(move || {
            let mut lines = Vec::new();
            for line in reader.lines() {
                let Ok(line) = line else { break };
                println!("[node {id}] {line}");
                lines.push(line);
            }
            lines
        }));
    }
    let mut ok = true;
    for (i, mut child) in children.into_iter().enumerate() {
        match child.wait() {
            Ok(status) if status.success() => {}
            other => {
                eprintln!("spawn-demo: node {} exited abnormally: {other:?}", i + 1);
                ok = false;
            }
        }
    }
    let mut node_lines = Vec::new();
    for f in forwarders {
        node_lines.push(f.join().unwrap_or_default());
    }

    if summarize(&info, seeded, &node_lines) && ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cheat_arg(c: Cheat) -> String {
    match c {
        Cheat::BadDeal { victim } => format!("bad-deal:{victim}"),
        Cheat::FalseAccuse { dealer } => format!("false-accuse:{dealer}"),
        Cheat::BadSignShare => "bad-sign-share".into(),
        Cheat::BadProductProof => "bad-product-proof".into(),
        Cheat::BadReshare { victim } => format!("bad-reshare:{victim}"),
        Cheat::BadNoncePoint => "bad-nonce-point".into(),
        Cheat::BadOpenShare => "bad-open-share".into(),
    }
}

/// Cross-check the per-process outputs and print the RESULT lines the
/// process-level tests assert on. Returns the demo's success verdict.
fn summarize(info: &CommitteeInfo, seeded: bool, node_lines: &[Vec<String>]) -> bool {
    let mut ok = true;
    // Keygen: either every process prints the same X, or every process
    // names the same blamed party.
    let xs: Vec<&str> = node_lines
        .iter()
        .filter_map(|lines| lines.iter().find(|l| l.starts_with("X ")))
        .map(|l| l.as_str())
        .collect();
    let keygen_ok = xs.len() == 3 && xs.iter().all(|x| *x == xs[0]);
    if keygen_ok {
        println!("RESULT keygen: all 3 processes agree on {}", xs[0]);
    } else {
        let blames: Vec<Vec<String>> = node_lines
            .iter()
            .map(|lines| {
                lines
                    .iter()
                    .filter(|l| l.starts_with("BLAME keygen"))
                    .cloned()
                    .collect()
            })
            .collect();
        let consistent =
            blames.iter().all(|b| b.len() == 1) && blames.iter().all(|b| b[0] == blames[0][0]);
        if xs.is_empty() && consistent {
            println!(
                "RESULT keygen: aborted consistently — every process reports {:?}",
                blames[0][0]
            );
        } else {
            println!("RESULT keygen: INCONSISTENT (xs={xs:?}, blames={blames:?})");
            ok = false;
        }
    }

    // Presign (full-arc mode only): either every process prints the same
    // PRESIG line, or every process names the same blamed party in the
    // offline factory (BLAME triples | BLAME presign).
    let mut presign_ok = seeded;
    if keygen_ok && !seeded {
        let presigs: Vec<&str> = node_lines
            .iter()
            .filter_map(|lines| lines.iter().find(|l| l.starts_with("PRESIG ")))
            .map(|l| l.as_str())
            .collect();
        if presigs.len() == 3 && presigs.iter().all(|p| *p == presigs[0]) {
            println!("RESULT presign: all 3 processes agree on {}", presigs[0]);
            presign_ok = true;
        } else {
            let blames: Vec<Vec<String>> = node_lines
                .iter()
                .map(|lines| {
                    lines
                        .iter()
                        .filter(|l| {
                            l.starts_with("BLAME triples") || l.starts_with("BLAME presign")
                        })
                        .cloned()
                        .collect()
                })
                .collect();
            let consistent =
                blames.iter().all(|b| b.len() == 1) && blames.iter().all(|b| b[0] == blames[0][0]);
            if presigs.is_empty() && consistent {
                println!(
                    "RESULT presign: aborted consistently — every process reports {:?}",
                    blames[0][0]
                );
            } else {
                println!("RESULT presign: INCONSISTENT (presigs={presigs:?}, blames={blames:?})");
                ok = false;
            }
        }
    } else if !seeded {
        println!("RESULT presign: skipped (keygen aborted)");
    }

    // Sign: every process prints the same SIG; verify it under the key
    // that signed — the FRESH keygen key in full-arc mode (parsed from
    // the X lines), the ceremony key in --seeded mode. Blame lines are
    // summarized per process.
    let sigs: Vec<&str> = node_lines
        .iter()
        .filter_map(|lines| lines.iter().find(|l| l.starts_with("SIG ")))
        .map(|l| l.as_str())
        .collect();
    if sigs.len() == 3 && sigs.iter().all(|s| *s == sigs[0]) {
        let sig = hex_decode(&sigs[0].replace("SIG ", "").replace(' ', ""))
            .and_then(|b| Signature::from_slice(&b).ok());
        let vk = if seeded {
            VerifyingKey::from_affine(info.x.to_affine()).ok()
        } else {
            xs[0]
                .strip_prefix("X ")
                .and_then(hex_decode)
                .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
        };
        let verified = match (vk, sig) {
            (Some(vk), Some(sig)) => vk.verify(DEMO_MESSAGE, &sig).is_ok(),
            _ => false,
        };
        println!("RESULT sign: all 3 processes agree; signature verifies under X: {verified}");
        ok &= verified;
    } else if !keygen_ok || !presign_ok {
        println!("RESULT sign: skipped (earlier phase aborted)");
    } else {
        println!("RESULT sign: MISSING or DISAGREEING signatures (sigs={sigs:?})");
        ok = false;
    }
    for (i, lines) in node_lines.iter().enumerate() {
        for line in lines.iter().filter(|l| l.starts_with("BLAME")) {
            println!("RESULT blame: node {} reports {line:?}", i + 1);
        }
    }
    if ok {
        println!("RESULT demo: SUCCESS");
    } else {
        println!("RESULT demo: FAILURE");
    }
    ok
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

// --- the original M1 orchestrator demo -----------------------------------------

fn m1_demo(port_base: u16) -> ExitCode {
    println!("== ohm-ecdsa-node M1 demo: 2-of-3 keygen over real TCP ==");
    let params = Params::new(3, 2).expect("valid params");

    // Transport keys (the deployment PKI of SPEC §13.1), one per party;
    // M1 is the reference-orchestration pattern, so this one process
    // holds all three.
    let signers: Vec<(usize, SecretKey)> = (1..=3)
        .map(|i| (i, SecretKey::random(&mut OsRng)))
        .collect();

    let parties: Vec<(usize, SocketAddr)> = (1..=3usize)
        .map(|i| {
            let port = if port_base == 0 {
                0
            } else {
                port_base + i as u16 - 1
            };
            (i, SocketAddr::from(([127, 0, 0, 1], port)))
        })
        .collect();
    let mesh = match MeshTransport::start(&parties, &signers, DEFAULT_ROUND_TIMEOUT) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mesh setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    for (id, addr) in mesh.local_addrs() {
        println!("  node {id} listening on {addr}");
    }
    println!("  full mesh up; echo broadcast accepts on 2-of-3 consistent echoes");
    println!("  every envelope is signed by its sender and verified on receipt");

    let mut transport = SigningTransport::new(mesh, &signers);
    let sid = session_id(b"ohm-ecdsa-node/demo", b"demo-key", None, b"keygen");
    let mut rngs: Vec<_> = (0..3).map(|_| OsRng).collect();
    let outs = match drive_dkg_signed(
        &params,
        &sid,
        b"ohm-ecdsa-node/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    ) {
        Ok(outs) => outs,
        Err(e) => {
            eprintln!("keygen aborted: {e}");
            return ExitCode::FAILURE;
        }
    };
    for out in &outs {
        println!("  party {} holds key share x_{}", out.index, out.index);
    }
    let x = outs[0].com.points[0].to_affine().to_encoded_point(true);
    println!("  joint public key X = {}", hex(x.as_bytes()));
    println!("  keygen complete through drive_dkg_signed over MeshTransport");
    ExitCode::SUCCESS
}
