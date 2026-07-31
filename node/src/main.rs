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
//!   wraps the mesh in mTLS with committee-pinned certs. `--restart`
//!   (H4, §10.4 + §10.3) runs the arc on the ROBUST drivers with the
//!   expel-and-restart policy: continuable faults are filtered with
//!   blame in-attempt; dealing-phase aborts expel the blamed and re-run
//!   over the surviving committee (original ids, poisoned sid/id; never
//!   lowering `t`). Default stays fail-fast — some deployments prefer
//!   loud aborts.
//! * `setup` — **DEMO-ONLY**: the one-process ceremony writing the
//!   public committee file and one SECRET seed file per party — a single
//!   machine momentarily holds EVERY party's transport secret key. For
//!   anything real use the distributed ceremony (`init` + `assemble`,
//!   below). `--tls` also writes per-party self-signed certs for the
//!   M3c mTLS mesh.
//! * `init` — H3 distributed ceremony, per-party step: on its OWN
//!   machine each party generates its own transport keypair (plus its
//!   self-signed cert with `--tls`), writes the SECRET
//!   `party-<id>.identity` and the PUBLIC `party-<id>.pub` bundle, and
//!   prints the bundle's fingerprint for out-of-band verification.
//! * `assemble` — H3 distributed ceremony, PUBLIC assembly step (safe
//!   to run anywhere): validates the collected `.pub` bundles and
//!   writes the shared `committee.hex` (the format every consumer
//!   already reads) plus the pinned cert set with TLS. Prints every
//!   party's fingerprint for cross-checking.
//! * `spawn-demo` — **DEMO-ONLY** showcase: set up a 2-of-3 committee
//!   IN THIS PROCESS (it holds all keys) and launch
//!   three child `node` processes on localhost, keygen → presign → sign
//!   across real processes, printing per-process logs, per-phase timings,
//!   the joint key, the signature, and any blame. `--cheat-node K
//!   --cheat C` drives child K into a cheater; `--seeded` falls back to
//!   the M2 seeded-sign demo; `--tls` (M3c) generates per-party certs
//!   and runs the arc over mTLS; `--ki` (§8.7) runs the key-independent
//!   arc: keygen → KEY-FREE pool record → 2-round online KI sign under
//!   the key the processes' own keygen produced; `--restart` (H4) runs
//!   the arc on the §10.4-robust + §10.3-restart drivers.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ohm_ecdsa::presign::{KeyShare, Presignature};
use ohm_ecdsa::transport::{drive_dkg_signed, SigningTransport};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::ceremony::{self, PubBundle};
use ohm_ecdsa_node::persist::{self, PersistError};
use ohm_ecdsa_node::pool::{PoolConfig, PoolManager};
use ohm_ecdsa_node::seed::{self, CommitteeInfo};
use ohm_ecdsa_node::tls::{self, CommitteeTls};
use ohm_ecdsa_node::{Cheat, MeshTransport, PartyNode, DEFAULT_ROUND_TIMEOUT};
use rand::rngs::OsRng;

/// Genesis anchor for the demo sids (SPEC §13.1).
const GENESIS: &[u8] = b"ohm-ecdsa-node/m2-demo";
/// The message the demo committee signs.
const DEMO_MESSAGE: &[u8] = b"ohm-ecdsa-node M2 demo: signed across real OS processes";
/// The messages the `--factory N` demo signs while the background
/// presignature factory keeps running (H2 Phase 3 — concurrent
/// sessions): distinct from each other and from [`DEMO_MESSAGE`].
const FACTORY_MESSAGES: [&[u8]; 3] = [
    b"ohm-ecdsa-node factory demo: message 1",
    b"ohm-ecdsa-node factory demo: message 2",
    b"ohm-ecdsa-node factory demo: message 3",
];
/// DKG commit tag for the per-node keygen driver.
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/dkg";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("m1-demo") => m1_demo(args.get(1).and_then(|a| a.parse().ok()).unwrap_or(0)),
        Some("setup") => setup(&args[1..]),
        Some("init") => init_mode(&args[1..]),
        Some("assemble") => assemble_mode(&args[1..]),
        Some("node") => node_mode(&args[1..]),
        Some("spawn-demo") => spawn_demo(&args[1..]),
        Some("auditor") => auditor(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  \
                 ohm-ecdsa-node m1-demo [PORT_BASE]\n  \
                 ohm-ecdsa-node init --id N --dir DIR [--addr HOST:PORT] [--tls]   (H3: per-party, on its OWN machine)\n  \
                 ohm-ecdsa-node assemble --committee DIR --inputs PUB,... [--t T]  (H3: PUBLIC, safe anywhere)\n  \
                 ohm-ecdsa-node setup --dir DIR [--presigs K] [--seed S] [--tls]   (DEMO-ONLY: one process holds ALL keys)\n  \
                 ohm-ecdsa-node node (--seed FILE | --identity FILE) --committee FILE --bind ADDR \\\n    \
                 [--rendezvous | --peers id@host:port,...] [--delay-ms D] [--seeded] [--ki] \\\n    \
                 [--round-timeout-secs S] [--cheat C] [--presig-id K] [--message MSG] \\\n    \
                 [--data-dir DIR] [--tls CERT KEY --pinned DIR] [--factory N] [--pool-ttl SECS] [--restart]\n  \
                 ohm-ecdsa-node spawn-demo [--dir DIR] [--delay-ms D] [--seeded] [--persist] \\\n    \
                 [--tls] [--ki] [--factory N] [--pool-ttl SECS] [--restart] [--cheat-node K --cheat C]   (DEMO-ONLY)\n  \
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
    eprintln!(
        "WARNING: DEMO-ONLY ceremony — this one process momentarily holds ALL parties' secret"
    );
    eprintln!(
        "         transport keys. For a real committee use the distributed ceremony instead:"
    );
    eprintln!(
        "         `init` (per party, on its own machine) → exchange .pub out-of-band → `assemble`."
    );
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

// --- H3: the distributed committee ceremony -----------------------------------
//
// The standard setup path for a real committee: each party runs `init`
// on its OWN machine (its secrets never leave), the PUBLIC `.pub`
// bundles travel out of band over an authenticated channel (the
// fingerprints below exist for the second-channel cross-check), and
// `assemble` — public data only, safe to run anywhere — writes the
// shared committee file. See `node/src/ceremony.rs` for the trust model.

fn init_mode(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let (Some(id), Some(dir)) = (
        flag_value(&mut args, "--id").and_then(|v| v.parse::<PartyId>().ok()),
        flag_value(&mut args, "--dir").map(PathBuf::from),
    ) else {
        eprintln!("init: --id N and --dir DIR are required");
        return ExitCode::FAILURE;
    };
    let addr = flag_value(&mut args, "--addr").unwrap_or_default();
    let with_tls = has_flag(&mut args, "--tls");
    match ceremony::init(id, &dir, &addr, with_tls) {
        Ok(bundle) => {
            println!(
                "party {id} initialized (secrets stay in {} — back it up and guard it)",
                dir.display()
            );
            println!(
                "  SECRET identity:  {} (ONLY this party may read it)",
                ceremony::identity_file(&dir, id).display()
            );
            if with_tls {
                println!("  SECRET TLS key:   {}", tls::key_file(&dir, id).display());
            }
            println!(
                "  PUBLIC bundle:    {} — distribute it over an AUTHENTICATED channel",
                ceremony::pub_file(&dir, id).display()
            );
            println!("  FINGERPRINT {}", ceremony::fingerprint(&bundle));
            println!(
                "  confirm this fingerprint with every other party out-of-band before assemble"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("init: {e}");
            ExitCode::FAILURE
        }
    }
}

fn assemble_mode(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let (Some(dir), Some(inputs)) = (
        flag_value(&mut args, "--committee").map(PathBuf::from),
        flag_value(&mut args, "--inputs"),
    ) else {
        eprintln!("assemble: --committee DIR and --inputs PUB,... are required");
        return ExitCode::FAILURE;
    };
    let t: Option<usize> = flag_value(&mut args, "--t").and_then(|v| v.parse().ok());
    let mut bundles: Vec<PubBundle> = Vec::new();
    for path in inputs.split(',') {
        match ceremony::read_pub(std::path::Path::new(path)) {
            Ok(b) => bundles.push(b),
            Err(e) => {
                eprintln!("assemble: reading {path} failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    match ceremony::assemble(&bundles, t, &dir) {
        Ok(info) => {
            let with_tls = bundles.iter().any(|b| !b.cert_pem.is_empty());
            println!(
                "committee assembled: {}-of-{} (parties 1..={})",
                info.params.t, info.params.n, info.params.n
            );
            println!(
                "  public committee file: {}",
                dir.join(seed::COMMITTEE_FILE).display()
            );
            if with_tls {
                println!(
                    "  pinned M3c cert set:   {} (pass as --pinned to every node)",
                    dir.display()
                );
            }
            println!("  VERIFY these fingerprints out-of-band against every party:");
            for b in &bundles {
                println!(
                    "    party {} fingerprint {}",
                    b.id,
                    ceremony::fingerprint(b)
                );
            }
            if bundles.iter().all(|b| !b.addr.is_empty()) {
                println!(
                    "  suggested --peers: {}",
                    bundles
                        .iter()
                        .map(|b| format!("{}@{}", b.id, b.addr))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("assemble: {e}");
            ExitCode::FAILURE
        }
    }
}

// --- node mode: one party, one process ----------------------------------------

fn node_mode(args: &[String]) -> ExitCode {
    let mut args = args.to_vec();
    let (Some(committee_path), Some(bind)) = (
        flag_value(&mut args, "--committee").map(PathBuf::from),
        flag_value(&mut args, "--bind"),
    ) else {
        eprintln!("node: --committee and --bind are required");
        return ExitCode::FAILURE;
    };
    // Exactly one secret source: `--seed` (the DEMO-ONLY one-process
    // ceremony — carries a ceremony key share and presignatures for the
    // `--seeded` fallback) or `--identity` (the H3 distributed ceremony —
    // only this party's own transport key, generated on its own machine).
    let seed_path = flag_value(&mut args, "--seed").map(PathBuf::from);
    let identity_path = flag_value(&mut args, "--identity").map(PathBuf::from);
    let rendezvous = has_flag(&mut args, "--rendezvous");
    let seeded = has_flag(&mut args, "--seeded");
    let ki = has_flag(&mut args, "--ki");
    // H4 (§10.4 + §10.3): `--restart` runs the arc on the ROBUST drivers
    // with the expel-and-restart policy — a cheater causes blame +
    // continued service, not an outage (default stays fail-fast: some
    // deployments prefer loud aborts).
    let restart = has_flag(&mut args, "--restart");
    // H2 Phase 3: `--factory N` runs the concurrent-sessions demo — a
    // background H5 pool manager keeps N presignatures in the node's
    // durable store while the main thread signs. `--pool-ttl SECS`
    // (H5, §8.6(3)) expires records older than SECS (0 = never).
    let factory: Option<usize> = flag_value(&mut args, "--factory").and_then(|v| v.parse().ok());
    let pool_ttl: u64 = flag_value(&mut args, "--pool-ttl")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
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

    if factory.is_some() && (seeded || ki) {
        eprintln!("node: --factory does not combine with --seeded or --ki");
        return ExitCode::FAILURE;
    }
    if pool_ttl > 0 && factory.is_none() {
        eprintln!("node: --pool-ttl only makes sense with --factory N");
        return ExitCode::FAILURE;
    }
    if restart && (seeded || ki || factory.is_some()) {
        eprintln!("node: --restart does not combine with --seeded, --ki, or --factory");
        return ExitCode::FAILURE;
    }

    // This process reads ONLY its own secret material plus the public
    // committee file — key separation by construction.
    let (me, transport_key, seed_presigs) = match (seed_path, identity_path) {
        (Some(path), None) => match seed::read_seed(&path) {
            Ok(s) => (s.id, s.transport_key, Some(s.presigs)),
            Err(e) => {
                eprintln!("node: reading {} failed: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
        (None, Some(path)) => match ceremony::read_identity(&path) {
            Ok(i) => (i.id, i.transport_key, None),
            Err(e) => {
                eprintln!("node: reading {} failed: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
        _ => {
            eprintln!("node: exactly one of --seed FILE or --identity FILE is required");
            return ExitCode::FAILURE;
        }
    };
    if seeded && seed_presigs.is_none() {
        eprintln!(
            "node: --seeded needs a ceremony seed file (--seed); a distributed-ceremony identity has no ceremony presignatures"
        );
        return ExitCode::FAILURE;
    }
    let info = match seed::read_committee(&committee_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("node: reading {} failed: {e}", committee_path.display());
            return ExitCode::FAILURE;
        }
    };
    let registry: BTreeMap<PartyId, VerifyingKey> = info.registry.iter().cloned().collect();
    // Fail closed on a tampered or mismatched committee file: this
    // node's own transport secret key MUST match its registry entry
    // (with the distributed ceremony this is the backstop for a swapped
    // `.pub` bundle that survived the out-of-band check).
    if registry.get(&me) != Some(SigningKey::from(&transport_key).verifying_key()) {
        eprintln!(
            "node {me}: own transport key does not match the committee registry entry \
             (tampered or wrong committee file?)"
        );
        return ExitCode::FAILURE;
    }
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
        &transport_key,
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
    // complaints/defenses over the wire). With `--restart` (H4 §10.3) a
    // dealing-phase cheater is expelled and the session re-runs over the
    // surviving committee with original ids (zero-slack refusal — e.g.
    // 2-of-3 — propagates the abort; `t` is never lowered).
    let phase_start = Instant::now();
    let kg_sid = session_id(GENESIS, &anchor_x, None, b"keygen");
    let mut rng = OsRng;
    let kg_out = if restart {
        node.keygen_with_restart(&kg_sid, DKG_TAG, &mut rng, cheat)
    } else {
        node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)
            .map(|share| (share, info.params.parties(), Vec::new()))
    };
    let (fresh, committee) = match kg_out {
        Ok((share, committee, blamed)) => {
            let x = share.com.points[0].to_affine().to_encoded_point(true);
            println!("X {}", hex(x.as_bytes()));
            if !blamed.is_empty() {
                println!("BLAME keygen {}", ids_str(&blamed));
            }
            eprintln!("[node {me}] keygen complete in {:?}", phase_start.elapsed());
            (Some(share), committee)
        }
        Err(Error::Abort { abort }) => {
            println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
            eprintln!("[node {me}] keygen aborted: {}", abort.detail);
            (None, Vec::new())
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

        // H2 Phase 3 (concurrent sessions): `--factory N` — the H5 pool
        // manager keeps N presignatures in the node's DURABLE store while
        // the main thread signs FACTORY_MESSAGES against consumed
        // records (`--pool-ttl` expires aged records, §8.6(3)). Every
        // session (factory presign, online sign) is demultiplexed by sid
        // in the acceptor and progresses concurrently; the node is shut
        // down cleanly at the end.
        if let Some(target) = factory {
            return run_factory_demo(
                Arc::new(node),
                me,
                share,
                x_bytes,
                target,
                pool_ttl,
                data_dir.clone(),
                cheat,
            );
        }

        // §8.7 KI mode: produce a KEY-FREE pool record (P1–P3 only — no
        // key involved), then bind it to the fresh key ONLINE with the
        // 2-round KI sign. The pool is in-memory (§8.7 storage
        // relaxation); `--data-dir`'s durable store stays per-key and is
        // not used for pool records.
        if ki {
            let phase_start = Instant::now();
            let ps_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"presign-ki");
            match node.presign_ki_pooled(&ps_sid, presig_id, &mut rng, cheat) {
                Ok(r) => {
                    println!("PRESIG {} {}", presig_id, hex(&r.to_bytes()));
                    eprintln!(
                        "[node {me}] KI pool record produced in {:?}",
                        phase_start.elapsed()
                    );
                }
                Err(Error::Abort { abort }) => {
                    println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
                    eprintln!("[node {me}] KI presign aborted: {}", abort.detail);
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("[node {me}] KI presign failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
            let sign_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"sign-ki");
            return finish_sign_ki(
                &node,
                me,
                &sign_sid,
                presig_id,
                &share,
                &message,
                &mut rng,
                cheat,
                Instant::now(),
            );
        }

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

        // Phase 2+3 with `--restart` (H4 §10.4 + §10.3): the ROBUST
        // presign composed with expel-and-restart — continuable faults
        // (bad opening shares, bad nonce points) are filtered in-attempt
        // with blame; dealing-phase aborts expel the blamed and re-run
        // over the surviving committee with a poisoned sid and id. The
        // survivors then sign over the final committee.
        if restart {
            let phase_start = Instant::now();
            let ps_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"presign");
            match node
                .presign_with_restart_over(&ps_sid, presig_id, &share, &committee, &mut rng, cheat)
            {
                Ok((presig, used_id, ps_committee, blamed)) => {
                    println!("PRESIG {} {}", presig.id, hex(&presig.r.to_bytes()));
                    if !blamed.is_empty() {
                        println!("BLAME presign {}", ids_str(&blamed));
                    }
                    eprintln!(
                        "[node {me}] presign complete in {:?} (id {used_id}, committee {ps_committee:?})",
                        phase_start.elapsed()
                    );
                    if stored {
                        // M3b: persist the produced record (id poisoning
                        // already guarantees freshness, §10.3(2)).
                        if let Err(e) = node.store_offer(&presig) {
                            eprintln!("node {me}: persisting the presignature failed: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                    let sign_sid = session_id(GENESIS, &x_bytes, Some(used_id), b"sign");
                    return finish_sign(
                        &node,
                        me,
                        &sign_sid,
                        &presig,
                        &ps_committee,
                        stored,
                        &message,
                        cheat,
                        Instant::now(),
                    );
                }
                Err(Error::Abort { abort }) => {
                    println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
                    eprintln!("[node {me}] presign aborted: {}", abort.detail);
                    return ExitCode::SUCCESS;
                }
                Err(e) => {
                    eprintln!("[node {me}] presign failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }

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
            &info.params.parties(),
            stored,
            &message,
            cheat,
            Instant::now(),
        );
    }

    // Seeded fallback (M2): sign with a ceremony-seeded presignature —
    // one broadcast round. With `--data-dir` the records are offered to
    // the durable store first (already-persisted ids are a no-op), so the
    // single-use guarantee holds across restarts here too (§8.6). Only
    // reachable with `--seed` (`--identity` + `--seeded` is rejected at
    // startup above).
    let seed_presigs = seed_presigs.expect("--seeded requires --seed");
    let Some(presig) = seed_presigs.iter().find(|p| p.id == presig_id) else {
        eprintln!("node {me}: no presignature id {presig_id} in the seed");
        return ExitCode::FAILURE;
    };
    let mut stored = false;
    if let Some(dir) = &data_dir {
        if let Err(e) = node.set_store(&dir.join("store"), &info.x.to_affine()) {
            eprintln!("node {me}: opening the presignature store failed: {e}");
            return ExitCode::FAILURE;
        }
        for p in &seed_presigs {
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
        &info.params.parties(),
        stored,
        &message,
        cheat,
        Instant::now(),
    )
}

/// The sign phase's outcome handling (shared by the full-arc, restart,
/// and seeded paths): print the signature / blame lines and the process
/// exit code. With `stored`, the presignature is CONSUMED from the
/// node's durable store (M3b, §8.6) instead of using the in-memory
/// record. `ids` is the signing committee (H4: the post-restart
/// survivors with original ids; the full committee otherwise).
#[allow(clippy::too_many_arguments)] // the sign phase's full context
fn finish_sign(
    node: &PartyNode,
    me: PartyId,
    sign_sid: &[u8],
    presig: &ohm_ecdsa::presign::Presignature,
    ids: &[PartyId],
    stored: bool,
    message: &[u8],
    cheat: Option<Cheat>,
    started: Instant,
) -> ExitCode {
    let out = if stored {
        node.sign_stored_over(sign_sid, presig.id, message, ids, cheat)
    } else {
        node.sign_over(sign_sid, presig, message, ids, cheat)
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

/// The KI sign phase's outcome handling (§8.7): the pool record is
/// ATOMICALLY CONSUMED from the node's in-memory key-free pool (§8.6(1))
/// and bound to `key` online in the 2-round KI sign; print the signature
/// / blame lines and the process exit code.
#[allow(clippy::too_many_arguments)] // the KI sign phase's full context
fn finish_sign_ki(
    node: &PartyNode,
    me: PartyId,
    sign_sid: &[u8],
    presig_id: u64,
    key: &ohm_ecdsa::presign::KeyShare,
    message: &[u8],
    rng: &mut impl rand::RngCore,
    cheat: Option<Cheat>,
    started: Instant,
) -> ExitCode {
    match node.sign_ki_pooled(sign_sid, presig_id, key, message, rng, cheat) {
        Ok(sig) => {
            let (r, s) = sig.split_bytes();
            println!("SIG {} {}", hex(&r), hex(&s));
            eprintln!(
                "[node {me}] KI signature delivered in {:?}",
                started.elapsed()
            );
            ExitCode::SUCCESS
        }
        Err(Error::Abort { abort }) => {
            println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
            eprintln!("[node {me}] KI signing aborted: {}", abort.detail);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[node {me}] KI signing failed: {e}");
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

/// H2 Phase 3 proving ground (`node --factory N`, concurrent sessions)
/// on the H5 POOL MANAGER: a background [`PoolManager`] thread keeps
/// `target` presignatures in the node's DURABLE store (M3b sealed
/// records, §8.6 — the manager is the single writer) while the main
/// thread signs [`FACTORY_MESSAGES`], consuming the OLDEST live record
/// per message via `sign_stored` (the consume tombstone is fsync'd
/// before the share is broadcast). `--pool-ttl SECS` (H5, §8.6(3))
/// expires aged records (erased, never served, ids burned). All three
/// node processes run the same deterministic session sequence (presign
/// ids `1..` in pool order — re-seeded from the persisted store after a
/// restart, never re-issued; sign id = the consumed record's id), so
/// their sids line up without any extra coordination; a sign session
/// starting while another node's factory session is mid-flight is
/// exactly the overlap this demonstrates. Prints one `SIG` line per
/// message and a final `FACTORY` line (target/produced/stored/expired/
/// signed); the node is shut down cleanly before exit. Without
/// `--data-dir` the pool store lives in a per-process temp dir removed
/// at the end.
#[allow(clippy::too_many_arguments)] // demo wiring: node + arc state + pool config
fn run_factory_demo(
    node: Arc<PartyNode>,
    me: PartyId,
    share: KeyShare,
    x_bytes: Vec<u8>,
    target: usize,
    pool_ttl: u64,
    data_dir: Option<PathBuf>,
    cheat: Option<Cheat>,
) -> ExitCode {
    // H5: the pool lives in the durable store (§8.6 — sealed, 0600).
    let (store_dir, cleanup) = match &data_dir {
        Some(d) => (d.join("store"), false),
        None => (
            std::env::temp_dir().join(format!("ohm-factory-store-{}-{me}", std::process::id())),
            true,
        ),
    };
    if let Err(e) = node.set_store(&store_dir, &share.com.points[0].to_affine()) {
        eprintln!("[node {me}] opening the pool store failed: {e}");
        return ExitCode::FAILURE;
    }
    let store = node.store_handle();
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));

    // The pool manager thread (H5): refill to `target`, expire records
    // older than `pool_ttl` (0 = never). Production is the ordinary
    // per-node §8 presign over the wire — concurrent with the sign
    // sessions below (H2 sid demultiplexing).
    let mut manager = {
        let node = Arc::clone(&node);
        let x_bytes = x_bytes.clone();
        let produce = move |id: u64| -> Result<Presignature, PersistError> {
            let sid = session_id(GENESIS, &x_bytes, Some(id), b"presign");
            let mut rng = OsRng;
            node.presign(&sid, id, &share, &mut rng, cheat)
                .map_err(|e| {
                    if let Error::Abort { abort } = &e {
                        println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
                    }
                    eprintln!("[node {me}] factory presign failed: {e}");
                    e.into()
                })
        };
        let mut cfg = PoolConfig::new(target, pool_ttl);
        cfg.label = format!("pool node-{me}");
        match PoolManager::with_system_clock(store.clone(), cfg, produce) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[node {me}] starting the pool manager failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    let counters = manager.counters();
    let factory = {
        let stop = Arc::clone(&stop);
        let failed = Arc::clone(&failed);
        std::thread::spawn(move || manager.run(&stop, &failed))
    };

    // The sign loop: consume the store's OLDEST live record per message
    // (the same order at every node) and sign while the manager keeps
    // producing — concurrent sessions over the same mesh.
    let mut ok = true;
    for msg in FACTORY_MESSAGES {
        let id = loop {
            if failed.load(Ordering::SeqCst) {
                ok = false;
                break None;
            }
            let oldest = store
                .lock()
                .expect("store mutex poisoned")
                .as_ref()
                .and_then(|s| s.oldest_live_id());
            if let Some(id) = oldest {
                break Some(id);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let Some(id) = id else { break };
        let started = Instant::now();
        let sign_sid = session_id(GENESIS, &x_bytes, Some(id), b"sign");
        match node.sign_stored(&sign_sid, id, msg, cheat) {
            Ok((sig, blamed)) => {
                let (r, s) = sig.split_bytes();
                println!("SIG {} {}", hex(&r), hex(&s));
                if !blamed.is_empty() {
                    println!("BLAME sign {}", ids_str(&blamed));
                }
                eprintln!(
                    "[node {me}] signature for presignature {id} delivered in {:?}",
                    started.elapsed()
                );
            }
            Err(PersistError::Protocol(Error::Abort { abort })) => {
                println!("BLAME {} {}", abort.phase, ids_str(&abort.blamed));
                eprintln!("[node {me}] signing aborted: {}", abort.detail);
                ok = false;
                break;
            }
            Err(e) => {
                eprintln!("[node {me}] signing failed: {e}");
                ok = false;
                break;
            }
        }
    }

    // The manager must have refilled everything the signs consumed
    // (deterministic under honest completion) — production WHILE signing
    // is the property under test.
    if ok {
        let want = target as u64 + FACTORY_MESSAGES.len() as u64;
        let deadline = Instant::now() + Duration::from_secs(60);
        while counters.produced() < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if counters.produced() < want {
            eprintln!(
                "[node {me}] factory made too little progress: {} < {want}",
                counters.produced()
            );
            ok = false;
        }
    }
    stop.store(true, Ordering::SeqCst);
    let _ = factory.join();
    let stored = store
        .lock()
        .expect("store mutex poisoned")
        .as_ref()
        .map_or(0, |s| s.len());
    println!(
        "FACTORY target={target} produced={} stored={stored} expired={} signed={}",
        counters.produced(),
        counters.expired(),
        FACTORY_MESSAGES.len()
    );
    // H2 clean shutdown: stop the mesh and join every thread (Drop
    // would do it too — this demonstrates the programmatic API).
    node.shutdown();
    if cleanup {
        let _ = std::fs::remove_dir_all(&store_dir);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
    let ki = has_flag(&mut args, "--ki");
    // H4: `--restart` runs the children on the §10.4 robust drivers with
    // the §10.3 expel-and-restart policy.
    let restart = has_flag(&mut args, "--restart");
    // H2 Phase 3: `--factory N` — the concurrent-sessions demo (see
    // `run_factory_demo`); `--pool-ttl SECS` (H5, §8.6(3)) sets the pool
    // records' time-to-live (0 = never expire).
    let factory: Option<usize> = flag_value(&mut args, "--factory").and_then(|v| v.parse().ok());
    let pool_ttl: u64 = flag_value(&mut args, "--pool-ttl")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if factory.is_some() && (seeded || ki || persist || with_tls || cheat.is_some()) {
        eprintln!(
            "spawn-demo: --factory does not combine with --seeded/--ki/--persist/--tls/--cheat"
        );
        return ExitCode::FAILURE;
    }
    if pool_ttl > 0 && factory.is_none() {
        eprintln!("spawn-demo: --pool-ttl only makes sense with --factory N");
        return ExitCode::FAILURE;
    }
    if restart && (seeded || ki || factory.is_some()) {
        eprintln!("spawn-demo: --restart does not combine with --seeded/--ki/--factory");
        return ExitCode::FAILURE;
    }

    if let Some(target) = factory {
        println!(
            "== ohm-ecdsa-node H2/H5 demo: 2-of-3 keygen, then a background pool manager (target {target}, ttl {}s) + {} concurrent signatures across 3 OS processes ==",
            pool_ttl,
            FACTORY_MESSAGES.len()
        );
    } else if seeded {
        println!("== ohm-ecdsa-node M2/M3a demo (SEEDED fallback): 2-of-3 keygen + sign across 3 OS processes ==");
    } else if with_tls {
        println!(
            "== ohm-ecdsa-node M3c demo: 2-of-3 keygen → presign → sign across 3 OS processes over mTLS =="
        );
    } else if ki {
        println!(
            "== ohm-ecdsa-node §8.7 KI demo: 2-of-3 keygen → KEY-FREE pool record → 2-round KI sign across 3 OS processes =="
        );
    } else if restart {
        println!(
            "== ohm-ecdsa-node H4 demo: 2-of-3 keygen → presign → sign across 3 OS processes (§10.4 robust + §10.3 restart) =="
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
    println!(
        "  ceremony seeds written to {} (DEMO-ONLY: this process momentarily holds ALL keys — for a real committee use init + assemble)",
        dir.display()
    );
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
    if ki {
        println!(
            "  KI mode (§8.7): the presignature is a KEY-FREE pool record; the key binds ONLINE in 2 rounds"
        );
    }
    if restart {
        println!(
            "  H4 mode: §10.4 robust continuation (blame + service continues) + §10.3 expel-and-restart on dealing-phase aborts"
        );
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
        if let Some(target) = factory {
            cmd.arg("--factory").arg(target.to_string());
            if pool_ttl > 0 {
                cmd.arg("--pool-ttl").arg(pool_ttl.to_string());
            }
        }
        if ki {
            cmd.arg("--ki");
        }
        if restart {
            cmd.arg("--restart");
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

    if summarize(&info, seeded, factory, &node_lines) && ok {
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
/// `factory` is the H2 `--factory N` target (concurrent-sessions demo):
/// the presign/sign checks are replaced by the factory checks.
fn summarize(
    info: &CommitteeInfo,
    seeded: bool,
    factory: Option<usize>,
    node_lines: &[Vec<String>],
) -> bool {
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
    // offline factory (BLAME triples | BLAME presign). Factory mode
    // produces MANY presignatures — its check is the FACTORY line below.
    let mut presign_ok = seeded || factory.is_some();
    if keygen_ok && !seeded && factory.is_none() {
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
    } else if !seeded && factory.is_none() {
        println!("RESULT presign: skipped (keygen aborted)");
    }

    // Sign: every process prints the same SIG; verify it under the key
    // that signed — the FRESH keygen key in full-arc mode (parsed from
    // the X lines), the ceremony key in --seeded mode. Blame lines are
    // summarized per process.
    if let Some(target) = factory {
        // H2 factory mode: every process prints one FACTORY line with
        // `produced >= target + signed` (the factory refilled everything
        // the signs consumed) and one SIG line per FACTORY_MESSAGES
        // entry — all processes agreeing, each signature verifying
        // against its message under the fresh X.
        let want = target + FACTORY_MESSAGES.len();
        let facts: Vec<&str> = node_lines
            .iter()
            .filter_map(|lines| lines.iter().find(|l| l.starts_with("FACTORY ")))
            .map(|l| l.as_str())
            .collect();
        let facts_ok = facts.len() == 3
            && facts.iter().all(|f| {
                f.strip_prefix("FACTORY ")
                    .and_then(|rest| {
                        let (mut produced, mut signed) = (None, None);
                        for kv in rest.split_whitespace() {
                            let (k, v) = kv.split_once('=')?;
                            match k {
                                "produced" => produced = v.parse::<usize>().ok(),
                                "signed" => signed = v.parse::<usize>().ok(),
                                _ => {}
                            }
                        }
                        Some((produced?, signed?))
                    })
                    .is_some_and(|(p, s)| p >= want && s == FACTORY_MESSAGES.len())
            });
        if facts_ok {
            println!(
                "RESULT factory: all 3 processes kept the pool at {target} while signing (produced >= {want})"
            );
        } else {
            println!("RESULT factory: MISSING or INSUFFICIENT progress (lines={facts:?})");
            ok = false;
        }
        let vk = if keygen_ok {
            xs[0]
                .strip_prefix("X ")
                .and_then(hex_decode)
                .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
        } else {
            None
        };
        for (idx, msg) in FACTORY_MESSAGES.iter().enumerate() {
            let sigs: Vec<&str> = node_lines
                .iter()
                .filter_map(|lines| lines.iter().filter(|l| l.starts_with("SIG ")).nth(idx))
                .map(|l| l.as_str())
                .collect();
            let sig = if sigs.len() == 3 && sigs.iter().all(|s| *s == sigs[0]) {
                hex_decode(&sigs[0].replace("SIG ", "").replace(' ', ""))
                    .and_then(|b| Signature::from_slice(&b).ok())
            } else {
                None
            };
            let verified = match (vk, sig) {
                (Some(vk), Some(sig)) => vk.verify(msg, &sig).is_ok(),
                _ => false,
            };
            println!(
                "RESULT sign {}: all 3 processes agree; signature verifies under X: {verified}",
                idx + 1
            );
            ok &= verified;
        }
        if !keygen_ok {
            println!("RESULT sign: factory mode requires a completed keygen");
            ok = false;
        }
    } else {
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
