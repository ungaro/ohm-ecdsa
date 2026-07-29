//! OHM-ECDSA node binary (M2): per-party processes plus the M1 demo.
//!
//! Subcommands:
//!
//! * `node` — run as ONE party (its own OS process, holding only its own
//!   seed): fresh keygen through the M2 per-node driver (§6 + §6.1
//!   complaints over the wire), then one online signature (§9, §10.4
//!   robust) using a seeded presignature ([`ohm_ecdsa_node::seed`]).
//! * `setup` — the demo ceremony: one orchestrated run writing the public
//!   committee file and one SECRET seed file per party.
//! * `spawn-demo` — the M2 showcase: set up a 2-of-3 committee and launch
//!   three child `node` processes on localhost, keygen then sign across
//!   real processes, printing per-process logs, the joint key, the
//!   signature, and any blame. `--cheat-node K --cheat C` drives child K
//!   into a cheater.
//! * `m1-demo [port_base]` — the original M1 orchestrator demo (one
//!   process, all keys, `drive_dkg_signed` over `MeshTransport`).
//!
//! Run `… --help`-less: wrong usage prints the usage text.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ohm_ecdsa::transport::{drive_dkg_signed, SigningTransport};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::seed::{self, CommitteeInfo};
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
        _ => {
            eprintln!(
                "usage:\n  \
                 ohm-ecdsa-node m1-demo [PORT_BASE]\n  \
                 ohm-ecdsa-node setup --dir DIR [--presigs K] [--seed S]\n  \
                 ohm-ecdsa-node node --seed FILE --committee FILE --bind ADDR \\\n    \
                 [--rendezvous | --peers id@host:port,...] [--delay-ms D] \\\n    \
                 [--round-timeout-secs S] [--cheat C] [--presig-id K] [--message MSG]\n  \
                 ohm-ecdsa-node spawn-demo [--dir DIR] [--delay-ms D] \\\n    \
                 [--cheat-node K --cheat C]\n  \
                 cheats: bad-deal:VICTIM | false-accuse:DEALER | bad-sign-share"
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

fn has_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn parse_cheat(s: &str) -> Option<Cheat> {
    if s == "bad-sign-share" {
        return Some(Cheat::BadSignShare);
    }
    let (kind, arg) = s.split_once(':')?;
    let id: PartyId = arg.parse().ok()?;
    match kind {
        "bad-deal" => Some(Cheat::BadDeal { victim: id }),
        "false-accuse" => Some(Cheat::FalseAccuse { dealer: id }),
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
    let bind_addr: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("node: bad --bind address: {e}");
            return ExitCode::FAILURE;
        }
    };
    let node = match PartyNode::bind(
        me,
        info.params,
        &my_seed.transport_key,
        registry,
        bind_addr,
        Duration::from_secs(timeout_secs),
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("node {me}: bind failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    node.set_send_delay(Duration::from_millis(delay_ms));

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

    let x_bytes = info
        .x
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Phase 1: fresh keygen through the per-node driver (§6 + §6.1
    // complaints/defenses over the wire). The fresh key share is NOT what
    // the sign phase below uses — per-node presign is M3, so signing runs
    // over the seeded ceremony key (documented demo shortcut).
    let kg_sid = session_id(GENESIS, &x_bytes, None, b"keygen");
    let mut rng = OsRng;
    match node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat) {
        Ok(share) => {
            let x = share.com.points[0].to_affine().to_encoded_point(true);
            println!("X {}", hex(x.as_bytes()));
            eprintln!("[node {me}] keygen complete; fresh key share stays in this process");
        }
        Err(Error::Abort { abort }) => {
            println!("BLAME keygen {}", ids_str(&abort.blamed));
            eprintln!("[node {me}] keygen aborted: {}", abort.detail);
        }
        Err(e) => {
            eprintln!("[node {me}] keygen failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Phase 2: online signing (§9, §10.4 robust) over the seeded
    // presignature — one broadcast round.
    let Some(presig) = my_seed.presigs.iter().find(|p| p.id == presig_id) else {
        eprintln!("node {me}: no presignature id {presig_id} in the seed");
        return ExitCode::FAILURE;
    };
    let sign_sid = session_id(GENESIS, &x_bytes, Some(presig_id), b"sign");
    match node.sign(&sign_sid, presig, &message, cheat) {
        Ok((sig, blamed)) => {
            let (r, s) = sig.split_bytes();
            println!("SIG {} {}", hex(&r), hex(&s));
            if !blamed.is_empty() {
                println!("BLAME sign {}", ids_str(&blamed));
            }
            eprintln!("[node {me}] signature delivered");
        }
        Err(Error::Abort { abort }) => {
            println!("BLAME sign {}", ids_str(&abort.blamed));
            eprintln!("[node {me}] signing aborted: {}", abort.detail);
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("[node {me}] signing failed: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn ids_str(ids: &[PartyId]) -> String {
    ids.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
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

    println!("== ohm-ecdsa-node M2 demo: 2-of-3 keygen + sign across 3 OS processes ==");
    let params = Params::new(3, 2).expect("valid params");
    let ceremony_seed = rand::RngCore::next_u64(&mut OsRng);
    let (info, seeds) = seed::ceremony(&params, 1, ceremony_seed);
    if let Err(e) = seed::write_all(&dir, &info, &seeds) {
        eprintln!("spawn-demo: writing seed files failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("  ceremony seeds written to {}", dir.display());
    if let (Some(k), Some(c)) = (cheat_node, cheat) {
        println!("  fault injection: node {k} runs with --cheat {c:?}");
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

    if summarize(&info, &node_lines) && ok {
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
    }
}

/// Cross-check the per-process outputs and print the RESULT lines the
/// process-level tests assert on. Returns the demo's success verdict.
fn summarize(info: &CommitteeInfo, node_lines: &[Vec<String>]) -> bool {
    let mut ok = true;
    // Keygen: either every process prints the same X, or every process
    // names the same blamed party.
    let xs: Vec<&str> = node_lines
        .iter()
        .filter_map(|lines| lines.iter().find(|l| l.starts_with("X ")))
        .map(|l| l.as_str())
        .collect();
    if xs.len() == 3 && xs.iter().all(|x| *x == xs[0]) {
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
    // Sign: every process prints the same SIG; verify it under the
    // ceremony key. Blame lines are summarized per process.
    let sigs: Vec<&str> = node_lines
        .iter()
        .filter_map(|lines| lines.iter().find(|l| l.starts_with("SIG ")))
        .map(|l| l.as_str())
        .collect();
    if sigs.len() == 3 && sigs.iter().all(|s| *s == sigs[0]) {
        let bytes = hex_decode(&sigs[0].replace("SIG ", "").replace(' ', ""));
        let verified = bytes
            .and_then(|b| Signature::from_slice(&b).ok())
            .and_then(|sig| {
                VerifyingKey::from_affine(info.x.to_affine())
                    .ok()
                    .map(|vk| vk.verify(DEMO_MESSAGE, &sig).is_ok())
            })
            .unwrap_or(false);
        println!("RESULT sign: all 3 processes agree; signature verifies under X: {verified}");
        ok &= verified;
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
