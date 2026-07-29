//! M2 latency benchmark over the real mesh (`PartyNode` per-node drivers).
//!
//! Measures wall-clock keygen (§6 + §6.1 rounds) and online-sign (§9)
//! times for 2-of-3 and 3-of-5 committees, on localhost AND with a
//! configurable per-link artificial send delay (`--delays`, the simulated
//! WAN — implemented as a send-side delay wrapper in the mesh). Reports
//! per-session medians in a small table.
//!
//! Per-node key separation holds here as everywhere in M2: every node
//! thread gets exactly its own transport key and its own presignature
//! records; the ceremony that produced the records (the documented M2
//! presignature shortcut, `ohm_ecdsa_node::seed`) finishes before the
//! threads start.
//!
//! Run: `cargo run --release -p ohm-ecdsa-node --example mesh_perf
//!       [--iters K] [--delays MS,MS,...]`

use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use ohm_ecdsa::{session_id, Params, PartyId};
use ohm_ecdsa_node::seed;
use ohm_ecdsa_node::PartyNode;
use rand::rngs::OsRng;

const GENESIS: &[u8] = b"ohm-ecdsa-node/mesh-perf";
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/mesh-perf/dkg";
const MESSAGE: &[u8] = b"mesh_perf benchmark message";
const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let iters: usize = arg_value(&args, "--iters")
        .and_then(|v| v.parse().ok())
        .unwrap_or(9);
    let delays: Vec<u64> = arg_value(&args, "--delays")
        .map(|v| v.split(',').filter_map(|d| d.parse().ok()).collect())
        .unwrap_or_else(|| vec![0, 50, 100]);

    println!("== ohm-ecdsa-node M2 mesh_perf ==");
    println!("{iters} iterations per cell (median reported), per-link send delay in ms");
    println!();
    println!(
        "{:<12} {:>10} {:>14} {:>14}",
        "committee", "delay ms", "keygen ms", "sign ms"
    );

    for (n, t) in [(3usize, 2usize), (5, 3)] {
        let params = Params::new(n, t).expect("valid params");
        // One ceremony per committee: n*iters presignatures per party per
        // delay cell (single-use records, unique ids per session).
        let (info, mut seeds) = seed::ceremony(&params, (iters * delays.len()) as u64, 7);
        for (delay_idx, &delay_ms) in delays.iter().enumerate() {
            let delay = Duration::from_millis(delay_ms);
            let (kg_ms, sign_ms) =
                run_cell(&params, &info, &mut seeds, delay, iters, delay_idx * iters);
            println!("{t}-of-{n}      {delay_ms:>10} {kg_ms:>14.1} {sign_ms:>14.1}");
        }
    }
    println!();
    println!("keygen = commit+reveal/p2p+complaint+defense rounds; sign = one broadcast round");
    println!("(presignatures seeded by the ceremony — per-node presign is M3)");
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Run one table cell: `iters` keygen sessions and `iters` sign sessions
/// over one committee on one delay setting. `presig_base` is the first
/// presignature id this cell consumes.
fn run_cell(
    params: &Params,
    info: &seed::CommitteeInfo,
    seeds: &mut [seed::PartySeed],
    delay: Duration,
    iters: usize,
    presig_base: usize,
) -> (f64, f64) {
    let n = params.n;
    let registry: std::collections::BTreeMap<PartyId, k256::ecdsa::VerifyingKey> =
        info.registry.iter().cloned().collect();
    // Bring up the nodes (each holds only its own transport key).
    let mut nodes = Vec::new();
    for seed in seeds.iter_mut() {
        let node = PartyNode::bind(
            seed.id,
            *params,
            &seed.transport_key,
            registry.clone(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            ROUND_TIMEOUT,
        )
        .expect("bind");
        node.set_send_delay(delay);
        nodes.push(node);
    }
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|nd| (nd.id(), nd.local_addr())).collect();
    for nd in &nodes {
        nd.connect(&addrs).expect("connect");
    }

    let barrier = Arc::new(Barrier::new(n + 1));
    let (tx, rx) = mpsc::channel();
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let tx = tx.clone();
        // Each thread takes ONLY its own party's presignature records.
        let mut my_presigs = Vec::new();
        for id in presig_base..presig_base + iters {
            let pos = seeds[k]
                .presigs
                .iter()
                .position(|p| p.id == id as u64)
                .expect("ceremony produced enough presigs");
            my_presigs.push(seeds[k].presigs.remove(pos));
        }
        let x = info.x;
        threads.push(std::thread::spawn(move || {
            let mut rng = OsRng;
            for (session, presig) in my_presigs.iter().enumerate() {
                // Keygen session (fresh sid per session).
                let sid = session_id(GENESIS, &x_bytes(x), Some(session as u64), b"keygen");
                barrier.wait();
                node.keygen(&sid, DKG_TAG, &mut rng, None).expect("keygen");
                barrier.wait();
                tx.send((session, SessionKind::Keygen)).unwrap();
                // Sign session over this cell's presignature.
                let sid = session_id(GENESIS, &x_bytes(x), Some(presig.id), b"sign");
                barrier.wait();
                node.sign(&sid, presig, MESSAGE, None).expect("sign");
                barrier.wait();
                tx.send((session, SessionKind::Sign)).unwrap();
            }
        }));
    }

    // Time the sessions from the harness side of the barriers.
    let mut kg_times = vec![0.0; iters];
    let mut sign_times = vec![0.0; iters];
    for session in 0..iters {
        for (kind, times) in [
            (SessionKind::Keygen, &mut kg_times),
            (SessionKind::Sign, &mut sign_times),
        ] {
            barrier.wait();
            let t0 = Instant::now();
            barrier.wait();
            times[session] = t0.elapsed().as_secs_f64() * 1000.0;
            let expect = (session, kind);
            for _ in 0..n {
                assert_eq!(rx.recv().unwrap(), expect);
            }
        }
    }
    for t in threads {
        t.join().expect("node thread");
    }
    (median(kg_times), median(sign_times))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SessionKind {
    Keygen,
    Sign,
}

fn x_bytes(x: k256::ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    x.to_affine().to_encoded_point(true).as_bytes().to_vec()
}
