//! H2 network-resilience tests (thread-level, strict per-node key
//! separation as in `party_offline.rs`): reconnection with journal
//! re-sync after a dropped connection, loud round timeouts against a
//! silent peer, clean shutdown (idle and mid-session), listener
//! accept-rate and garbage-frame guards, and MULTIPLE concurrent
//! protocol sessions (a background presignature factory overlapping
//! online signing, demultiplexed by sid). The process-level counterpart
//! is `process_demo.rs::process_demo_factory_concurrent_signing`.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, SecretKey};
use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::{session_id, Error, Params, PartyId};
use ohm_ecdsa_node::mesh::accept_cap_per_second;
use ohm_ecdsa_node::PartyNode;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
/// Short timeout for the loud-timeout / shutdown tests (keeps them fast).
const SHORT_TIMEOUT: Duration = Duration::from_secs(2);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/resilience";
const FACTORY_MESSAGES: [&[u8]; 3] = [
    b"resilience test: factory message 1",
    b"resilience test: factory message 2",
    b"resilience test: factory message 3",
];

/// Build `n` connected PartyNodes, each holding ONLY its own transport
/// key (same pattern as `party_offline.rs`, with a configurable round
/// timeout). Returns the nodes in id order.
fn committee_nodes(params: &Params, key_seed: u64, timeout: Duration) -> Vec<PartyNode> {
    let mut kr = StdRng::seed_from_u64(key_seed);
    let keys: Vec<SecretKey> = (0..params.n).map(|_| SecretKey::random(&mut kr)).collect();
    let registry: BTreeMap<PartyId, VerifyingKey> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i + 1, *k256::ecdsa::SigningKey::from(k).verifying_key()))
        .collect();
    let nodes: Vec<PartyNode> = (1..=params.n)
        .map(|id| {
            PartyNode::bind(
                id,
                *params,
                &keys[id - 1],
                registry.clone(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                timeout,
            )
            .unwrap()
        })
        .collect();
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    for node in &nodes {
        node.connect(&addrs).unwrap();
    }
    nodes
}

fn x_bytes(x: ProjectivePoint) -> Vec<u8> {
    x.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// H2 Phase 1: a peer connection dropped after the mesh is up is
/// re-established by the reconnector (capped backoff + jitter), and the
/// journal re-sync re-delivers every in-flight session message — the
/// keygen completes despite node 1's outgoing connection to node 2
/// being torn down before the first round.
#[test]
fn reconnect_after_drop_completes_keygen() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 41, ROUND_TIMEOUT);
    // Tear down node 1's outgoing connection to node 2 BEFORE the
    // session starts: every keygen message from 1 to 2 then goes through
    // the journal → reconnect → re-sync path.
    nodes[0].debug_drop_outgoing(2);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(4100 + id as u64);
            let sid = session_id(GENESIS, b"reconnect", None, b"keygen");
            let key = node.keygen(&sid, DKG_TAG, &mut rng, None).expect("keygen");
            (x_bytes(key.com.points[0]), node.metrics())
        }));
    }
    let mut xs = Vec::new();
    let mut metrics = Vec::new();
    for t in threads {
        let (x, m) = t.join().unwrap();
        xs.push(x);
        metrics.push(m);
    }
    assert!(xs.iter().all(|x| *x == xs[0]), "nodes disagree on X");
    assert!(
        metrics[0].reconnects >= 1,
        "node 1 reconnected at least once: {:?}",
        metrics[0]
    );
}

/// H2 Phase 1/2: a committee peer that accepts connections but never
/// sends a single frame (node 3's driver simply never runs) fails its
/// round LOUDLY at the honest nodes — the round timeout returns the
/// partial accepted set and the driver fails closed — and nothing parks:
/// every node (including the silent one) shuts down cleanly and quickly.
#[test]
fn silent_peer_round_timeout_fails_loudly() {
    let params = Params::new(3, 2).unwrap();
    let mut nodes = committee_nodes(&params, 42, SHORT_TIMEOUT);
    let silent = nodes.pop().unwrap(); // node 3: mesh up, never drives
    let started = Instant::now();
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(4200 + id as u64);
            let sid = session_id(GENESIS, b"silent", None, b"keygen");
            node.keygen(&sid, DKG_TAG, &mut rng, None)
        }));
    }
    for (k, t) in threads.into_iter().enumerate() {
        let out = t.join().unwrap();
        assert!(
            out.is_err(),
            "node {}: keygen with a silent peer must fail closed",
            k + 1
        );
    }
    // One round timeout, not a hang: the drivers fail after ~2 s, far
    // below the 30 s production-style default.
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "round timeout took {:?}",
        started.elapsed()
    );
    // The silent node parked no threads: shutdown joins everything.
    let shutdown_start = Instant::now();
    silent.shutdown();
    assert!(
        shutdown_start.elapsed() < Duration::from_secs(6),
        "silent-node shutdown took {:?}",
        shutdown_start.elapsed()
    );
}

/// H2 Phase 1: `PartyNode::shutdown` stops the mesh and joins every
/// thread — on an idle node and mid-session. Mid-session drivers fail
/// closed on their round deadline; the shutdown itself never hangs.
#[test]
fn shutdown_idle_and_inflight() {
    let params = Params::new(3, 2).unwrap();
    // Idle: bind + connect, shut down immediately.
    let idle = committee_nodes(&params, 43, ROUND_TIMEOUT);
    let started = Instant::now();
    for node in &idle {
        node.shutdown();
    }
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "idle shutdown took {:?}",
        started.elapsed()
    );
    drop(idle); // Drop after shutdown: idempotent, no double-join.

    // In-flight: all three nodes mid-keygen when shutdown lands.
    let live = committee_nodes(&params, 44, Duration::from_secs(5));
    let mut threads = Vec::new();
    for (k, node) in live.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(4400 + id as u64);
            let sid = session_id(GENESIS, b"inflight", None, b"keygen");
            let out = node.keygen(&sid, DKG_TAG, &mut rng, None);
            node.shutdown(); // driver done: shut its own mesh down
            out
        }));
    }
    thread::sleep(Duration::from_millis(150)); // let the session start
    let started = Instant::now();
    let mut done = 0;
    for t in threads {
        // The keygen may have completed (fast path) or failed closed on
        // the shutdown-torn mesh — either way the driver returns and the
        // node's own shutdown inside the thread joined its threads.
        let _ = t.join().unwrap();
        done += 1;
    }
    assert_eq!(done, 3);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "in-flight shutdown took {:?}",
        started.elapsed()
    );
}

/// H2 Phase 2: the listener's accept-rate window counts poke/scan noise
/// (raw TCP connections that never speak) while the honest session is
/// unaffected — the honest peers connected at startup, before the flood.
#[test]
fn accept_rate_cap_counts_poke_flood() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 45, ROUND_TIMEOUT);
    let target = nodes[0].local_addr();
    // Flood node 1's listener with raw connections inside one window.
    let cap = accept_cap_per_second(params.n) as usize;
    let mut flood = Vec::new();
    for _ in 0..cap + 16 {
        if let Ok(s) = TcpStream::connect(target) {
            flood.push(s);
        }
    }
    // The listener thread may be scheduled after the kernel has already
    // completed the handshakes into the backlog (loaded/single-CPU
    // machines) — poll the counter with a deadline instead of asserting
    // immediately.
    let deadline = Instant::now() + Duration::from_secs(5);
    while nodes[0].metrics().accepts_rate_limited == 0 {
        assert!(
            Instant::now() < deadline,
            "the accept-rate window never counted the flood: {:?}",
            nodes[0].metrics()
        );
        thread::sleep(Duration::from_millis(25));
    }
    drop(flood);
    // The honest keygen completes regardless.
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(4500 + id as u64);
            let sid = session_id(GENESIS, b"pokes", None, b"keygen");
            x_bytes(
                node.keygen(&sid, DKG_TAG, &mut rng, None)
                    .expect("keygen")
                    .com
                    .points[0],
            )
        }));
    }
    let xs: Vec<Vec<u8>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(xs.iter().all(|x| *x == xs[0]), "nodes disagree on X");
}

/// H2 Phase 2: garbage frames (an absurd length prefix, undecodable
/// payloads) on raw connections are dropped by the framing layer before
/// they ever reach the acceptor — the honest keygen completes while the
/// flood runs.
#[test]
fn garbage_flood_dropped_honest_session_completes() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 46, ROUND_TIMEOUT);
    let target = nodes[0].local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let mut flooders = Vec::new();
    for kind in 0..3u8 {
        let stop = Arc::clone(&stop);
        flooders.push(thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok(mut s) = TcpStream::connect(target) else {
                    continue;
                };
                match kind {
                    // Absurd length prefix: over the per-family frame cap.
                    0 => {
                        let _ = s.write_all(&u32::MAX.to_be_bytes());
                    }
                    // Small frame, undecodable payload.
                    1 => {
                        let _ = s.write_all(&17u32.to_be_bytes());
                        let _ = s.write_all(b"garbage payload!!");
                    }
                    // Endless well-formed-length garbage frames.
                    _ => {
                        for _ in 0..64 {
                            let _ = s.write_all(&4u32.to_be_bytes());
                            let _ = s.write_all(b"junk");
                        }
                    }
                }
            }
        }));
    }
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(4600 + id as u64);
            let sid = session_id(GENESIS, b"flood", None, b"keygen");
            x_bytes(
                node.keygen(&sid, DKG_TAG, &mut rng, None)
                    .expect("keygen")
                    .com
                    .points[0],
            )
        }));
    }
    let xs: Vec<Vec<u8>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    stop.store(true, Ordering::SeqCst);
    for f in flooders {
        let _ = f.join();
    }
    assert!(xs.iter().all(|x| *x == xs[0]), "nodes disagree on X");
}

/// H2 Phase 3: MULTIPLE protocol sessions in flight concurrently. Each
/// node runs a background factory thread keeping 2 presignatures in a
/// pool (per-node §7.2/§8 sessions) while its main thread signs 3
/// messages against consumed records — the acceptor demultiplexes every
/// session by sid, so factory traffic and online signing overlap. Same
/// deterministic session order at every node (presign ids 1.., sign id =
/// consumed record id), so no extra coordination is needed.
#[test]
fn concurrent_factory_and_signing() {
    let params = Params::new(3, 2).unwrap();
    const TARGET: usize = 2;
    let nodes = committee_nodes(&params, 47, ROUND_TIMEOUT);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let node = Arc::new(node);
            let mut rng = StdRng::seed_from_u64(4700 + id as u64);
            let kg_sid = session_id(GENESIS, b"factory", None, b"keygen");
            let key = node
                .keygen(&kg_sid, DKG_TAG, &mut rng, None)
                .expect("keygen");
            let xb = x_bytes(key.com.points[0]);

            let pool: Arc<Mutex<VecDeque<Presignature>>> = Arc::new(Mutex::new(VecDeque::new()));
            let produced = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let factory = {
                let node = Arc::clone(&node);
                let pool = Arc::clone(&pool);
                let produced = Arc::clone(&produced);
                let stop = Arc::clone(&stop);
                let xb = xb.clone();
                thread::spawn(move || {
                    let mut rng = StdRng::seed_from_u64(4800 + id as u64);
                    let mut next_id = 1u64;
                    while !stop.load(Ordering::SeqCst) {
                        if pool.lock().unwrap().len() >= TARGET {
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        let id = next_id;
                        next_id += 1;
                        let sid = session_id(GENESIS, &xb, Some(id), b"presign");
                        match node.presign(&sid, id, &key, &mut rng, None) {
                            Ok(p) => {
                                pool.lock().unwrap().push_back(p);
                                produced.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(Error::ZeroValue(_)) => continue,
                            Err(e) => panic!("factory presign failed: {e}"),
                        }
                    }
                })
            };

            // Sign the three messages against the pool's oldest records
            // while the factory keeps producing.
            let mut sigs = Vec::new();
            for msg in FACTORY_MESSAGES {
                let presig = loop {
                    if let Some(p) = pool.lock().unwrap().pop_front() {
                        break p;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let sign_sid = session_id(GENESIS, &xb, Some(presig.id), b"sign");
                let (sig, blamed) = node.sign(&sign_sid, &presig, msg, None).expect("sign");
                assert!(blamed.is_empty());
                sigs.push(sig);
            }
            // The factory must refill everything the signs consumed.
            let want = TARGET as u64 + FACTORY_MESSAGES.len() as u64;
            let deadline = Instant::now() + Duration::from_secs(60);
            while produced.load(Ordering::SeqCst) < want && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            stop.store(true, Ordering::SeqCst);
            factory.join().unwrap();
            node.shutdown();
            (xb, sigs, produced.load(Ordering::SeqCst))
        }));
    }
    let mut outcomes = Vec::new();
    for t in threads {
        outcomes.push(t.join().unwrap());
    }
    // All nodes agree on the fresh key and on every signature; each
    // signature verifies under the fresh key; the factory made progress
    // (produced = target + signed) at every node.
    assert!(outcomes.iter().all(|o| o.0 == outcomes[0].0));
    let vk = VerifyingKey::from_sec1_bytes(&outcomes[0].0).unwrap();
    for (i, (_, sigs, produced)) in outcomes.iter().enumerate() {
        assert_eq!(
            *produced,
            TARGET as u64 + FACTORY_MESSAGES.len() as u64,
            "node {}: factory progress",
            i + 1
        );
        assert_eq!(sigs.len(), FACTORY_MESSAGES.len());
        for (j, (msg, sig)) in FACTORY_MESSAGES.iter().zip(sigs).enumerate() {
            assert_eq!(*sig, outcomes[0].1[j], "node {}: sig {}", i + 1, j);
            vk.verify(msg, sig)
                .unwrap_or_else(|e| panic!("node {}: invalid signature: {e}", i + 1));
        }
    }
}
