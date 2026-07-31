//! A6 operability tests (thread-level): the metrics snapshot after a
//! real 3-node full arc — every counter present with a sane value, the
//! format parsing line-by-line — and the `MetricsReporter` interval +
//! final writes (`node --metrics-file`).

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, SecretKey};
use ohm_ecdsa::{session_id, Params, PartyId};
use ohm_ecdsa_node::metrics::{self, MetricsReporter};
use ohm_ecdsa_node::pool::PoolStats;
use ohm_ecdsa_node::PartyNode;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/metrics";
const MESSAGE: &[u8] = b"metrics test message";

/// A fresh empty temp directory for one test/node.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-metrics-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build `n` connected PartyNodes (same strict key-separation harness as
/// `party_offline.rs`). Returns the nodes in id order.
fn committee_nodes(params: &Params, key_seed: u64) -> Vec<PartyNode> {
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
                ROUND_TIMEOUT,
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

/// Parse the metrics file into `(header, counters)` blocks, asserting
/// the documented format line-by-line: one `#`-prefixed header per
/// block, then only `name value` lines (`[a-z_]+` name, u64 value).
fn parse_blocks(text: &str) -> Vec<(String, BTreeMap<String, u64>)> {
    let mut blocks = Vec::new();
    let mut cur: Option<(String, BTreeMap<String, u64>)> = None;
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("# ") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some((header.to_string(), BTreeMap::new()));
            continue;
        }
        let (name, value) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("malformed metrics line {line:?}"));
        assert!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "counter name must be [a-z_]+: {name:?}"
        );
        let value: u64 = value
            .parse()
            .unwrap_or_else(|_| panic!("counter value must be a u64: {line:?}"));
        cur.as_mut()
            .expect("counters follow a header")
            .1
            .insert(name.to_string(), value);
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    blocks
}

/// The full arc over the real mesh with a durable store per node; then
/// a snapshot per node carries the mesh, session AND store counters
/// with sane values, and the file round-trips through `append` + parse.
#[test]
fn snapshot_after_full_arc_has_sane_counters() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 77);
    let started = Instant::now();
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = (k + 1) as PartyId;
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(7700 + id as u64);
            let kg_sid = session_id(GENESIS, b"arc", Some(7), b"keygen");
            let key = node
                .keygen(&kg_sid, DKG_TAG, &mut rng, None)
                .expect("keygen");
            let xb = x_bytes(key.com.points[0]);
            // A durable store per node (the dev-key default under a temp
            // dir) so the store counters have something to say.
            let dir = tmpdir(&format!("store-{id}"));
            node.set_store(&dir, &key.com.points[0].to_affine())
                .expect("open store");
            let ps_sid = session_id(GENESIS, &xb, Some(1), b"presign");
            node.presign_stored(&ps_sid, 1, &key, &mut rng, None)
                .expect("presign");
            let sign_sid = session_id(GENESIS, &xb, Some(1), b"sign");
            let (sig, blamed) = node.sign_stored(&sign_sid, 1, MESSAGE, None).expect("sign");
            assert!(blamed.is_empty());
            (node, key.com.points[0], sig, dir)
        }));
    }
    let mut outcomes = Vec::new();
    for t in threads {
        outcomes.push(t.join().unwrap());
    }
    // Sanity: one X, one valid signature (the arc itself is covered in
    // party_offline.rs — this test is about the counters).
    let vk = VerifyingKey::from_affine(outcomes[0].1.to_affine()).unwrap();
    for (_, x, sig, _) in &outcomes {
        assert!(*x == outcomes[0].1);
        vk.verify(MESSAGE, sig).expect("signature verifies under X");
    }

    for (node, _, _, dir) in &outcomes {
        // A pool view is optional; pass one to exercise the pool lines.
        let pool = PoolStats {
            target: 2,
            stored: 0,
            produced: 3,
            expired: 1,
        };
        let block = metrics::snapshot(node, Some(&pool), started);
        let file = dir.join("metrics.log");
        metrics::append(&file, &block).unwrap();
        metrics::append(&file, &block).unwrap();
        let text = fs::read_to_string(&file).unwrap();
        let blocks = parse_blocks(&text);
        assert_eq!(blocks.len(), 2, "two appended snapshot blocks");
        let (header, counters) = &blocks[0];
        assert!(
            header.starts_with(&format!("ohm-ecdsa-node metrics node={} ", node.id())),
            "header: {header}"
        );
        assert!(header.contains("committee=1,2,3"), "header: {header}");
        assert!(header.contains(" pid="), "header: {header}");
        assert!(header.contains(" uptime_s="), "header: {header}");
        for key in [
            "tls_enabled",
            "frames_sent",
            "frames_received",
            "frames_dropped_bad_signature",
            "frames_dropped_misrouted",
            "frames_dropped_rate_limited",
            "frames_dropped_oversize",
            "frames_dropped_inbox_full",
            "acceptor_drops",
            "accepts_rate_limited",
            "handshake_rejects",
            "reconnects",
            "sessions_active",
            "sessions_completed",
            "pool_target",
            "pool_stored",
            "pool_produced",
            "pool_expired",
            "store_live",
            "store_consumed",
            "store_expired",
            "store_integrity_warnings",
        ] {
            assert!(counters.contains_key(key), "missing counter {key}");
        }
        assert!(counters["frames_sent"] > 0, "node {}", node.id());
        assert!(counters["frames_received"] > 0, "node {}", node.id());
        // keygen + presign (its sub-sessions) + sign all retired.
        assert!(
            counters["sessions_completed"] >= 3,
            "node {}: {}",
            node.id(),
            counters["sessions_completed"]
        );
        assert_eq!(counters["sessions_active"], 0);
        assert_eq!(counters["store_consumed"], 1, "signed one record");
        assert_eq!(counters["store_live"], 0, "the pool view is synthetic");
        assert_eq!(counters["tls_enabled"], 0);
        assert_eq!(counters["pool_target"], 2);
        assert_eq!(counters["pool_expired"], 1);
        fs::remove_dir_all(dir).ok();
    }
}

/// The reporter (`node --metrics-file`) appends interval snapshots and
/// exactly one FINAL block on drop, in the same parseable format.
#[test]
fn reporter_writes_interval_and_final_blocks() {
    let params = Params::new(1, 1).unwrap();
    let key = SecretKey::random(&mut StdRng::seed_from_u64(99));
    let registry: BTreeMap<PartyId, VerifyingKey> =
        [(1, *k256::ecdsa::SigningKey::from(&key).verifying_key())]
            .into_iter()
            .collect();
    let node = std::sync::Arc::new(
        PartyNode::bind(
            1,
            params,
            &key,
            registry,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            ROUND_TIMEOUT,
        )
        .unwrap(),
    );
    let dir = tmpdir("reporter");
    let file = dir.join("metrics.log");
    {
        let _reporter = MetricsReporter::start(
            file.clone(),
            std::sync::Arc::clone(&node),
            Duration::from_millis(150),
        );
        thread::sleep(Duration::from_millis(400));
        // Drop: stops the thread and appends the final snapshot.
    }
    let text = fs::read_to_string(&file).unwrap();
    let blocks = parse_blocks(&text);
    assert!(
        blocks.len() >= 2,
        "interval blocks + the final block: {}",
        blocks.len()
    );
    for (header, counters) in &blocks {
        assert!(header.contains("node=1"), "header: {header}");
        assert!(header.contains("committee=1"), "header: {header}");
        assert_eq!(counters["frames_sent"], 0, "no sessions ran");
        assert_eq!(counters["sessions_completed"], 0);
        // A node with no store configured has no store lines.
        assert!(!counters.contains_key("store_live"));
        assert!(!counters.contains_key("pool_target"));
    }
    fs::remove_dir_all(&dir).ok();
}
