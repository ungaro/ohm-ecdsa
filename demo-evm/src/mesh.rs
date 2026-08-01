//! M3 mesh driver: the demo committee as REAL per-node drivers — three
//! `PartyNode` instances (the node crate's per-party drivers) on
//! loopback TCP with strict per-node key separation, per-node durable
//! single-use presignature stores (`DiskPresigStore`), and the wire
//! §6.1/§8/§9 rounds. This replaces the in-process `sim` orchestrator
//! for the committee; the EIP-1559 assembly and JSON-RPC side are
//! unchanged.
//!
//! Committee identity: keygen is DETERMINISTIC (fixed seed + sid — the
//! mesh committee gets its OWN fresh address, distinct from the sim
//! committee whose key was burned in the 2026-08-01 k-reuse incident,
//! see README). Keygen re-runs on every process start and reproduces
//! the SAME joint key, so the funded address is stable across runs.
//!
//! Presignature ids across runs: two monotonic counter FILES in the
//! data dir (`next-presign-id`, `next-sign-id`). Each is read and
//! incremented BEFORE use, so a crash leaves a harmless hole, never a
//! collision with a consumed id (SPEC §8.6). The durable store's
//! consume tombstone (fsync'd before the share is broadcast) is the
//! single-use enforcement for signing; the sign-id counter mirrors it
//! at the driver level — a failed attempt is never retried with the
//! same record.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, Scalar, SecretKey};
use ohm_ecdsa::{session_id, Params, PartyId};
use ohm_ecdsa_node::PartyNode;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::tx;
use crate::DemoError;

/// Deterministic seeds for the mesh committee — keygen (stable address)
/// and transport keys. DISTINCT from the sim arc's `DEMO_SEED`: this is
/// a fresh committee with a fresh address.
pub const MESH_KEYGEN_SEED: u64 = 0x0E55_0003;
const MESH_TRANSPORT_SEED: u64 = 0x0E55_0004;

const DKG_TAG: &[u8] = b"ohm-ecdsa-demo-evm/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-demo-evm/mesh";
const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// The default per-node data directory root (`demo-evm/data/mesh`).
/// Contains sealed store records — gitignored, never committed.
pub fn default_data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("mesh")
}

/// What a mesh setup run established.
#[derive(Debug)]
pub struct MeshSetup {
    /// EIP-55 checksummed committee address (stable across runs).
    pub address: String,
    /// The joint verifying key (for the ecrecover assertion).
    pub joint_vk: VerifyingKey,
    /// The presignature id minted (and durably stored) by this run.
    pub presigned_id: u64,
}

/// Read a u64 counter file (missing/unparseable → 0).
fn read_counter(data_dir: &Path, name: &str) -> u64 {
    fs::read_to_string(data_dir.join(name))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Persist a counter value.
fn write_counter(data_dir: &Path, name: &str, value: u64) -> Result<(), DemoError> {
    fs::write(data_dir.join(name), format!("{value}\n"))
        .map_err(|e| DemoError::Io(format!("counter {name}: {e}")))
}

/// Build 3 connected PartyNodes with deterministic transport keys.
fn committee_nodes(params: &Params) -> Result<Vec<PartyNode>, DemoError> {
    let mut kr = StdRng::seed_from_u64(MESH_TRANSPORT_SEED);
    let keys: Vec<SecretKey> = (0..params.n).map(|_| SecretKey::random(&mut kr)).collect();
    let registry: BTreeMap<PartyId, VerifyingKey> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i + 1, *k256::ecdsa::SigningKey::from(k).verifying_key()))
        .collect();
    let mut nodes = Vec::new();
    for id in 1..=params.n {
        nodes.push(
            PartyNode::bind(
                id,
                *params,
                &keys[id - 1],
                registry.clone(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                ROUND_TIMEOUT,
            )
            .map_err(|e| DemoError::Io(format!("mesh bind: {e}")))?,
        );
    }
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    for node in &nodes {
        node.connect(&addrs)
            .map_err(|e| DemoError::Io(format!("mesh connect: {e}")))?;
    }
    Ok(nodes)
}

/// Run one mesh session: every node keygens (deterministic — same X
/// every run), opens its durable store under `data_dir/node-<id>/store`,
/// and then runs `driver(node, key, x)`. Returns the joint key/address
/// plus the per-node driver outputs (all identical for the demo's
/// drivers; agreement is asserted).
fn mesh_session<T, F>(
    data_dir: &Path,
    driver: F,
) -> Result<(AffinePoint, String, Vec<T>), DemoError>
where
    T: Send + 'static,
    F: Fn(&PartyNode, &ohm_ecdsa::presign::KeyShare, &AffinePoint) -> Result<T, DemoError>
        + Send
        + Copy
        + 'static,
{
    let params = Params::new(3, 2)?;
    let nodes = committee_nodes(&params)?;
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let node_dir = data_dir.join(format!("node-{id}"));
        fs::create_dir_all(&node_dir).map_err(|e| DemoError::Io(e.to_string()))?;
        threads.push(thread::spawn(
            move || -> Result<(AffinePoint, T), DemoError> {
                let mut rng = StdRng::seed_from_u64(MESH_KEYGEN_SEED + id as u64);
                let kg_sid = session_id(GENESIS, b"committee", Some(0), b"keygen");
                let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
                let x = key.com.points[0].to_affine();
                node.set_store(&node_dir.join("store"), &x)?;
                let out = driver(&node, &key, &x)?;
                node.shutdown();
                Ok((x, out))
            },
        ));
    }
    let mut xs = Vec::new();
    let mut outs = Vec::new();
    for t in threads {
        let (x, out) = t.join().expect("mesh node thread panicked")?;
        xs.push(x);
        outs.push(out);
    }
    assert!(xs.iter().all(|x| *x == xs[0]), "mesh nodes must agree on X");
    let address = tx::eip55(&tx::address_of(&xs[0]));
    Ok((xs[0], address, outs))
}

/// Mesh committee setup (idempotent across runs): deterministic keygen
/// reproducing the same address, durable stores opened, and ONE fresh
/// presignature minted over the wire and persisted per node (id from
/// the monotonic `next-presign-id` counter — warming the pool is setup,
/// not signing).
pub fn setup(data_dir: &Path) -> Result<MeshSetup, DemoError> {
    fs::create_dir_all(data_dir).map_err(|e| DemoError::Io(e.to_string()))?;
    // Increment BEFORE use: a crash leaves a hole, never a reused id.
    let presign_id = read_counter(data_dir, "next-presign-id");
    write_counter(data_dir, "next-presign-id", presign_id + 1)?;

    let (x, address, _) = mesh_session(data_dir, move |node, key, x| {
        let mut rng = StdRng::from_entropy(); // fresh k per run (§8.6)
        let xb = x.to_encoded_point(true);
        let ps_sid = session_id(GENESIS, xb.as_bytes(), Some(presign_id), b"presign");
        node.presign_stored(&ps_sid, presign_id, key, &mut rng, None)?;
        Ok(())
    })?;
    let joint_vk = VerifyingKey::from_sec1_bytes(x.to_encoded_point(false).as_bytes())
        .expect("the joint key is a valid curve point");
    Ok(MeshSetup {
        address,
        joint_vk,
        presigned_id: presign_id,
    })
}

/// Sign the scalar `m` (the EIP-1559 sighash reduced by the caller)
/// with the NEXT sign-id from the monotonic counter, consumed from the
/// durable stores over the wire (`sign_stored_scalar`). The counter
/// increments BEFORE the attempt: a failed or aborted attempt is never
/// retried with the same presignature (the store's consume tombstone
/// enforces the same at the durability layer).
pub fn sign(data_dir: &Path, m: &Scalar) -> Result<Signature, DemoError> {
    let sign_id = read_counter(data_dir, "next-sign-id");
    write_counter(data_dir, "next-sign-id", sign_id + 1)?;
    sign_with_id(data_dir, sign_id, m)
}

/// [`sign`] with an explicit presignature id (tests assert that a
/// consumed id fails).
pub fn sign_with_id(data_dir: &Path, presig_id: u64, m: &Scalar) -> Result<Signature, DemoError> {
    let m = *m; // the closure moves into the node threads
    let (_, _, sigs) = mesh_session(data_dir, move |node, _key, x| {
        let xb = x.to_encoded_point(true);
        let sign_sid = session_id(GENESIS, xb.as_bytes(), Some(presig_id), b"sign");
        let (sig, blamed) = node.sign_stored_scalar(&sign_sid, presig_id, &m, None)?;
        assert!(blamed.is_empty(), "honest demo run must blame nobody");
        Ok(sig)
    })?;
    assert!(
        sigs.iter().all(|s| *s == sigs[0]),
        "mesh nodes must combine the same signature"
    );
    Ok(sigs.into_iter().next().expect("three nodes"))
}
