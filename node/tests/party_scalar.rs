//! Scalar-message signing over the wire (SPEC §9): the
//! `sign_scalar`/`sign_stored_scalar` variants sign an EXTERNALLY
//! computed message scalar (e.g. an EVM keccak-256 sighash reduced via
//! the core's `scalar_from_digest`) instead of letting the driver
//! SHA-256 the message.
//!
//! Coverage: 3-node keygen → `presign_stored` into per-node
//! `DiskPresigStore`s → `sign_stored_scalar` over a FIXED scalar yields
//! a valid low-`s` signature verifying with k256 against the joint key,
//! and a second `sign_stored_scalar` with the SAME presignature id
//! FAILS (the durable store's consume tombstone is the §8.6 single-use
//! enforcement).

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ohm_ecdsa::{scalar_from_digest, session_id, Error, Params, PartyId};
use ohm_ecdsa_node::persist::PersistError;
use ohm_ecdsa_node::PartyNode;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/scalar";

/// The fixed externally-computed digest (stand-in for an EVM sighash).
const DIGEST: [u8; 32] = [0x42u8; 32];

/// A fresh empty temp directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-scalar-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build `n` connected PartyNodes, each holding ONLY its own transport
/// key (the party_offline.rs harness).
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

/// The full arc over a scalar message: keygen → durable presign →
/// `sign_stored_scalar`, then a second sign with the same id fails.
#[test]
fn scalar_message_full_arc_and_single_use() {
    let params = Params::new(3, 2).unwrap();
    let dir = tmpdir("arc");
    let nodes = committee_nodes(&params, 61);
    let m = scalar_from_digest(&DIGEST);

    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let node_dir = dir.join(format!("node-{id}"));
        let m = m;
        threads.push(thread::spawn(move || -> Result<_, PersistError> {
            let mut rng = StdRng::seed_from_u64(900 + id as u64);
            let kg_sid = session_id(GENESIS, b"scalar", Some(0), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let x = key.com.points[0].to_affine();
            node.set_store(&node_dir.join("store"), &x)?;
            let xb = x.to_encoded_point(true);
            let ps_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"presign");
            node.presign_stored(&ps_sid, 0, &key, &mut rng, None)?;
            let sign_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"sign");
            let (sig, blamed) = node.sign_stored_scalar(&sign_sid, 0, &m, None)?;
            assert!(blamed.is_empty());
            // The consume tombstone is durable BEFORE the next line runs:
            // a second sign with the same id must fail at the store.
            let err = node.sign_stored_scalar(&sign_sid, 0, &m, None).unwrap_err();
            assert!(
                matches!(err, PersistError::Protocol(Error::PresigStore(_))),
                "second sign with id 0: {err:?}"
            );
            node.shutdown();
            Ok((x, sig))
        }));
    }

    let mut xs = Vec::new();
    let mut sigs = Vec::new();
    for t in threads {
        let (x, sig) = t.join().unwrap().unwrap();
        xs.push(x);
        sigs.push(sig);
    }
    assert!(xs.iter().all(|x| *x == xs[0]), "all nodes agree on X");
    assert!(
        sigs.iter().all(|s| *s == sigs[0]),
        "all nodes combine the same signature"
    );

    // k256 verification against the joint key over the SAME prehash the
    // scalar was reduced from; low-s asserted (BIP-62/EIP-2).
    let vk = VerifyingKey::from_sec1_bytes(xs[0].to_encoded_point(false).as_bytes()).unwrap();
    let sig: Signature = sigs[0];
    vk.verify_prehash(&DIGEST, &sig)
        .expect("signature verifies under X");
    assert!(!bool::from(sig.s().is_high()), "low-s");

    fs::remove_dir_all(&dir).ok();
}
