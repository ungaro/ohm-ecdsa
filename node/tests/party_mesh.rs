//! M2 integration tests: per-node drivers over real TCP with strict
//! per-node key separation (each node thread holds ONLY its own transport
//! key, its own RNG, and — for signing — its own seeded presignature
//! records; the ceremony that produces the records is the documented M2
//! shortcut, see `ohm_ecdsa_node::seed`).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::{ProjectivePoint, Scalar, SecretKey};
use ohm_ecdsa::presign::KeyShare;
use ohm_ecdsa::shamir::interpolate_at_zero;
use ohm_ecdsa::{session_id, Error, Params, PartyId};
use ohm_ecdsa_node::seed;
use ohm_ecdsa_node::{Cheat, PartyNode};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test";
const MESSAGE: &[u8] = b"party_mesh test message";

/// Build `n` connected PartyNodes, each holding ONLY its own transport
/// key. Returns the nodes in id order; move each into its own thread.
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

/// Run keygen on every node (each in its own thread, with its own RNG),
/// optionally driving node `cheat_at` with `cheat`.
fn run_keygen(
    params: &Params,
    nodes: Vec<PartyNode>,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<ohm_ecdsa::Result<KeyShare>> {
    assert_eq!(nodes.len(), params.n);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let cheat = cheat_at.and_then(|(at, c)| (at == id).then_some(c));
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(rng_seed + id as u64);
            let sid = session_id(GENESIS, b"keygen", Some(rng_seed), b"keygen");
            node.keygen(&sid, DKG_TAG, &mut rng, cheat)
        }));
    }
    threads.into_iter().map(|t| t.join().unwrap()).collect()
}

/// Per-node sign outcome: the signature and the blamed senders.
type SignOutcome = ohm_ecdsa::Result<(Signature, Vec<PartyId>)>;

/// Bring up a committee from a ceremony's seeds (each node holds only its
/// own seed's transport key and presignature records) and run one sign
/// session. Returns, per node, its `(signature, blamed)` result.
fn run_sign(
    params: &Params,
    ceremony_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> (ProjectivePoint, Vec<SignOutcome>) {
    let (info, seeds) = seed::ceremony(params, 1, ceremony_seed);
    let registry: BTreeMap<PartyId, VerifyingKey> = info.registry.iter().cloned().collect();
    let nodes: Vec<PartyNode> = seeds
        .iter()
        .map(|s| {
            PartyNode::bind(
                s.id,
                *params,
                &s.transport_key,
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
    let mut threads = Vec::new();
    for (node, seed) in nodes.into_iter().zip(seeds) {
        let id = node.id();
        let cheat = cheat_at.and_then(|(at, c)| (at == id).then_some(c));
        let x = info.x;
        threads.push(thread::spawn(move || {
            // The thread takes ownership of the whole seed: only THIS
            // party's presignature record exists here.
            let presig = seed.presigs.into_iter().next().expect("one presig");
            let sid = session_id(GENESIS, &x_bytes(x), Some(presig.id), b"sign");
            node.sign(&sid, &presig, MESSAGE, cheat)
        }));
    }
    let results = threads.into_iter().map(|t| t.join().unwrap()).collect();
    (info.x, results)
}

fn x_bytes(x: ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    x.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

#[test]
fn party_keygen_reconstructs_joint_key() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 11);
    let outs = run_keygen(&params, nodes, 100, None);
    let shares: Vec<KeyShare> = outs.into_iter().collect::<Result<_, _>>().unwrap();
    // Every node computed the same joint commitment on its own view.
    for s in &shares {
        assert_eq!(s.com.points[0], shares[0].com.points[0]);
        assert_eq!(s.com.points.len(), params.t);
    }
    // Any t = 2 shares reconstruct the joint secret under the public key.
    let parties = vec![1, 2];
    let xs: Vec<Scalar> = parties.iter().map(|&p| shares[p - 1].share).collect();
    let x = interpolate_at_zero(&parties, &xs);
    assert_eq!(ProjectivePoint::GENERATOR * x, shares[0].com.points[0]);
    assert_ne!(shares[0].share, shares[1].share);
}

#[test]
fn party_keygen_3_of_5_reconstructs() {
    let params = Params::new(5, 3).unwrap();
    let nodes = committee_nodes(&params, 12);
    let outs = run_keygen(&params, nodes, 200, None);
    let shares: Vec<KeyShare> = outs.into_iter().collect::<Result<_, _>>().unwrap();
    let parties = vec![2, 4, 5];
    let xs: Vec<Scalar> = parties.iter().map(|&p| shares[p - 1].share).collect();
    let x = interpolate_at_zero(&parties, &xs);
    assert_eq!(ProjectivePoint::GENERATOR * x, shares[0].com.points[0]);
}

#[test]
fn party_keygen_blames_cheating_dealer_via_wire_complaints() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 13);
    // Node 2 deals a wrong share to party 3 (F2, §10.1): party 3's
    // complaint and node 2's defense go over the wire; every node
    // adjudicates EvalCom and names dealer 2.
    let outs = run_keygen(&params, nodes, 300, Some((2, Cheat::BadDeal { victim: 3 })));
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(
                    abort.blamed,
                    vec![2],
                    "node {} blamed {:?}",
                    i + 1,
                    abort.blamed
                );
                assert!(abort.detail.contains("defense"));
            }
            other => panic!("node {}: expected abort blaming 2, got {other:?}", i + 1),
        }
    }
}

#[test]
fn party_keygen_blames_false_accuser() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 14);
    // Node 3 accuses honest dealer 1: the defense verifies, so every node
    // blames the accuser (§6.1 false-accusation branch).
    let outs = run_keygen(
        &params,
        nodes,
        400,
        Some((3, Cheat::FalseAccuse { dealer: 1 })),
    );
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(
                    abort.blamed,
                    vec![3],
                    "node {} blamed {:?}",
                    i + 1,
                    abort.blamed
                );
                assert!(abort.detail.contains("false accusation"));
            }
            other => panic!("node {}: expected abort blaming 3, got {other:?}", i + 1),
        }
    }
}

#[test]
fn party_sign_produces_valid_low_s_signature() {
    let params = Params::new(3, 2).unwrap();
    let (x, results) = run_sign(&params, 21, None);
    let vk = VerifyingKey::from_affine(x.to_affine()).unwrap();
    let mut sigs = Vec::new();
    for (i, res) in results.into_iter().enumerate() {
        let (sig, blamed) = res.unwrap_or_else(|e| panic!("node {}: {e}", i + 1));
        assert!(blamed.is_empty());
        vk.verify(MESSAGE, &sig).expect("valid signature");
        // Low-s (BIP-62/EIP-2).
        assert!(!bool::from(sig.s().is_high()));
        sigs.push(sig);
    }
    assert!(sigs.iter().all(|s| *s == sigs[0]), "all nodes agree");
}

#[test]
fn party_sign_robust_names_cheater_and_delivers() {
    let params = Params::new(3, 2).unwrap();
    // Node 2 broadcasts a wrong share: every node blames it and still
    // interpolates from the two honest shares (§10.4 robust combine).
    let (x, results) = run_sign(&params, 22, Some((2, Cheat::BadSignShare)));
    let vk = VerifyingKey::from_affine(x.to_affine()).unwrap();
    let mut sigs = Vec::new();
    for (i, res) in results.into_iter().enumerate() {
        let (sig, blamed) = res.unwrap_or_else(|e| panic!("node {}: {e}", i + 1));
        assert_eq!(blamed, vec![2], "node {} blamed {:?}", i + 1, blamed);
        vk.verify(MESSAGE, &sig)
            .expect("valid signature despite the cheater");
        sigs.push(sig);
    }
    assert!(sigs.iter().all(|s| *s == sigs[0]), "all nodes agree");
}
