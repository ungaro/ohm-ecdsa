//! M3a integration tests: the per-node OFFLINE FACTORY over real TCP
//! with strict per-node key separation (each node thread holds ONLY its
//! own transport key, its own RNG, its own key share, and its own
//! triple/presignature shares). Coverage: per-node triple generation
//! (SPEC §7.2) with its three cheater classes named identically by every
//! node, per-node presign (SPEC §8) with its opening/nonce-point cheater
//! classes, and the full arc keygen → presign → sign under the key the
//! nodes' own keygen produced (the `party_mesh` tests cover the seeded
//! fallback and the keygen/sign drivers).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar, SecretKey};
use ohm_ecdsa::shamir::interpolate_at_zero;
use ohm_ecdsa::triples::{TriplePublic, TripleShare};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::{Cheat, PartyNode};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/offline";
const MESSAGE: &[u8] = b"party_offline test message";

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

fn x_bytes(x: ProjectivePoint) -> Vec<u8> {
    x.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// Spawn one thread per node running `driver(node, id, rng, cheat)` and
/// collect the results in id order.
fn run_per_node<T: Send + 'static>(
    nodes: Vec<PartyNode>,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
    driver: impl Fn(PartyNode, PartyId, StdRng, Option<Cheat>) -> T + Send + Copy + 'static,
) -> Vec<T> {
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let cheat = cheat_at.and_then(|(at, c)| (at == id).then_some(c));
        threads.push(thread::spawn(move || {
            let rng = StdRng::seed_from_u64(rng_seed + id as u64);
            driver(node, id, rng, cheat)
        }));
    }
    threads.into_iter().map(|t| t.join().unwrap()).collect()
}

type TripleOut = ohm_ecdsa::Result<(TripleShare, TriplePublic)>;

/// Run one per-node triple session (SPEC §7.2) on every node.
fn run_triples(
    params: &Params,
    key_seed: u64,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<TripleOut> {
    let nodes = committee_nodes(params, key_seed);
    run_per_node(
        nodes,
        rng_seed,
        cheat_at,
        move |node, _id, mut rng, cheat| {
            let sid = session_id(GENESIS, b"triples", Some(rng_seed), b"triples");
            node.triple(&sid, &mut rng, cheat)
        },
    )
}

/// Assert every node's outcome is an abort blaming `party` in `phase`
/// whose detail contains `needle`.
fn assert_consistent_blame(outs: Vec<TripleOut>, party: PartyId, phase: Phase, needle: &str) {
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(
                    abort.blamed,
                    vec![party],
                    "node {} blamed {:?}",
                    i + 1,
                    abort.blamed
                );
                assert_eq!(abort.phase, phase, "node {}", i + 1);
                assert!(
                    abort.detail.contains(needle),
                    "node {} detail {:?}",
                    i + 1,
                    abort.detail
                );
            }
            other => panic!(
                "node {}: expected abort blaming {party}, got {other:?}",
                i + 1
            ),
        }
    }
}

#[test]
fn party_triples_multiplicative_2_of_3() {
    let params = Params::new(3, 2).unwrap();
    let outs = run_triples(&params, 31, 500, None);
    let triples: Vec<(TripleShare, TriplePublic)> =
        outs.into_iter().collect::<Result<_, _>>().unwrap();
    // Every node computed the same public commitments on its own view.
    for (_, public) in &triples {
        assert_eq!(public.ca.points, triples[0].1.ca.points);
        assert_eq!(public.cb.points, triples[0].1.cb.points);
        assert_eq!(public.cc.points, triples[0].1.cc.points);
    }
    // Any t = 2 shares reconstruct α, β, γ with α·β = γ, matching the
    // public commitments.
    let parties = vec![1, 2];
    let a = interpolate_at_zero(
        &parties,
        &triples.iter().map(|t| t.0.a).collect::<Vec<_>>()[..2],
    );
    let b = interpolate_at_zero(
        &parties,
        &triples.iter().map(|t| t.0.b).collect::<Vec<_>>()[..2],
    );
    let c = interpolate_at_zero(
        &parties,
        &triples.iter().map(|t| t.0.c).collect::<Vec<_>>()[..2],
    );
    assert_eq!(a * b, c);
    assert_eq!(triples[0].1.ca.points[0], ProjectivePoint::GENERATOR * a);
    assert_eq!(triples[0].1.cb.points[0], ProjectivePoint::GENERATOR * b);
    assert_eq!(triples[0].1.cc.points[0], ProjectivePoint::GENERATOR * c);
    // Distinct nodes hold distinct shares.
    assert_ne!(triples[0].0.a, triples[1].0.a);
}

#[test]
fn party_triples_multiplicative_3_of_5() {
    let params = Params::new(5, 3).unwrap();
    let outs = run_triples(&params, 32, 600, None);
    let triples: Vec<(TripleShare, TriplePublic)> =
        outs.into_iter().collect::<Result<_, _>>().unwrap();
    let parties = vec![2, 4, 5];
    let pick = |f: &dyn Fn(&(TripleShare, TriplePublic)) -> Scalar| {
        parties
            .iter()
            .map(|&p| f(&triples[p - 1]))
            .collect::<Vec<_>>()
    };
    let a = interpolate_at_zero(&parties, &pick(&|t| t.0.a));
    let b = interpolate_at_zero(&parties, &pick(&|t| t.0.b));
    let c = interpolate_at_zero(&parties, &pick(&|t| t.0.c));
    assert_eq!(a * b, c);
    assert_eq!(triples[0].1.cc.points[0], ProjectivePoint::GENERATOR * c);
}

#[test]
fn party_triples_blames_bad_product_proof() {
    let params = Params::new(3, 2).unwrap();
    // Node 2 broadcasts an invalid DLEQ product proof (F3): the proof
    // check fails identically at every node — no complaint round needed.
    let outs = run_triples(&params, 33, 700, Some((2, Cheat::BadProductProof)));
    assert_consistent_blame(outs, 2, Phase::Triples, "DLEQ product proof");
}

#[test]
fn party_triples_blames_bad_reshare_via_wire_complaints() {
    let params = Params::new(3, 2).unwrap();
    // Node 2 sends a wrong re-shared share to party 3 (F2): party 3's
    // §6.1 complaint and node 2's defense (carrying the dealt — wrong —
    // value) go over the wire; every node adjudicates EvalCom and names
    // dealer 2.
    let outs = run_triples(&params, 34, 800, Some((2, Cheat::BadReshare { victim: 3 })));
    assert_consistent_blame(outs, 2, Phase::Triples, "defense");
}

#[test]
fn party_triples_blames_false_accuser() {
    let params = Params::new(3, 2).unwrap();
    // Node 3 accuses honest dealer 1 in the T3 complaint round: the
    // dealer's defense verifies everywhere, so every node blames the
    // accuser (§6.1 false-accusation branch).
    let outs = run_triples(
        &params,
        35,
        900,
        Some((3, Cheat::FalseAccuse { dealer: 1 })),
    );
    assert_consistent_blame(outs, 3, Phase::Triples, "false accusation");
}

/// Per-node presign outcome: the presignature's public `r` (secret
/// shares stay inside the node threads).
fn run_presign(
    params: &Params,
    key_seed: u64,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<ohm_ecdsa::Result<Scalar>> {
    let nodes = committee_nodes(params, key_seed);
    run_per_node(
        nodes,
        rng_seed,
        cheat_at,
        move |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"presign/keygen", Some(rng_seed), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            Ok::<_, Error>(node.presign(&ps_sid, 0, &key, &mut rng, cheat)?.r)
        },
    )
}

#[test]
fn party_presign_blames_bad_nonce_point() {
    let params = Params::new(3, 2).unwrap();
    // Node 2 broadcasts a wrong nonce point R_j (F5): it fails the
    // EvalCom(A[k], 2) check at every node.
    let outs = run_presign(&params, 36, 1000, Some((2, Cheat::BadNoncePoint)));
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(abort.blamed, vec![2], "node {}", i + 1);
                assert_eq!(abort.phase, Phase::Presign, "node {}", i + 1);
                assert!(abort.detail.contains("nonce point"), "node {}", i + 1);
            }
            other => panic!("node {}: expected abort blaming 2, got {other:?}", i + 1),
        }
    }
}

#[test]
fn party_presign_blames_bad_open_share() {
    let params = Params::new(3, 2).unwrap();
    // Node 2 broadcasts a wrong v opening share: it fails the
    // point-equality check against the Beaver-derived commitment at
    // every node (fail-fast identifiable abort, §4.6).
    let outs = run_presign(&params, 37, 1100, Some((2, Cheat::BadOpenShare)));
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(abort.blamed, vec![2], "node {}", i + 1);
                assert_eq!(abort.phase, Phase::Presign, "node {}", i + 1);
                assert!(abort.detail.contains("commitment check"), "node {}", i + 1);
            }
            other => panic!("node {}: expected abort blaming 2, got {other:?}", i + 1),
        }
    }
}

/// The full M3a arc, per node: keygen → presign (under the fresh key) →
/// sign with the presignature the node just produced. Returns, per node,
/// the joint key, the presignature's `r`, the signature, and the blamed
/// signers.
struct ArcOutcome {
    x: ProjectivePoint,
    presig_r: Scalar,
    sig: Signature,
    blamed: Vec<PartyId>,
}

#[test]
fn party_full_arc_signs_under_own_key() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 38);
    let outcomes = run_per_node(nodes, 1200, None, |node, _id, mut rng, cheat| {
        let kg_sid = session_id(GENESIS, b"arc", Some(1200), b"keygen");
        let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
        let xb = x_bytes(key.com.points[0]);
        let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
        let presig = node.presign(&ps_sid, 0, &key, &mut rng, cheat)?;
        let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign");
        let (sig, blamed) = node.sign(&sign_sid, &presig, MESSAGE, cheat)?;
        Ok::<_, Error>(ArcOutcome {
            x: key.com.points[0],
            presig_r: presig.r,
            sig,
            blamed,
        })
    });
    let outcomes: Vec<ArcOutcome> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    // All nodes agree on the fresh joint key and the presignature nonce.
    assert!(outcomes.iter().all(|o| o.x == outcomes[0].x));
    assert!(outcomes.iter().all(|o| o.presig_r == outcomes[0].presig_r));
    // The signature verifies under the key the nodes' OWN keygen
    // produced — no ceremony involved — and is low-s normalized.
    let vk = VerifyingKey::from_affine(outcomes[0].x.to_affine()).unwrap();
    for (i, o) in outcomes.iter().enumerate() {
        assert!(o.blamed.is_empty(), "node {}", i + 1);
        vk.verify(MESSAGE, &o.sig)
            .unwrap_or_else(|e| panic!("node {}: invalid signature: {e}", i + 1));
        assert!(!bool::from(o.sig.s().is_high()), "node {}: high-s", i + 1);
    }
    assert!(outcomes.iter().all(|o| o.sig == outcomes[0].sig));
}
