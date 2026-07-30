//! §8.7 key-independent mode over the wire: the per-node KI drivers on
//! real TCP with strict per-node key separation (each node thread holds
//! ONLY its own transport key, RNG, key shares, and key-free pool
//! records). Coverage: the KI full arc (keygen → KEY-FREE pool record →
//! 2-round online KI sign under the nodes' own key), ONE key-free pool
//! signing for TWO DIFFERENT keys (the §8.7 headline property), single-use
//! enforcement through the pool, and R1 opening-share cheater blame.
//! Thread-level counterpart of the `process_demo_ki_full_arc` test.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar, SecretKey};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::{Cheat, PartyNode};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/ki";
const MESSAGE: &[u8] = b"party_ki test message";

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

/// Per-node KI arc outcome: the joint key, the pool record's public `r`,
/// and the KI signature (secret shares stay inside the node threads).
struct KiOutcome {
    x: ProjectivePoint,
    r: Scalar,
    sig: Signature,
}

#[test]
fn party_ki_full_arc_signs_under_own_key() {
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 41);
    let outcomes = run_per_node(nodes, 1300, None, |node, _id, mut rng, cheat| {
        let kg_sid = session_id(GENESIS, b"ki-arc", Some(1300), b"keygen");
        let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
        let xb = x_bytes(key.com.points[0]);
        // Pool production (P1–P3 only — the record is KEY-FREE), then the
        // 2-round online KI sign binding the record to the fresh key.
        let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign-ki");
        let r = node.presign_ki_pooled(&ps_sid, 0, &mut rng, cheat)?;
        let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign-ki");
        let sig = node.sign_ki_pooled(&sign_sid, 0, &key, MESSAGE, &mut rng, cheat)?;
        // §8.6(1) single-use: the id is consumed; a second signing
        // attempt with it fails LOCALLY before any share is broadcast.
        let again_sid = session_id(GENESIS, &xb, Some(0), b"sign-ki-again");
        let again = node.sign_ki_pooled(&again_sid, 0, &key, b"replay", &mut rng, cheat);
        assert!(
            matches!(again, Err(Error::PresigStore(_))),
            "consumed pool id must not sign twice: {again:?}"
        );
        Ok::<_, Error>(KiOutcome {
            x: key.com.points[0],
            r,
            sig,
        })
    });
    let outcomes: Vec<KiOutcome> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    // All nodes agree on the fresh joint key, the pool record's nonce,
    // and the signature.
    assert!(outcomes.iter().all(|o| o.x == outcomes[0].x));
    assert!(outcomes.iter().all(|o| o.r == outcomes[0].r));
    assert!(outcomes.iter().all(|o| o.sig == outcomes[0].sig));
    // The KI signature verifies under the key the nodes' OWN keygen
    // produced — the pool record was produced before any key binding —
    // and is low-s normalized.
    let vk = VerifyingKey::from_affine(outcomes[0].x.to_affine()).unwrap();
    for (i, o) in outcomes.iter().enumerate() {
        vk.verify(MESSAGE, &o.sig)
            .unwrap_or_else(|e| panic!("node {}: invalid KI signature: {e}", i + 1));
        assert!(!bool::from(o.sig.s().is_high()), "node {}: high-s", i + 1);
    }
}

#[test]
fn party_ki_pool_signs_for_two_different_keys() {
    // THE §8.7 headline over the wire: TWO independent keygens (two
    // different joint keys), ONE key-free pool (two records), and two
    // signatures — one per key — each verifying under its own X.
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 42);
    let outcomes = run_per_node(nodes, 1400, None, |node, _id, mut rng, cheat| {
        // Two fresh keys (two independent keygen sessions).
        let kg_a_sid = session_id(GENESIS, b"two-keys", Some(1400), b"keygen-a");
        let key_a = node.keygen(&kg_a_sid, DKG_TAG, &mut rng, cheat)?;
        let kg_b_sid = session_id(GENESIS, b"two-keys", Some(1400), b"keygen-b");
        let key_b = node.keygen(&kg_b_sid, DKG_TAG, &mut rng, cheat)?;
        let (xa, xb) = (key_a.com.points[0], key_b.com.points[0]);
        assert_ne!(xa, xb, "independent keygens must yield distinct keys");
        // ONE key-free pool, two records (produced under no key at all;
        // the sid anchors on the first key for domain separation only).
        let ps0_sid = session_id(GENESIS, &x_bytes(xa), Some(0), b"presign-ki");
        let r0 = node.presign_ki_pooled(&ps0_sid, 0, &mut rng, cheat)?;
        let ps1_sid = session_id(GENESIS, &x_bytes(xa), Some(1), b"presign-ki");
        let r1 = node.presign_ki_pooled(&ps1_sid, 1, &mut rng, cheat)?;
        assert_ne!(r0, r1, "distinct pool records use distinct nonces");
        // Record 0 signs under key A, record 1 under key B.
        let sign_a_sid = session_id(GENESIS, &x_bytes(xa), Some(0), b"sign-ki");
        let sig_a = node.sign_ki_pooled(
            &sign_a_sid,
            0,
            &key_a,
            b"message for key A",
            &mut rng,
            cheat,
        )?;
        let sign_b_sid = session_id(GENESIS, &x_bytes(xb), Some(1), b"sign-ki");
        let sig_b = node.sign_ki_pooled(
            &sign_b_sid,
            1,
            &key_b,
            b"message for key B",
            &mut rng,
            cheat,
        )?;
        Ok::<_, Error>((xa, xb, sig_a, sig_b))
    });
    let outcomes: Vec<_> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    let (xa, xb, sig_a, sig_b) = &outcomes[0];
    assert!(outcomes.iter().all(|o| o.0 == *xa && o.1 == *xb));
    assert!(outcomes.iter().all(|o| o.2 == *sig_a && o.3 == *sig_b));
    // Each signature verifies under ITS OWN key — and NOT under the other.
    let vk_a = VerifyingKey::from_affine(xa.to_affine()).unwrap();
    let vk_b = VerifyingKey::from_affine(xb.to_affine()).unwrap();
    vk_a.verify(b"message for key A", sig_a).unwrap();
    vk_b.verify(b"message for key B", sig_b).unwrap();
    assert!(vk_a.verify(b"message for key B", sig_b).is_err());
    assert!(vk_b.verify(b"message for key A", sig_a).is_err());
    assert!(!bool::from(sig_a.s().is_high()) && !bool::from(sig_b.s().is_high()));
}

#[test]
fn party_ki_sign_blames_bad_open_share() {
    // Node 2 broadcasts a wrong R1 opening share (δ = ⟦u⟧−⟦α⟧): it fails
    // the point-equality check against A[u]−A[α] at every node (fail-fast
    // identifiable abort, §8.7 K1).
    let params = Params::new(3, 2).unwrap();
    let nodes = committee_nodes(&params, 43);
    let outs = run_per_node(
        nodes,
        1500,
        Some((2, Cheat::BadOpenShare)),
        |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"ki-blame", Some(1500), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign-ki");
            // Honest pool production — the cheat targets the ONLINE R1
            // opening only.
            let presig = node.presign_ki(&ps_sid, 0, &mut rng, None)?;
            let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign-ki");
            node.sign_ki(&sign_sid, &presig, &key, MESSAGE, &mut rng, cheat)
        },
    );
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(abort.blamed, vec![2], "node {}", i + 1);
                assert_eq!(abort.phase, Phase::Sign, "node {}", i + 1);
                assert!(
                    abort.detail.contains("commitment check"),
                    "node {} detail {:?}",
                    i + 1,
                    abort.detail
                );
            }
            other => panic!("node {}: expected abort blaming 2, got {other:?}", i + 1),
        }
    }
}
