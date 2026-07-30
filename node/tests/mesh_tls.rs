//! M3c integration tests: OPTIONAL mutually-authenticated TLS on the
//! mesh (SPEC §13.1) with committee-pinned self-signed certificates.
//! Thread-level, strict per-node key separation (each node holds only
//! its own transport key, its own TLS key, and the PUBLIC pinned
//! committee cert set); the §10.2 envelope signatures stay on
//! regardless — TLS is defense in depth, never a replacement.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, SecretKey};
use ohm_ecdsa::presign::KeyShare;
use ohm_ecdsa::{session_id, Error, Params, PartyId};
use ohm_ecdsa_node::tls::CommitteeTls;
use ohm_ecdsa_node::PartyNode;
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
/// Short timeout for the fail-closed tests (rounds that can never
/// complete error out after the round timeout).
const FAIL_TIMEOUT: Duration = Duration::from_secs(2);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/tls";
const MESSAGE: &[u8] = b"mesh_tls test message";

/// Generate one self-signed cert for a party (rcgen); returns
/// `(cert_der, key_der)` — the key is SECRET.
fn gen_cert(id: PartyId) -> (Vec<u8>, Vec<u8>) {
    let names = vec![
        ohm_ecdsa_node::tls::TLS_SERVER_NAME.to_string(),
        format!("party-{id}.ohm-ecdsa.node"),
    ];
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).expect("rcgen");
    (cert.der().as_ref().to_vec(), signing_key.serialize_der())
}

/// Per-node TLS material for a committee. With `rogue`, that party's
/// OWN certificate is freshly generated and NOT the one the other
/// nodes pin for it (an unpinned peer cert).
fn committee_tls(n: usize, rogue: Option<PartyId>) -> Vec<Arc<CommitteeTls>> {
    let honest: BTreeMap<PartyId, (Vec<u8>, Vec<u8>)> =
        (1..=n).map(|id| (id, gen_cert(id))).collect();
    let pinned: BTreeMap<PartyId, Vec<u8>> = honest
        .iter()
        .map(|(id, (cert, _))| (*id, cert.clone()))
        .collect();
    (1..=n)
        .map(|id| {
            let (own_cert, own_key) = if rogue == Some(id) {
                // The rogue node's own cert is NOT what the committee
                // pins for its id.
                gen_cert(id)
            } else {
                honest[&id].clone()
            };
            let mut my_pinned = pinned.clone();
            if rogue == Some(id) {
                my_pinned.insert(id, own_cert.clone());
            }
            Arc::new(
                CommitteeTls::from_der(id, own_cert, own_key, my_pinned).expect("consistent tls"),
            )
        })
        .collect()
}

/// Transport keys + registry for a committee (same pattern as the
/// plaintext tests).
fn committee_keys(
    params: &Params,
    key_seed: u64,
) -> (Vec<SecretKey>, BTreeMap<PartyId, VerifyingKey>) {
    let mut kr = StdRng::seed_from_u64(key_seed);
    let keys: Vec<SecretKey> = (0..params.n).map(|_| SecretKey::random(&mut kr)).collect();
    let registry = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i + 1, *k256::ecdsa::SigningKey::from(k).verifying_key()))
        .collect();
    (keys, registry)
}

/// Bind `n` TLS PartyNodes (unconnected). `tls[i]` belongs to party
/// `i + 1`.
fn bind_nodes(
    params: &Params,
    key_seed: u64,
    tls: &[Arc<CommitteeTls>],
    timeout: Duration,
) -> Vec<PartyNode> {
    let (keys, registry) = committee_keys(params, key_seed);
    (1..=params.n)
        .map(|id| {
            PartyNode::bind_with_tls(
                id,
                *params,
                &keys[id - 1],
                registry.clone(),
                SocketAddr::from(([127, 0, 0, 1], 0)),
                timeout,
                Some(tls[id - 1].clone()),
            )
            .unwrap()
        })
        .collect()
}

fn connect_all(nodes: &[PartyNode]) {
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    for node in nodes {
        node.connect(&addrs).unwrap();
    }
}

fn x_bytes(x: ProjectivePoint) -> Vec<u8> {
    x.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

struct ArcOutcome {
    x: ProjectivePoint,
    sig: Signature,
}

#[test]
fn tls_full_arc_signs_under_own_key() {
    // The whole M3a arc — keygen → presign → sign — over mTLS: every
    // connection mutually authenticated with committee-pinned certs.
    let params = Params::new(3, 2).unwrap();
    let tls = committee_tls(params.n, None);
    let nodes = bind_nodes(&params, 51, &tls, ROUND_TIMEOUT);
    connect_all(&nodes);
    let mut threads = Vec::new();
    for node in nodes {
        threads.push(thread::spawn(move || {
            let id = node.id();
            let mut rng = StdRng::seed_from_u64(5100 + id as u64);
            let kg_sid = session_id(GENESIS, b"arc", Some(5100), b"keygen");
            let key: KeyShare = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            let presig = node.presign(&ps_sid, 0, &key, &mut rng, None)?;
            let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign");
            let (sig, blamed) = node.sign(&sign_sid, &presig, MESSAGE, None)?;
            assert!(blamed.is_empty());
            Ok::<_, Error>(ArcOutcome {
                x: key.com.points[0],
                sig,
            })
        }));
    }
    let outcomes: Vec<ArcOutcome> = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(outcomes.iter().all(|o| o.x == outcomes[0].x));
    let vk = VerifyingKey::from_affine(outcomes[0].x.to_affine()).unwrap();
    for (i, o) in outcomes.iter().enumerate() {
        vk.verify(MESSAGE, &o.sig)
            .unwrap_or_else(|e| panic!("node {}: invalid signature: {e}", i + 1));
        assert!(!bool::from(o.sig.s().is_high()), "node {}: high-s", i + 1);
    }
    assert!(outcomes.iter().all(|o| o.sig == outcomes[0].sig));
}

#[test]
fn tls_rejects_unpinned_peer_cert() {
    // Node 2 presents a certificate the committee does NOT pin for it
    // (and the committee pins a different cert for id 2): every
    // handshake involving node 2 must fail — in BOTH directions — and
    // the nodes fail closed (no plaintext fallback, keygen cannot
    // complete).
    let params = Params::new(3, 2).unwrap();
    let tls = committee_tls(params.n, Some(2));
    let nodes = bind_nodes(&params, 52, &tls, FAIL_TIMEOUT);
    let addrs: Vec<(PartyId, SocketAddr)> =
        nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
    // The mesh connect REJECTS the unpinned peer. Honest nodes 1 and 3
    // fail synchronously: their outgoing handshake to 2 expects the
    // pinned cert for id 2 and gets the rogue one. Node 2's own
    // outgoing handshakes COMPLETE locally (its pinned set for 1/3 is
    // correct): in TLS 1.3 the client finishes before the server
    // rejects its certificate — the peers kill those links with an
    // alert immediately after, so the connections are dead on arrival.
    for node in &nodes {
        if node.id() == 2 {
            continue;
        }
        assert!(
            node.connect(&addrs).is_err(),
            "node {} must not connect across an unpinned cert",
            node.id()
        );
    }
    // Fail closed: with node 2 cut off, keygen cannot complete anywhere
    // (rounds time out and the drivers abort — no fallback, no wrong
    // key).
    let mut threads = Vec::new();
    for node in nodes {
        threads.push(thread::spawn(move || {
            let id = node.id();
            let mut rng = StdRng::seed_from_u64(5200 + id as u64);
            let kg_sid = session_id(GENESIS, b"rogue", Some(5200), b"keygen");
            node.keygen(&kg_sid, DKG_TAG, &mut rng, None)
        }));
    }
    for (i, t) in threads.into_iter().enumerate() {
        let out = t.join().unwrap();
        assert!(
            out.is_err(),
            "node {} must fail closed without the full mesh, got {out:?}",
            i + 1
        );
    }
}

#[test]
fn tls_rejects_plaintext_peer() {
    // A plaintext TCP peer poking a TLS node's listener: the handshake
    // fails, the connection is dropped, and the node is unaffected (it
    // still completes keygen with its real TLS peers afterwards).
    let params = Params::new(3, 2).unwrap();
    let tls = committee_tls(params.n, None);
    let mut nodes = bind_nodes(&params, 53, &tls, ROUND_TIMEOUT);
    let rest = nodes.split_off(1);
    let first = nodes.into_iter().next().unwrap();

    // Plaintext garbage toward the TLS listener.
    let mut plain = TcpStream::connect(first.local_addr()).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    plain.write_all(b"\x00\x00\x00\x0cnot-tls-at-all").unwrap();
    let mut buf = [0u8; 64];
    let mut closed = false;
    for _ in 0..8 {
        match plain.read(&mut buf) {
            Ok(0) | Err(_) => {
                closed = true;
                break;
            }
            Ok(_) => {} // TLS alert bytes before the close
        }
    }
    assert!(closed, "the TLS node must drop a plaintext peer");

    // The node still works: bring up the rest of the TLS committee and
    // run keygen.
    let mut all = vec![first];
    all.extend(rest);
    connect_all(&all);
    let mut threads = Vec::new();
    for node in all {
        threads.push(thread::spawn(move || {
            let id = node.id();
            let mut rng = StdRng::seed_from_u64(5300 + id as u64);
            let kg_sid = session_id(GENESIS, b"plain-poke", Some(5300), b"keygen");
            node.keygen(&kg_sid, DKG_TAG, &mut rng, None)
        }));
    }
    let shares: Vec<KeyShare> = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Result<_, _>>()
        .expect("keygen completes after the rejected plaintext attempt");
    assert!(shares
        .iter()
        .all(|s| s.com.points[0] == shares[0].com.points[0]));
}
