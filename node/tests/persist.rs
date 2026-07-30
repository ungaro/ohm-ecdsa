//! M3b integration tests: persistence and the §A.4 evidence flow.
//!
//! Coverage: the durable presignature store (SPEC §8.6 — survives
//! drop/reopen, a consumed id stays consumed across a simulated crash,
//! duplicate inserts rejected, wrong-key reopen rejected, stray `.tmp`
//! files dropped), the transcript archive (§4.7 accepted sets,
//! dedup + decode), the blame-token archive and OFFLINE auditor (§10.2,
//! §A.4 — F2 dealt-share and F6 sign-share tokens verify, a tampered
//! token is rejected), and crash-recovery integration: a node signs
//! (consuming the record), "restarts" (a fresh store instance on the
//! same directory), and a second sign with the same id fails.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, SecretKey};
use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::{Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::{session_id, Error, Params, PartyId, Phase};
use ohm_ecdsa_node::persist::{
    audit_token, read_transcript, Archive, DiskPresigStore, PersistError,
};
use ohm_ecdsa_node::seal::StorageKey;
use ohm_ecdsa_node::{Cheat, NodePayload, PartyNode};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Deterministic storage key for sealed-store tests (H5).
fn sk() -> StorageKey {
    StorageKey::from_secret(&[7u8; 32])
}

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/persist";
const MESSAGE: &[u8] = b"persist test message";

/// A fresh empty temp directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-persist-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// One ceremony-style presignature record (id 0) plus the joint key it
/// is bound to, produced by the core's deterministic sim.
fn test_presig() -> (Presignature, AffinePoint) {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 7);
    let keys = sim::run_keygen(&params, b"ohm-ecdsa-node/persist-test/keygen", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 0, &mut rngs, None).unwrap();
    let first = presigs.into_iter().next().expect("one record per party");
    (first, keys[0].com.points[0].to_affine())
}

// --- the durable store (SPEC §8.6) ------------------------------------------

#[test]
fn disk_store_survives_reopen() {
    let dir = tmpdir("reopen");
    let (presig, x) = test_presig();
    {
        let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
        store.insert(&presig).unwrap();
        assert!(store.contains(0));
    } // drop == close
    let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
    assert_eq!(store.len(), 1);
    let back = store.consume(0).unwrap();
    assert_eq!(back.id, presig.id);
    assert_eq!(back.r, presig.r);
    assert_eq!(back.u_share, presig.u_share);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_store_consumed_stays_consumed_across_restart() {
    let dir = tmpdir("consumed");
    let (presig, x) = test_presig();
    {
        let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
        store.insert(&presig).unwrap();
        store.consume(0).unwrap();
        assert!(dir.join("0.consumed").exists());
    } // simulated crash: the process dies here
      // §8.6(1): the tombstone was fsync'd BEFORE the record was handed
      // out, so the id stays consumed across the kill/restart.
    let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
    assert!(store.is_empty());
    let err = store.consume(0).unwrap_err();
    assert!(
        matches!(err, PersistError::Protocol(Error::PresigStore(_))),
        "consume after restart: {err:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_store_rejects_duplicate_insert_after_reopen() {
    let dir = tmpdir("duplicate");
    let (presig, x) = test_presig();
    {
        let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
        store.insert(&presig).unwrap();
        let err = store.insert(&presig).unwrap_err();
        assert!(matches!(err, PersistError::Protocol(Error::PresigStore(_))));
    }
    // Duplicate rejection survives the reopen, both for a live id…
    let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
    let err = store.insert(&presig).unwrap_err();
    assert!(matches!(err, PersistError::Protocol(Error::PresigStore(_))));
    // …and for an id that was already CONSUMED (nonce-reuse guard).
    store.consume(0).unwrap();
    let err = store.insert(&presig).unwrap_err();
    assert!(matches!(err, PersistError::Protocol(Error::PresigStore(_))));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_store_rejects_wrong_key() {
    let dir = tmpdir("wrong-key");
    let (presig, x) = test_presig();
    let mut store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
    store.insert(&presig).unwrap();
    drop(store);
    // §8.6(4): one store per long-term key — reopening under a different
    // key is rejected.
    let other = ProjectivePoint::GENERATOR.to_affine();
    let err = DiskPresigStore::open(&dir, &other, &sk()).unwrap_err();
    assert!(matches!(err, PersistError::Protocol(Error::PresigStore(_))));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_store_drops_stray_tmp_file() {
    let dir = tmpdir("stray-tmp");
    let (_, x) = test_presig();
    // A crash between the temp write and the rename leaves a `.tmp`
    // file; the insert was never acknowledged, so `open` deletes it.
    fs::write(dir.join("5.tmp"), b"partial record").unwrap();
    let store = DiskPresigStore::open(&dir, &x, &sk()).unwrap();
    assert!(!dir.join("5.tmp").exists());
    assert!(!store.contains(5));
    assert!(store.is_empty());
    fs::remove_dir_all(&dir).ok();
}

// --- the transcript archive (SPEC §4.7) ---------------------------------------

#[test]
fn transcript_archive_dedups_and_decodes() {
    let dir = tmpdir("transcript");
    let sk = SecretKey::random(&mut StdRng::seed_from_u64(11));
    let key = SigningKey::from(&sk);
    let se1 = SignedEnvelope::sign(
        Envelope::broadcast(
            b"sid",
            Phase::KeyGen,
            1,
            1,
            NodePayload::Complaints(vec![2]),
        ),
        &key,
    );
    let se2 = SignedEnvelope::sign(
        Envelope::broadcast(b"sid", Phase::KeyGen, 2, 1, NodePayload::Complaints(vec![])),
        &key,
    );
    {
        let mut archive = Archive::create(&dir).unwrap();
        archive.log_accepted(&se1).unwrap();
        archive.log_accepted(&se1).unwrap(); // same slot: deduped
        archive.log_accepted(&se2).unwrap();
    }
    // An existing transcript is appended to, not truncated.
    let mut archive = Archive::create(&dir).unwrap();
    archive.log_accepted(&se1).unwrap();
    let entries = read_transcript(&dir.join("transcript.log")).unwrap();
    assert_eq!(entries.len(), 3);
    let encoded: Vec<Vec<u8>> = entries
        .iter()
        .map(|se| {
            let mut b = Vec::new();
            se.encode(&mut b);
            b
        })
        .collect();
    let mut e1 = Vec::new();
    se1.encode(&mut e1);
    let mut e2 = Vec::new();
    se2.encode(&mut e2);
    assert_eq!(encoded, vec![e1.clone(), e2, e1]);
    fs::remove_dir_all(&dir).ok();
}

// --- thread-level harness (as party_offline.rs, with the registry kept) -------

/// Build `n` connected PartyNodes plus the public key registry (the
/// auditor's input).
fn committee_nodes(
    params: &Params,
    key_seed: u64,
) -> (Vec<PartyNode>, Vec<(PartyId, VerifyingKey)>) {
    let mut kr = StdRng::seed_from_u64(key_seed);
    let keys: Vec<SecretKey> = (0..params.n).map(|_| SecretKey::random(&mut kr)).collect();
    let registry: Vec<(PartyId, VerifyingKey)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (i + 1, *SigningKey::from(k).verifying_key()))
        .collect();
    let btree: BTreeMap<PartyId, VerifyingKey> = registry.iter().cloned().collect();
    let nodes: Vec<PartyNode> = (1..=params.n)
        .map(|id| {
            PartyNode::bind(
                id,
                *params,
                &keys[id - 1],
                btree.clone(),
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
    (nodes, registry)
}

// --- the blame-token archive + offline auditor (SPEC §10.2, §A.4) --------------

/// F2 over the wire: node 2 deals a wrong share to party 1 in keygen.
/// The accuser (node 1) archives a dealt-share token; the auditor
/// verifies it offline and rejects a tampered copy.
#[test]
fn audit_token_verifies_and_rejects_tampered() {
    let params = Params::new(3, 2).unwrap();
    let dir = tmpdir("audit-dealt");
    let (nodes, registry) = committee_nodes(&params, 51);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let node_dir = dir.join(format!("node-{id}"));
        threads.push(thread::spawn(move || {
            node.set_archive(&node_dir.join("archive")).unwrap();
            let cheat = (id == 2).then_some(Cheat::BadDeal { victim: 1 });
            let mut rng = StdRng::seed_from_u64(600 + id as u64);
            let sid = session_id(GENESIS, b"audit", Some(0), b"keygen");
            node.keygen(&sid, DKG_TAG, &mut rng, cheat)
        }));
    }
    // Every node reaches the same verdict: dealer 2 blamed.
    for t in threads {
        match t.join().unwrap() {
            Err(Error::Abort { abort }) => assert_eq!(abort.blamed, vec![2]),
            other => panic!("expected abort blaming 2, got {other:?}"),
        }
    }
    // Only the ACCUSER holds the dealer's signed P2P share envelope —
    // only its archive has a token; the others log `token: none`.
    let token_path = dir.join("node-1/archive/blame-keygen-2.tok");
    assert!(token_path.exists());
    for id in [2, 3] {
        let aborts = fs::read_to_string(dir.join(format!("node-{id}/archive/aborts.log"))).unwrap();
        assert!(aborts.contains("token: none"), "node {id}: {aborts}");
    }
    // The offline audit: every check passes, the verdict is VALID.
    let bytes = fs::read(&token_path).unwrap();
    let report = audit_token(&bytes, &registry);
    assert!(report.verdict(), "checks: {:?}", report.checks);
    assert_eq!(report.blamed, vec![2]);
    assert_eq!(report.phase, Phase::KeyGen);
    // A tampered token (one flipped byte) is rejected.
    let mut tampered = bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert!(!audit_token(&tampered, &registry).verdict());
    // …and so is the honest token audited against the WRONG registry.
    let wrong: Vec<(PartyId, VerifyingKey)> = (1..=3usize)
        .map(|i| {
            let sk = SecretKey::random(&mut StdRng::seed_from_u64(90 + i as u64));
            (i, *SigningKey::from(&sk).verifying_key())
        })
        .collect();
    assert!(!audit_token(&bytes, &wrong).verdict());
    fs::remove_dir_all(&dir).ok();
}

/// F6 over the wire: node 2 broadcasts a wrong signature share in the
/// full arc. Every honest node archives a sign-share token; the auditor
/// recomputes `s_j·G == EvalCom(m·A[u] + r·A[z], j)` offline.
#[test]
fn audit_sign_share_token_verifies() {
    let params = Params::new(3, 2).unwrap();
    let dir = tmpdir("audit-sign");
    let (nodes, registry) = committee_nodes(&params, 52);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let node_dir = dir.join(format!("node-{id}"));
        threads.push(thread::spawn(move || {
            node.set_archive(&node_dir.join("archive")).unwrap();
            let cheat = (id == 2).then_some(Cheat::BadSignShare);
            let mut rng = StdRng::seed_from_u64(700 + id as u64);
            let kg_sid = session_id(GENESIS, b"audit-sign", Some(0), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
            let xb = key.com.points[0].to_affine().to_encoded_point(true);
            let ps_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"presign");
            let presig = node.presign(&ps_sid, 0, &key, &mut rng, cheat)?;
            let sign_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"sign");
            node.sign(&sign_sid, &presig, MESSAGE, cheat)
        }));
    }
    // The signature is still delivered; node 2 is blamed by all.
    for t in threads {
        let (_sig, blamed) = t.join().unwrap().unwrap();
        assert_eq!(blamed, vec![2]);
    }
    let token_path = dir.join("node-1/archive/blame-sign-2.tok");
    assert!(token_path.exists());
    assert!(dir.join("node-3/archive/blame-sign-2.tok").exists());
    let bytes = fs::read(&token_path).unwrap();
    let report = audit_token(&bytes, &registry);
    assert!(report.verdict(), "checks: {:?}", report.checks);
    assert_eq!(report.phase, Phase::Sign);
    let mut tampered = bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert!(!audit_token(&tampered, &registry).verdict());
    fs::remove_dir_all(&dir).ok();
}

// --- crash recovery (SPEC §8.6(1)) --------------------------------------------

/// The full arc with durable stores: each node presigns (persisting the
/// record) and signs (consuming it with an fsync'd tombstone). A
/// "restart" — a FRESH store instance on the same directory — sees the
/// tombstone: a second sign with the same presignature id fails.
#[test]
fn party_arc_restart_keeps_consumed_ids() {
    let params = Params::new(3, 2).unwrap();
    let dir = tmpdir("crash-recovery");
    let (nodes, _registry) = committee_nodes(&params, 53);
    let mut threads = Vec::new();
    for (k, node) in nodes.into_iter().enumerate() {
        let id = k + 1;
        let node_dir = dir.join(format!("node-{id}"));
        threads.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(800 + id as u64);
            let kg_sid = session_id(GENESIS, b"crash", Some(0), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let x = key.com.points[0].to_affine();
            node.set_store(&node_dir.join("store"), &x).unwrap();
            let xb = x.to_encoded_point(true);
            let ps_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"presign");
            node.presign_stored(&ps_sid, 0, &key, &mut rng, None)
                .unwrap();
            let sign_sid = session_id(GENESIS, xb.as_bytes(), Some(0), b"sign");
            let (sig, blamed) = node.sign_stored(&sign_sid, 0, MESSAGE, None).unwrap();
            assert!(blamed.is_empty());
            Ok::<_, Error>((x, sig))
        }));
    }
    let mut xs = Vec::new();
    for t in threads {
        let (x, _sig) = t.join().unwrap().unwrap();
        xs.push(x);
    }
    assert!(xs.iter().all(|x| *x == xs[0]));
    // Simulated crash + restart: reopen the store on each node's
    // directory. The consumed id stays consumed (§8.6(1)).
    for id in 1..=3usize {
        let store_dir = dir.join(format!("node-{id}/store"));
        assert!(store_dir.join("0.consumed").exists());
        assert!(!store_dir.join("0.presig").exists());
        let mut store = DiskPresigStore::open(&store_dir, &xs[0], &sk()).unwrap();
        assert!(store.is_empty());
        let err = store.consume(0).unwrap_err();
        assert!(
            matches!(err, PersistError::Protocol(Error::PresigStore(_))),
            "node {id}: {err:?}"
        );
    }
    fs::remove_dir_all(&dir).ok();
}
