//! H4 integration tests: §10.4 robust continuation and §10.3
//! expel-and-restart over real TCP with strict per-node key separation
//! (each node thread holds ONLY its own transport key, its own RNG, its
//! own key share, and its own triple/presignature shares). Coverage:
//! robust sign with blame-token archiving (M3b F6), robust presign
//! openings (bad `v` share, bad nonce point) completing with consistent
//! blame and records that still sign, robust triple reconstruction of a
//! cheating dealer's committed re-sharing polynomial (and the fabricated
//! -request branch), 3-of-6 expel-and-restart over the surviving
//! original ids with poisoned sid/id, zero-slack refusal in 2-of-3
//! (never lowering `t`), and robust KI signing (R1 + R2 faults).
//! The fail-fast default drivers stay covered by `party_mesh` /
//! `party_offline` / `party_ki`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
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
use ohm_ecdsa_node::persist::audit_token;
use ohm_ecdsa_node::{Cheat, PartyNode};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const DKG_TAG: &[u8] = b"ohm-ecdsa-node/test/dkg";
const GENESIS: &[u8] = b"ohm-ecdsa-node/test/robust";
const MESSAGE: &[u8] = b"party_robust test message";

/// A fresh empty temp directory for one test (archives).
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-robust-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build `n` connected PartyNodes, each holding ONLY its own transport
/// key; also returns the PUBLIC registry (for the offline auditor).
fn committee_nodes(
    params: &Params,
    key_seed: u64,
) -> (Vec<PartyNode>, Vec<(PartyId, VerifyingKey)>) {
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
    (nodes, registry.into_iter().collect())
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

/// Assert a signature is equal at every node, verifies under `x`, and is
/// low-s normalized.
fn assert_sig(x: ProjectivePoint, sigs: &[Signature]) {
    assert!(sigs.iter().all(|s| *s == sigs[0]), "signatures disagree");
    let vk = VerifyingKey::from_affine(x.to_affine()).unwrap();
    for (i, sig) in sigs.iter().enumerate() {
        vk.verify(MESSAGE, sig)
            .unwrap_or_else(|e| panic!("node {}: invalid signature: {e}", i + 1));
        assert!(!bool::from(sig.s().is_high()), "node {}: high-s", i + 1);
    }
}

// --- 1. Robust sign (§10.4 online) + M3b F6 token archiving -------------

#[test]
fn party_sign_robust_blames_cheater_and_archives_token() {
    // Node 2 broadcasts a wrong signature share: every node filters it,
    // names party 2, and still delivers the SAME valid signature — and
    // every node's archive holds a verifying F6 blame token for party 2.
    let params = Params::new(3, 2).unwrap();
    let (nodes, registry) = committee_nodes(&params, 51);
    let dirs: Vec<PathBuf> = (0..params.n)
        .map(|i| tmpdir(&format!("sign-{i}")))
        .collect();
    for (node, dir) in nodes.iter().zip(&dirs) {
        node.set_archive(dir).unwrap();
    }
    let outcomes = run_per_node(
        nodes,
        2100,
        Some((2, Cheat::BadSignShare)),
        |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"sign-arc", Some(2100), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            let presig = node.presign(&ps_sid, 0, &key, &mut rng, cheat)?;
            let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign");
            let (sig, blamed) = node.sign(&sign_sid, &presig, MESSAGE, cheat)?;
            Ok::<_, Error>((key.com.points[0], sig, blamed))
        },
    );
    let outcomes: Vec<_> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, (_, _, blamed)) in outcomes.iter().enumerate() {
        assert_eq!(*blamed, vec![2], "node {} blamed {blamed:?}", i + 1);
    }
    let sigs: Vec<Signature> = outcomes.iter().map(|o| o.1).collect();
    assert_sig(outcomes[0].0, &sigs);
    // M3b: the F6 sign-share token for party 2 is archived at EVERY node
    // and verifies offline against the public registry.
    for dir in &dirs {
        let token = dir.join("blame-sign-2.tok");
        assert!(token.exists(), "missing token in {}", dir.display());
        let bytes = std::fs::read(&token).unwrap();
        let report = audit_token(&bytes, &registry);
        assert!(
            report.verdict(),
            "token in {} failed the offline audit: {:?}",
            dir.display(),
            report.checks
        );
    }
}

// --- 2. Robust presign openings (§10.4 offline) --------------------------

/// Robust-presign arc outcome: the joint key, the presignature nonce,
/// the presign blame, and a signature produced with the record.
struct PresignOutcome {
    x: ProjectivePoint,
    presig_r: Scalar,
    blamed: Vec<PartyId>,
    sig: Signature,
    sign_blamed: Vec<PartyId>,
}

fn run_presign_robust_arc(
    params: &Params,
    key_seed: u64,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<ohm_ecdsa::Result<PresignOutcome>> {
    let (nodes, _) = committee_nodes(params, key_seed);
    run_per_node(
        nodes,
        rng_seed,
        cheat_at,
        move |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"presign-robust", Some(rng_seed), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, cheat)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            let (presig, blamed) = node.presign_robust(&ps_sid, 0, &key, &mut rng, cheat)?;
            let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign");
            let (sig, sign_blamed) = node.sign(&sign_sid, &presig, MESSAGE, cheat)?;
            Ok::<_, Error>(PresignOutcome {
                x: key.com.points[0],
                presig_r: presig.r,
                blamed,
                sig,
                sign_blamed,
            })
        },
    )
}

#[test]
fn party_presign_robust_continues_bad_open_share() {
    // Node 2 broadcasts a wrong `v` opening share: it is filtered and
    // blamed at EVERY node (point equality on public data), the opening
    // interpolates from the remaining ≥ t valid shares, the presign
    // completes everywhere, and the resulting records sign and verify.
    let params = Params::new(5, 3).unwrap();
    let outcomes = run_presign_robust_arc(&params, 52, 2200, Some((2, Cheat::BadOpenShare)));
    let outcomes: Vec<PresignOutcome> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o.blamed, vec![2], "node {} blamed {:?}", i + 1, o.blamed);
        assert!(o.sign_blamed.is_empty(), "node {}", i + 1);
        assert_eq!(o.presig_r, outcomes[0].presig_r, "node {}", i + 1);
    }
    let sigs: Vec<Signature> = outcomes.iter().map(|o| o.sig).collect();
    assert_sig(outcomes[0].x, &sigs);
}

#[test]
fn party_presign_robust_continues_bad_nonce_point() {
    // Node 2 broadcasts a wrong nonce point R_2 (F5): it is filtered and
    // blamed everywhere, R interpolates over the valid senders with the
    // subset Lagrange weights, and the records still sign and verify.
    let params = Params::new(5, 3).unwrap();
    let outcomes = run_presign_robust_arc(&params, 53, 2300, Some((2, Cheat::BadNoncePoint)));
    let outcomes: Vec<PresignOutcome> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o.blamed, vec![2], "node {} blamed {:?}", i + 1, o.blamed);
        assert_eq!(o.presig_r, outcomes[0].presig_r, "node {}", i + 1);
    }
    let sigs: Vec<Signature> = outcomes.iter().map(|o| o.sig).collect();
    assert_sig(outcomes[0].x, &sigs);
}

// --- 3. Robust triples: §10.4 public reconstruction ----------------------

type TripleRobustOut = ohm_ecdsa::Result<(TripleShare, TriplePublic, Vec<PartyId>)>;

fn run_triples_robust(
    params: &Params,
    key_seed: u64,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<TripleRobustOut> {
    let (nodes, _) = committee_nodes(params, key_seed);
    run_per_node(
        nodes,
        rng_seed,
        cheat_at,
        move |node, _id, mut rng, cheat| {
            let sid = session_id(GENESIS, b"triples-robust", Some(rng_seed), b"triples");
            node.triple_robust(&sid, &mut rng, cheat)
        },
    )
}

#[test]
fn party_triples_robust_reconstructs_bad_reshare() {
    // Node 2 sends a wrong re-shared share g_2(4) to party 4: party 4's
    // reconstruction request carries node 2's own signed envelope, every
    // node blames dealer 2, and the supply round lets every node
    // interpolate the committed g_2 — the victim recovers its share and
    // the triple is multiplicative at the public commitments.
    let params = Params::new(5, 3).unwrap();
    let outs = run_triples_robust(
        &params,
        54,
        2400,
        Some((2, Cheat::BadReshare { victim: 4 })),
    );
    let triples: Vec<(TripleShare, TriplePublic, Vec<PartyId>)> =
        outs.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, (share, public, blamed)) in triples.iter().enumerate() {
        assert_eq!(*blamed, vec![2], "node {} blamed {blamed:?}", i + 1);
        assert_eq!(public.cc.points, triples[0].1.cc.points, "node {}", i + 1);
        // Every node's c-share — including the VICTIM's reconstructed
        // one — verifies against the public commitment at its index.
        assert!(
            public.cc.verify_share(i + 1, &share.c),
            "node {}: c-share fails the commitment check",
            i + 1
        );
    }
    // c == a·b per the openings (interpolating over a set that INCLUDES
    // the victim node 4's recovered share), matching the commitments.
    type TripleOut = (TripleShare, TriplePublic, Vec<PartyId>);
    let parties = vec![1, 3, 4];
    let pick = |f: &dyn Fn(&TripleOut) -> Scalar| {
        parties
            .iter()
            .map(|&p| f(&triples[p - 1]))
            .collect::<Vec<_>>()
    };
    let a = interpolate_at_zero(&parties, &pick(&|t| t.0.a));
    let b = interpolate_at_zero(&parties, &pick(&|t| t.0.b));
    let c = interpolate_at_zero(&parties, &pick(&|t| t.0.c));
    assert_eq!(a * b, c);
    assert_eq!(triples[0].1.ca.points[0], ProjectivePoint::GENERATOR * a);
    assert_eq!(triples[0].1.cb.points[0], ProjectivePoint::GENERATOR * b);
    assert_eq!(triples[0].1.cc.points[0], ProjectivePoint::GENERATOR * c);
}

#[test]
fn party_triples_robust_blames_false_requester() {
    // Node 3 accuses honest dealer 1 in the reconstruction request
    // round: the carried envelope's share VERIFIES against the dealer's
    // commitment, so every node blames the requester (fabricated
    // evidence is an abort — §10.3 restarts without the accuser).
    let params = Params::new(3, 2).unwrap();
    let outs = run_triples_robust(
        &params,
        55,
        2500,
        Some((3, Cheat::FalseAccuse { dealer: 1 })),
    );
    for (i, out) in outs.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(abort.blamed, vec![3], "node {}", i + 1);
                assert_eq!(abort.phase, Phase::Triples, "node {}", i + 1);
                assert!(
                    abort.detail.contains("false accusation"),
                    "node {} detail {:?}",
                    i + 1,
                    abort.detail
                );
            }
            other => panic!("node {}: expected abort blaming 3, got {other:?}", i + 1),
        }
    }
}

// --- 4. Expel-and-restart (§10.3) at the driver level --------------------

#[test]
fn party_keygen_restart_completes_over_survivors_original_ids() {
    // 3-of-6 with node 2 dealing a wrong share to party 5 (F2): the
    // session restarts over the 5 survivors with ORIGINAL ids and
    // completes; node 2 is expelled (its own run ends with the abort).
    let params = Params::new(6, 3).unwrap();
    let (nodes, _) = committee_nodes(&params, 56);
    let outcomes = run_per_node(
        nodes,
        2600,
        Some((2, Cheat::BadDeal { victim: 5 })),
        |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"keygen-restart", Some(2600), b"keygen");
            node.keygen_with_restart(&kg_sid, DKG_TAG, &mut rng, cheat)
        },
    );
    let mut xs = Vec::new();
    for (i, out) in outcomes.into_iter().enumerate() {
        let id = i + 1;
        if id == 2 {
            match out {
                Err(Error::Abort { abort }) => assert_eq!(abort.blamed, vec![2]),
                other => panic!("node 2: expected expulsion abort, got {other:?}"),
            }
            continue;
        }
        let (share, committee, blamed) = out.unwrap_or_else(|e| panic!("node {id}: {e}"));
        assert_eq!(committee, vec![1, 3, 4, 5, 6], "node {id}");
        assert_eq!(blamed, vec![2], "node {id}");
        assert_eq!(share.index, id, "node {id}: original id preserved");
        assert!(
            share.com.verify_share(id, &share.share),
            "node {id}: share fails the commitment check"
        );
        xs.push(share.com.points[0]);
    }
    assert!(xs.iter().all(|x| *x == xs[0]), "survivors disagree on X");
}

/// Restart-presign outcome: the joint key, the id actually used, the
/// final committee, the cumulative blame, and a signature over the
/// final committee.
#[derive(Debug)]
struct RestartOutcome {
    x: ProjectivePoint,
    used_id: u64,
    committee: Vec<PartyId>,
    blamed: Vec<PartyId>,
    sig: Signature,
}

#[test]
fn party_presign_restart_completes_3_of_6() {
    // 3-of-6 with node 2 broadcasting an invalid DLEQ product proof in
    // the first triple session (F3, dealing phase — not continuable):
    // every node computes the SAME restart committee ([1,3,4,5,6],
    // original ids), poisons the sid AND the presignature id, and the
    // retry completes; the survivors sign over the final committee.
    const FIRST_ID: u64 = 7;
    let params = Params::new(6, 3).unwrap();
    let (nodes, _) = committee_nodes(&params, 57);
    let outcomes = run_per_node(
        nodes,
        2700,
        Some((2, Cheat::BadProductProof)),
        |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"presign-restart", Some(2700), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            let (presig, used_id, committee, blamed) =
                node.presign_with_restart(&ps_sid, FIRST_ID, &key, &mut rng, cheat)?;
            let sign_sid = session_id(GENESIS, &xb, Some(used_id), b"sign");
            let (sig, sign_blamed) =
                node.sign_over(&sign_sid, &presig, MESSAGE, &committee, cheat)?;
            assert!(sign_blamed.is_empty());
            Ok::<_, Error>(RestartOutcome {
                x: key.com.points[0],
                used_id,
                committee,
                blamed,
                sig,
            })
        },
    );
    let mut survivors = Vec::new();
    for (i, out) in outcomes.into_iter().enumerate() {
        let id = i + 1;
        if id == 2 {
            match out {
                Err(Error::Abort { abort }) => {
                    assert_eq!(abort.blamed, vec![2]);
                    assert!(
                        abort.detail.contains("expelled"),
                        "node 2: {}",
                        abort.detail
                    );
                }
                other => panic!("node 2: expected expulsion abort, got {other:?}"),
            }
            continue;
        }
        let o = out.unwrap_or_else(|e| panic!("node {id}: {e}"));
        // §10.3(2): the poisoned id is never reused — the retry used a
        // fresh id (and, internally, a fresh sid).
        assert_eq!(o.used_id, FIRST_ID + 1, "node {id}: id not poisoned");
        assert_eq!(o.committee, vec![1, 3, 4, 5, 6], "node {id}");
        assert_eq!(o.blamed, vec![2], "node {id}");
        survivors.push(o);
    }
    assert_eq!(survivors.len(), 5);
    assert!(survivors.iter().all(|o| o.x == survivors[0].x));
    let sigs: Vec<Signature> = survivors.iter().map(|o| o.sig).collect();
    assert_sig(survivors[0].x, &sigs);
}

#[test]
fn party_presign_restart_refused_zero_slack() {
    // 2-of-3 (n = 2t−1 — ZERO slack): any expulsion would drop below
    // 2t−1, so the restart is REFUSED and the session fails with the
    // policy refusal noted — `t` is never silently lowered.
    let params = Params::new(3, 2).unwrap();
    let (nodes, _) = committee_nodes(&params, 58);
    let outcomes = run_per_node(
        nodes,
        2800,
        Some((2, Cheat::BadProductProof)),
        |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"zero-slack", Some(2800), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let xb = x_bytes(key.com.points[0]);
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign");
            node.presign_with_restart(&ps_sid, 0, &key, &mut rng, cheat)
        },
    );
    for (i, out) in outcomes.into_iter().enumerate() {
        match out {
            Err(Error::Abort { abort }) => {
                assert_eq!(abort.blamed, vec![2], "node {}", i + 1);
                assert!(
                    abort.detail.contains("expel-and-restart refused"),
                    "node {} detail {:?}",
                    i + 1,
                    abort.detail
                );
            }
            other => panic!(
                "node {}: expected a refused-restart abort blaming 2, got {other:?}",
                i + 1
            ),
        }
    }
}

// --- 5. Robust KI signing (§8.7 + §10.4) ---------------------------------

fn run_ki_robust_arc(
    key_seed: u64,
    rng_seed: u64,
    cheat_at: Option<(PartyId, Cheat)>,
) -> Vec<ohm_ecdsa::Result<(ProjectivePoint, Signature, Vec<PartyId>)>> {
    let params = Params::new(3, 2).unwrap();
    let (nodes, _) = committee_nodes(&params, key_seed);
    run_per_node(
        nodes,
        rng_seed,
        cheat_at,
        move |node, _id, mut rng, cheat| {
            let kg_sid = session_id(GENESIS, b"ki-robust", Some(rng_seed), b"keygen");
            let key = node.keygen(&kg_sid, DKG_TAG, &mut rng, None)?;
            let xb = x_bytes(key.com.points[0]);
            // Honest KEY-FREE pool production — the cheat targets the online
            // KI sign only.
            let ps_sid = session_id(GENESIS, &xb, Some(0), b"presign-ki");
            let presig = node.presign_ki(&ps_sid, 0, &mut rng, None)?;
            let sign_sid = session_id(GENESIS, &xb, Some(0), b"sign-ki");
            let (sig, blamed) =
                node.sign_ki_robust(&sign_sid, &presig, &key, MESSAGE, &mut rng, cheat)?;
            Ok::<_, Error>((key.com.points[0], sig, blamed))
        },
    )
}

#[test]
fn party_sign_ki_robust_blames_bad_sign_share_and_delivers() {
    // Node 2 broadcasts a wrong R2 signature share: filtered and blamed
    // at every node; the KI signature is still delivered and verifies.
    let outcomes = run_ki_robust_arc(59, 2900, Some((2, Cheat::BadSignShare)));
    let outcomes: Vec<_> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, (_, _, blamed)) in outcomes.iter().enumerate() {
        assert_eq!(*blamed, vec![2], "node {} blamed {blamed:?}", i + 1);
    }
    let sigs: Vec<Signature> = outcomes.iter().map(|o| o.1).collect();
    assert_sig(outcomes[0].0, &sigs);
}

#[test]
fn party_sign_ki_robust_continues_bad_open_share() {
    // Node 2 broadcasts a wrong R1 opening share (δ = ⟦u⟧−⟦α⟧): filtered
    // and blamed at every node, expelled from R2's share set; the KI
    // signature is still delivered and verifies.
    let outcomes = run_ki_robust_arc(60, 3000, Some((2, Cheat::BadOpenShare)));
    let outcomes: Vec<_> = outcomes.into_iter().collect::<Result<_, _>>().unwrap();
    for (i, (_, _, blamed)) in outcomes.iter().enumerate() {
        assert_eq!(*blamed, vec![2], "node {} blamed {blamed:?}", i + 1);
    }
    let sigs: Vec<Signature> = outcomes.iter().map(|o| o.1).collect();
    assert_sig(outcomes[0].0, &sigs);
}
