//! End-to-end integration tests for OHM-ECDSA (SPEC §6–§10).

use k256::ecdsa::{signature::Verifier, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use std::collections::BTreeMap;

use ohm_ecdsa::dkg::DkgTamper;
use ohm_ecdsa::open::open;
use ohm_ecdsa::presign::{KeyShare, PresignTamper};
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::{self, SimTransport};
use ohm_ecdsa::triples::{self, TripleShare, TripleTamper};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{Error, Params, PartyId, Phase, PresigStore};

fn pubkey(keys: &[KeyShare]) -> ProjectivePoint {
    keys[0].com.points[0]
}

fn assert_valid(x: &ProjectivePoint, msg: &[u8], sig: &k256::ecdsa::Signature) {
    let vk =
        VerifyingKey::from_sec1_bytes(x.to_affine().to_encoded_point(false).as_bytes()).unwrap();
    vk.verify(msg, sig).expect("signature must verify under X");
    assert!(
        !bool::from(sig.s().is_high()),
        "s must be normalized low (BIP-62/EIP-2)"
    );
}

#[test]
fn e2e_2_of_3() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 1);
    let keys = sim::run_keygen(&params, b"key/1", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"OHM-ECDSA end-to-end, 2-of-3";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn e2e_3_of_5_with_only_t_signers() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 2);
    let keys = sim::run_keygen(&params, b"key/2", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 7, &mut rngs, None).unwrap();
    // Only parties {2, 4, 5} participate online.
    let subset: Vec<_> = presigs
        .into_iter()
        .filter(|p| p.index != 1 && p.index != 3)
        .collect();
    let msg = b"3-of-5 signed by parties 2,4,5";
    let sig = sim::run_sign(&params, &subset, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn sign_cheater_is_identified() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 3);
    let keys = sim::run_keygen(&params, b"key/3", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    // Party 2 broadcasts a garbage signature share.
    let err =
        sim::run_sign(&params, &presigs, b"m", Some((2, Scalar::from(0xdeadu64)))).unwrap_err();
    match err {
        Error::Abort { abort } => assert_eq!(abort.blamed, vec![2]),
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn presign_cheater_is_identified() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 4);
    let keys = sim::run_keygen(&params, b"key/4", &mut rngs).unwrap();
    // Party 3 broadcasts a wrong nonce point R_3.
    let tamper = PresignTamper {
        bad_nonce_point: Some(3),
        ..Default::default()
    };
    let err = sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => assert_eq!(abort.blamed, vec![3]),
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn hd_tweak_derivation() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 5);
    let keys = sim::run_keygen(&params, b"key/5", &mut rngs).unwrap();
    let mut presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    // BIP32-style additive tweak: x' = x + τ (SPEC §9.4).
    let tau = Scalar::from(777u64);
    for p in presigs.iter_mut() {
        p.apply_tweak(&tau);
    }
    let msg = b"derived child key signature";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    let x_child = pubkey(&keys) + ProjectivePoint::GENERATOR * tau;
    assert_valid(&x_child, msg, &sig);
}

#[test]
fn many_presignatures_sign_distinct_messages() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 6);
    let keys = sim::run_keygen(&params, b"key/6", &mut rngs).unwrap();
    for id in 1..=5u64 {
        let presigs = sim::run_presign(&params, &keys, id, &mut rngs, None).unwrap();
        let msg = format!("message #{id}");
        let sig = sim::run_sign(&params, &presigs, msg.as_bytes(), None).unwrap();
        assert_valid(&pubkey(&keys), msg.as_bytes(), &sig);
    }
}

#[test]
fn keygen_false_accusation_blames_accuser() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 10);
    // The share from dealer 1 to party 3 is corrupted in transit; dealer
    // 1's §6.1 defense verifies, so party 3's complaint is false.
    let tamper = DkgTamper {
        corrupt_share: Some((1, 3)),
        ..Default::default()
    };
    let err =
        sim::run_keygen_with_tamper(&params, b"key/10", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::KeyGen);
            assert_eq!(abort.blamed, vec![3]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn keygen_cheating_dealer_is_blamed() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 11);
    // Dealer 2 deals party 1 a wrong share; its §6.1 defense does not verify.
    let tamper = DkgTamper {
        bad_deal: Some((2, 1)),
        ..Default::default()
    };
    let err =
        sim::run_keygen_with_tamper(&params, b"key/11", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::KeyGen);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn triples_cheating_dealer_is_blamed() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 12);
    // Party 2 re-shares a wrong share to party 3 (T2); blamed in T3.
    let tamper = TripleTamper {
        bad_reshare: Some((2, 3)),
        ..Default::default()
    };
    let err =
        triples::generate_with_tamper(&params, b"triple/12", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn triples_bad_product_proof_is_blamed() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 13);
    // Party 1 broadcasts an invalid DLEQ product proof (F3).
    let tamper = TripleTamper {
        bad_product_proof: Some(1),
        ..Default::default()
    };
    let err =
        triples::generate_with_tamper(&params, b"triple/13", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![1]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn robust_sign_excludes_cheater_and_delivers() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 14);
    let keys = sim::run_keygen(&params, b"key/14", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"robust 2-of-3 with one cheater";
    let (sig, blamed) =
        sim::run_sign_robust(&params, &presigs, msg, &[(2, Scalar::from(0xdeadu64))]).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_sign_tolerates_t_minus_1_cheaters() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 15);
    let keys = sim::run_keygen(&params, b"key/15", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"robust 3-of-5 with two cheaters";
    let tamper = [(1, Scalar::from(0xdeadu64)), (4, Scalar::from(0xbeefu64))];
    let (sig, blamed) = sim::run_sign_robust(&params, &presigs, msg, &tamper).unwrap();
    assert_eq!(blamed, vec![1, 4]);
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_sign_fails_without_t_valid_shares() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 16);
    let keys = sim::run_keygen(&params, b"key/16", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    // Two of three shares are garbage: only one valid share < t = 2.
    let tamper = [(1, Scalar::from(0xdeadu64)), (2, Scalar::from(0xbeefu64))];
    let err = sim::run_sign_robust(&params, &presigs, b"m", &tamper).unwrap_err();
    match err {
        Error::NotEnoughShares { got: 1, need: 2 } => {}
        other => panic!("expected NotEnoughShares, got {other:?}"),
    }
}

#[test]
fn presig_store_enforces_single_use() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 17);
    let keys = sim::run_keygen(&params, b"key/17", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let pk = pubkey(&keys).to_affine();
    let mut stores: Vec<PresigStore> = (0..3).map(|_| PresigStore::new(pk)).collect();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    let msg = b"single-use presignature, 2-of-3";
    let sig = sim::run_sign_stored(&params, &mut stores, 1, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
    // The id is consumed everywhere: a second attempt must fail.
    assert!(stores.iter().all(|s| !s.contains(1) && s.is_empty()));
    let err = sim::run_sign_stored(&params, &mut stores, 1, msg, None).unwrap_err();
    match err {
        Error::PresigStore("unknown or consumed presignature id") => {}
        other => panic!("expected PresigStore, got {other:?}"),
    }
}

#[test]
fn presig_store_rejects_duplicate_insert() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 18);
    let keys = sim::run_keygen(&params, b"key/18", &mut rngs).unwrap();
    // Two independent presign runs under the same id.
    let first = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let second = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let mut store = PresigStore::new(pubkey(&keys).to_affine());
    store.insert(first.into_iter().next().unwrap()).unwrap();
    let err = store
        .insert(second.into_iter().next().unwrap())
        .unwrap_err();
    match err {
        Error::PresigStore("duplicate presignature id") => {}
        other => panic!("expected PresigStore, got {other:?}"),
    }
    assert_eq!(store.len(), 1);
}

#[test]
fn presig_store_unknown_id() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 19);
    let keys = sim::run_keygen(&params, b"key/19", &mut rngs).unwrap();
    let mut store = PresigStore::new(pubkey(&keys).to_affine());
    assert!(store.is_empty());
    let err = store.consume(42).unwrap_err();
    match err {
        Error::PresigStore("unknown or consumed presignature id") => {}
        other => panic!("expected PresigStore, got {other:?}"),
    }
}

#[test]
fn batch_triples_are_multiplicative() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 20);
    let count = 4;
    let batch = triples::generate_batch(&params, b"triple-batch/20", count, &mut rngs).unwrap();
    assert_eq!(batch.len(), 3);
    assert!(batch.iter().all(|party| party.len() == count));
    for b in 0..count {
        let pubc = &batch[0][b].1;
        let open_of = |pick: fn(&TripleShare) -> Scalar, com: &FeldmanCommitment| {
            let shares: BTreeMap<PartyId, Scalar> = batch
                .iter()
                .map(|party| (party[b].0.index, pick(&party[b].0)))
                .collect();
            open(params.t, com, &shares, Phase::Triples).unwrap()
        };
        let a = open_of(|s| s.a, &pubc.ca);
        let b_ = open_of(|s| s.b, &pubc.cb);
        let c = open_of(|s| s.c, &pubc.cc);
        assert_eq!(c, a * b_, "triple {b} must be multiplicative");
    }
}

#[test]
fn batch_presign_sign_distinct_messages() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 21);
    let keys = sim::run_keygen(&params, b"key/21", &mut rngs).unwrap();
    let ids: Vec<u64> = (1..=5).collect();
    let batch = sim::run_presign_batch(&params, &keys, &ids, &mut rngs, None).unwrap();
    assert_eq!(batch.len(), 3);
    assert!(batch.iter().all(|party| party.len() == ids.len()));
    let mut iters: Vec<_> = batch.into_iter().map(Vec::into_iter).collect();
    for (b, &id) in ids.iter().enumerate() {
        let presigs: Vec<_> = iters.iter_mut().map(|it| it.next().unwrap()).collect();
        assert!(presigs.iter().all(|p| p.id == id));
        let msg = format!("batch message #{id} (index {b})");
        let sig = sim::run_sign(&params, &presigs, msg.as_bytes(), None).unwrap();
        assert_valid(&pubkey(&keys), msg.as_bytes(), &sig);
    }
}

#[test]
fn batch_presign_cheater_is_identified() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 22);
    let keys = sim::run_keygen(&params, b"key/22", &mut rngs).unwrap();
    // Party 3 broadcasts a wrong nonce point R_3 (batch item 0).
    let tamper = PresignTamper {
        bad_nonce_point: Some(3),
        ..Default::default()
    };
    let err =
        sim::run_presign_batch(&params, &keys, &[1, 2, 3], &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Presign);
            assert_eq!(abort.blamed, vec![3]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn robust_presign_bad_open_share_completes() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 23);
    let keys = sim::run_keygen(&params, b"key/23", &mut rngs).unwrap();
    // Party 2 broadcasts a wrong opening share in the P2 v opening.
    let tamper = PresignTamper {
        bad_open_share: Some(2),
        ..Default::default()
    };
    let (presigs, blamed) =
        sim::run_presign_robust(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(presigs.len(), 2);
    assert!(presigs.iter().all(|p| p.index != 2));
    let msg = b"robust presign, bad v-opening share";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_presign_bad_nonce_point_completes() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 24);
    let keys = sim::run_keygen(&params, b"key/24", &mut rngs).unwrap();
    // Party 3 broadcasts a wrong nonce point R_3 (P3).
    let tamper = PresignTamper {
        bad_nonce_point: Some(3),
        ..Default::default()
    };
    let (presigs, blamed) =
        sim::run_presign_robust(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![3]);
    assert_eq!(presigs.len(), 2);
    assert!(presigs.iter().all(|p| p.index != 3));
    let msg = b"robust presign, bad nonce point";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_triples_bad_reshare_recovers() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 25);
    // Dealer 2 re-shares a wrong share to party 3 (T2); the honest
    // majority publicly reconstructs g_2 and continues (§10.4).
    let tamper = TripleTamper {
        bad_reshare: Some((2, 3)),
        ..Default::default()
    };
    let (triple, blamed) =
        triples::generate_robust(&params, b"triple/25", &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(triple.len(), 2);
    let pubc = &triple[0].1;
    let open_of = |pick: fn(&TripleShare) -> Scalar, com: &FeldmanCommitment| {
        let shares: BTreeMap<PartyId, Scalar> =
            triple.iter().map(|(s, _)| (s.index, pick(s))).collect();
        open(params.t, com, &shares, Phase::Triples).unwrap()
    };
    let a = open_of(|s| s.a, &pubc.ca);
    let b_ = open_of(|s| s.b, &pubc.cb);
    let c = open_of(|s| s.c, &pubc.cc);
    assert_eq!(c, a * b_);
}

#[test]
fn robust_triples_bad_product_proof_aborts() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 26);
    // F3: the dealer's C_j commits to a wrong product — reconstruction
    // would recover a wrong-but-committed polynomial, so continuation is
    // impossible even on the robust path.
    let tamper = TripleTamper {
        bad_product_proof: Some(1),
        ..Default::default()
    };
    let err =
        triples::generate_robust(&params, b"triple/26", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![1]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn presign_restart_expels_cheater_and_recovers() {
    // 3-of-6: one slack, so one expulsion still leaves n′ = 5 ≥ 2t−1.
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 30);
    let keys = sim::run_keygen(&params, b"key/30", &mut rngs).unwrap();
    // Dealing-phase fault (F2): party 2 re-shares a wrong share in the
    // first triple session — the fail-fast presign aborts.
    let tamper = PresignTamper {
        triple_tamper: Some(TripleTamper {
            bad_reshare: Some((2, 3)),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (presigs, blamed, used_id) =
        sim::run_presign_with_restart(&params, &keys, 41, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(used_id, 42, "the aborted id 41 must be poisoned (§10.3(2))");
    assert_eq!(presigs.len(), 5);
    assert!(presigs.iter().all(|p| p.id == used_id));
    // The survivors keep their ORIGINAL ids — the evaluation points of
    // their long-term key shares.
    let ids: Vec<PartyId> = presigs.iter().map(|p| p.index).collect();
    assert_eq!(ids, vec![1, 3, 4, 5, 6]);
    let msg = b"expel-and-restart presign, 3-of-6";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn presign_restart_refused_without_slack() {
    // 2-of-3 (n = 2t−1, zero slack): the same dealing-phase abort leaves
    // n′ = 2 < 2t−1, so the restart is refused and the original abort is
    // propagated — t is never silently lowered (§13.4 territory).
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 31);
    let keys = sim::run_keygen(&params, b"key/31", &mut rngs).unwrap();
    let tamper = PresignTamper {
        triple_tamper: Some(TripleTamper {
            bad_reshare: Some((2, 3)),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err =
        sim::run_presign_with_restart(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            // The F2 fault fires inside the presign instance's triple
            // session, so the abort carries the Triples phase.
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected the original identifiable abort, got {other:?}"),
    }
}

#[test]
fn keygen_restart_expels_cheater_and_recovers() {
    // 3-of-6 with a cheating dealer: the first attempt aborts blaming 2,
    // the restart completes over the 5 survivors (renumbered 1..=5 — a
    // fresh keygen has no long-term shares to preserve).
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 32);
    let tamper = DkgTamper {
        bad_deal: Some((2, 1)),
        ..Default::default()
    };
    let (keys, blamed) =
        sim::run_keygen_with_restart(&params, b"key/32", &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(keys.len(), 5);
    assert!(keys.iter().enumerate().all(|(k, key)| key.index == k + 1));
    // The resulting key signs end-to-end at n′ = 5, t = 3.
    let params5 = Params::new(5, 3).unwrap();
    let presigs = sim::run_presign(&params5, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"expel-and-restart keygen, 3-of-6";
    let sig = sim::run_sign(&params5, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn triples_restart_expels_cheater_and_recovers() {
    // 3-of-6 with an F3 fault (bad DLEQ product proof) — not continuable
    // even on the §10.4 robust path, so the §10.3 restart handles it.
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 33);
    let tamper = TripleTamper {
        bad_product_proof: Some(4),
        ..Default::default()
    };
    let (triple, blamed) =
        sim::run_triples_with_restart(&params, b"triple/33", &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![4]);
    assert_eq!(triple.len(), 5);
    // The restarted triple (over the renumbered 1..=5) is multiplicative.
    let params5 = Params::new(5, 3).unwrap();
    let pubc = &triple[0].1;
    let open_of = |pick: fn(&TripleShare) -> Scalar, com: &FeldmanCommitment| {
        let shares: BTreeMap<PartyId, Scalar> =
            triple.iter().map(|(s, _)| (s.index, pick(s))).collect();
        open(params5.t, com, &shares, Phase::Triples).unwrap()
    };
    let a = open_of(|s| s.a, &pubc.ca);
    let b_ = open_of(|s| s.b, &pubc.cb);
    let c = open_of(|s| s.c, &pubc.cc);
    assert_eq!(c, a * b_);
}

#[test]
fn keygen_via_transport_driver_signs_end_to_end() {
    // Keygen driven explicitly through the transport seam (§13.2): the
    // accepted sets come from SimTransport, not from sim's hand delivery.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 77);
    let mut transport = SimTransport::new();
    let keys = transport::drive_dkg(
        &params,
        b"key/transport",
        b"e2e/dkg-commit",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    )
    .unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"keygen through the transport seam, 2-of-3";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}
