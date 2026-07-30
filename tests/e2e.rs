//! End-to-end integration tests for OHM-ECDSA (SPEC §6–§10).

use k256::ecdsa::{signature::Verifier, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use std::collections::BTreeMap;

use ohm_ecdsa::dkg::DkgTamper;
use ohm_ecdsa::open::open;
use ohm_ecdsa::presign::{self, KeyShare, PresignTamper};
use ohm_ecdsa::refresh::ReshareTamper;
use ohm_ecdsa::shamir::{interpolate_at, slot_point};
use ohm_ecdsa::sign::KiSignTamper;
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::{self, SimTransport};
use ohm_ecdsa::triples::{self, TripleShare, TripleTamper};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{Committee, Error, KiPool, Params, PartyId, Phase, PresigStore};

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
fn batch_triples_one_bad_proof_blames_prover() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 60);
    // Party 2 broadcasts one invalid DLEQ product proof out of 5 (F3): the
    // aggregate fast path fails and the per-proof fallback attributes the
    // blame to that exact prover (per-triple blame, SPEC §7.3).
    let tamper = TripleTamper {
        bad_product_proof_at: Some((2, 3)),
        ..Default::default()
    };
    let err = triples::generate_batch_with_tamper(
        &params,
        b"triple-batch/60",
        5,
        &mut rngs,
        Some(&tamper),
    )
    .unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![2]);
            assert!(abort.detail.contains("batch index 3"));
        }
        other => panic!("expected identifiable abort, got {other:?}"),
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
fn packed_triples_are_multiplicative() {
    // t=2, B=2, n=5 — FY-minimal committee: n ≥ 2t+2B−3 = 5 (SPEC §7.4.1).
    let params = Params::new(5, 2).unwrap();
    let mut rngs = sim::make_rngs(5, 70);
    let b_pack = 2;
    let packed =
        triples::generate_packed(&params, b"packed-triples/70", b_pack, &mut rngs, None).unwrap();
    assert_eq!(packed.len(), 5);
    assert!(packed.iter().all(|party| party.len() == b_pack));
    // Degree d = t+B−2 = 2: commitment vectors carry d+1 points.
    assert_eq!(packed[0][0].1.ca.points.len(), params.t + b_pack - 1);
    let ids = params.parties();
    for b in 0..b_pack {
        // Open each slot's values by interpolation at the slot point e_b
        // over all n party points (the packed convention: the TripleShare
        // scalars are the packed polynomials' evaluations at the party
        // points; slot values exist only under interpolation).
        let open_slot = |pick: fn(&TripleShare) -> Scalar, com: &FeldmanCommitment| {
            let shares: Vec<Scalar> = packed.iter().map(|party| pick(&party[b].0)).collect();
            for (k, &j) in ids.iter().enumerate() {
                assert!(com.verify_share(j, &shares[k]), "share must verify");
            }
            interpolate_at(&slot_point(b), &ids, &shares)
        };
        let pubc = &packed[0][b].1;
        let alpha = open_slot(|s| s.a, &pubc.ca);
        let beta = open_slot(|s| s.b, &pubc.cb);
        let gamma = open_slot(|s| s.c, &pubc.cc);
        assert_eq!(gamma, alpha * beta, "slot {b} must be multiplicative");
    }
    // The packed convention: a/b shares are one scalar per party for all
    // slots (the packed polynomials' evaluations at the party point).
    for party in &packed {
        assert_eq!(party[0].0.a, party[1].0.a);
        assert_eq!(party[0].0.b, party[1].0.b);
    }
}

#[test]
fn packed_mode_b1_matches_base() {
    // B = 1 degenerates to base mode: the constraint is n ≥ 2t−1, the
    // degree is t−1, and slot 0 is point 0 (SPEC §7.4.1) — a base 2-of-3
    // committee runs packed triples unchanged.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 71);
    let packed =
        triples::generate_packed(&params, b"packed-triples/71", 1, &mut rngs, None).unwrap();
    assert_eq!(packed[0].len(), 1);
    assert_eq!(packed[0][0].1.ca.points.len(), params.t); // degree t−1
    let ids = params.parties();
    let open_slot0 = |pick: fn(&TripleShare) -> Scalar| {
        let shares: Vec<Scalar> = packed.iter().map(|party| pick(&party[0].0)).collect();
        interpolate_at(&slot_point(0), &ids, &shares)
    };
    let alpha = open_slot0(|s| s.a);
    let beta = open_slot0(|s| s.b);
    let gamma = open_slot0(|s| s.c);
    assert_eq!(gamma, alpha * beta);
}

#[test]
fn packed_presign_and_sign() {
    // t=2, B=2, n=5: packed presignatures sign distinct messages; the
    // online quorum is d+1 = t+B−1 = 3 (SPEC §7.4.3).
    let params = Params::new(5, 2).unwrap();
    let mut rngs = sim::make_rngs(5, 72);
    let keys = sim::run_keygen(&params, b"key/72", &mut rngs).unwrap();
    let presigs = sim::run_presign_packed(&params, &keys, &[1, 2], &mut rngs, None).unwrap();
    assert_eq!(presigs.len(), 5);
    assert!(presigs.iter().all(|party| party.len() == 2));
    let (slot0, slot1): (Vec<_>, Vec<_>) = presigs
        .into_iter()
        .map(|mut party| (party.remove(0), party.remove(0)))
        .unzip();
    assert!(slot0.iter().all(|p| p.id == 1));
    assert!(slot1.iter().all(|p| p.id == 2));

    // Slot 0 signs with exactly the quorum d+1 = 3 parties.
    let msg0 = b"packed presignature, slot 0";
    let sig0 = sim::run_sign_packed(&params, 2, 0, &slot0[..3], msg0, None).unwrap();
    assert_valid(&pubkey(&keys), msg0, &sig0);

    // Slot 1 signs a different message with a different quorum subset
    // (parties 2, 3, 4).
    let msg1 = b"packed presignature, slot 1";
    let sig1 = sim::run_sign_packed(&params, 2, 1, &slot1[1..4], msg1, None).unwrap();
    assert_valid(&pubkey(&keys), msg1, &sig1);

    // The §7.4.3 trade-off: signing with only t = 2 shares FAILS — the
    // degree-d sharing needs d+1 = 3 points.
    let err = sim::run_sign_packed(&params, 2, 0, &slot0[..2], msg0, None).unwrap_err();
    match err {
        Error::NotEnoughShares { got: 2, need: 3 } => {}
        other => panic!("expected NotEnoughShares, got {other:?}"),
    }
}

#[test]
fn packed_triples_cheater_is_blamed() {
    let params = Params::new(5, 2).unwrap();
    // Bad re-shared share in PT2 (F2): the §6.1 defense does not verify,
    // so the dealing party is blamed.
    let mut rngs = sim::make_rngs(5, 73);
    let tamper = TripleTamper {
        bad_reshare: Some((2, 4)),
        ..Default::default()
    };
    let err = triples::generate_packed(&params, b"packed-triples/73", 2, &mut rngs, Some(&tamper))
        .unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
    // Bad DLEQ product proof in PT2 (F3): the prover is blamed.
    let mut rngs = sim::make_rngs(5, 74);
    let tamper = TripleTamper {
        bad_product_proof: Some(3),
        ..Default::default()
    };
    let err = triples::generate_packed(&params, b"packed-triples/74", 2, &mut rngs, Some(&tamper))
        .unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Triples);
            assert_eq!(abort.blamed, vec![3]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn packed_mode_rejects_undersized_committee() {
    // 2-of-3 admits only B = 1: B = 2 needs n ≥ 2t+2B−3 = 5 (SPEC §7.4.1).
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 75);
    match triples::generate_packed(&params, b"packed-triples/75", 2, &mut rngs, None) {
        Err(Error::InvalidParams(_)) => {}
        other => panic!("expected InvalidParams, got {other:?}"),
    }
    let keys = sim::run_keygen(&params, b"key/75", &mut rngs).unwrap();
    match sim::run_presign_packed(&params, &keys, &[1, 2], &mut rngs, None) {
        Err(Error::InvalidParams(_)) => {}
        other => panic!("expected InvalidParams, got {other:?}"),
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
fn presign_restart_robust_handles_opening_fault_in_attempt() {
    // 3-of-6: party 2 broadcasts a wrong P2 v-opening share — a fault the
    // §10.4 robust path continues from, so the composed wrapper completes
    // on the FIRST attempt: no restart, the id is NOT poisoned.
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 34);
    let keys = sim::run_keygen(&params, b"key/34", &mut rngs).unwrap();
    let tamper = PresignTamper {
        bad_open_share: Some(2),
        ..Default::default()
    };
    let (presigs, blamed, used_id) =
        sim::run_presign_with_restart(&params, &keys, 41, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(used_id, 41, "a completed attempt must not poison the id");
    assert_eq!(presigs.len(), 5);
    assert!(presigs.iter().all(|p| p.id == used_id));
    let ids: Vec<PartyId> = presigs.iter().map(|p| p.index).collect();
    assert_eq!(ids, vec![1, 3, 4, 5, 6]);
    let msg = b"restart wrapper, in-attempt robust presign";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn presign_restart_still_restarts_on_dealing_fault() {
    // 3-of-6: one slack, so one expulsion still leaves n′ = 5 ≥ 2t−1.
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 30);
    let keys = sim::run_keygen(&params, b"key/30", &mut rngs).unwrap();
    // Dealing-phase fault (F2): party 2 re-shares a wrong share in the
    // first triple session — the dealing phase stays fail-fast even on
    // the robust path, so the attempt aborts and §10.3 restarts it.
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
fn triples_restart_robust_recovers_reshare_fault_in_attempt() {
    // 3-of-6: dealer 2 re-shares a wrong share to party 3 (T2) — the
    // §10.4 robust path publicly reconstructs g_2 and completes the
    // FIRST attempt: no restart (the survivors keep their original ids;
    // a restart would renumber to 1..=5).
    let params = Params::new(6, 3).unwrap();
    let mut rngs = sim::make_rngs(6, 35);
    let tamper = TripleTamper {
        bad_reshare: Some((2, 3)),
        ..Default::default()
    };
    let (triple, blamed) =
        sim::run_triples_with_restart(&params, b"triple/35", &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(triple.len(), 5);
    let ids: Vec<PartyId> = triple.iter().map(|(s, _)| s.index).collect();
    assert_eq!(
        ids,
        vec![1, 3, 4, 5, 6],
        "in-attempt completion, no renumbering"
    );
    // The reconstructed triple is multiplicative.
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
fn triples_restart_restarts_on_bad_product_proof() {
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

// --- §13.4 committee maintenance -------------------------------------------

#[test]
fn refresh_preserves_key_and_enables_signing() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 80);
    let keys = sim::run_keygen(&params, b"key/80", &mut rngs).unwrap();
    let x = pubkey(&keys);
    let refreshed = sim::run_refresh(&params, &keys, b"refresh/80", &mut rngs, None).unwrap();
    // The public key is unchanged (checked against the ORIGINAL keyshare
    // commitment), but every share is new.
    assert_eq!(pubkey(&refreshed), x);
    for (old, new) in keys.iter().zip(&refreshed) {
        assert_eq!(old.index, new.index);
        assert_ne!(old.share, new.share);
    }
    // The refreshed shares presign and sign end-to-end.
    let presigs = sim::run_presign(&params, &refreshed, 1, &mut rngs, None).unwrap();
    let msg = b"post-refresh signature, 2-of-3";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&x, msg, &sig);
}

#[test]
fn refresh_invalidates_presignatures() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 81);
    let keys = sim::run_keygen(&params, b"key/81", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let pk = pubkey(&keys).to_affine();
    let mut stores: Vec<PresigStore> = (0..3).map(|_| PresigStore::new(pk)).collect();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    // Refresh, then apply the §13.4 invalidation (stores are caller-owned).
    let refreshed = sim::run_refresh(&params, &keys, b"refresh/81", &mut rngs, None).unwrap();
    for store in stores.iter_mut() {
        store.clear();
    }
    assert!(stores.iter().all(|s| s.is_empty()));
    // The pre-refresh presignature id is gone from every store.
    let err = sim::run_sign_stored(&params, &mut stores, 1, b"m", None).unwrap_err();
    match err {
        Error::PresigStore("unknown or consumed presignature id") => {}
        other => panic!("expected PresigStore, got {other:?}"),
    }
    // Fresh presignatures under the refreshed shares sign as usual.
    let presigs = sim::run_presign(&params, &refreshed, 2, &mut rngs, None).unwrap();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    let msg = b"post-refresh stored signature";
    let sig = sim::run_sign_stored(&params, &mut stores, 2, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn refresh_cheating_dealer_is_blamed() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 82);
    let keys = sim::run_keygen(&params, b"key/82", &mut rngs).unwrap();
    // Dealer 3 deals a wrong zero-constant share to party 1 (§6.1 F2): its
    // defense fails verification, so the dealer is blamed.
    let tamper = DkgTamper {
        bad_deal: Some((3, 1)),
        ..Default::default()
    };
    let err =
        sim::run_refresh(&params, &keys, b"refresh/82", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Refresh);
            assert_eq!(abort.blamed, vec![3]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

#[test]
fn reshare_to_new_committee_signs() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 83);
    let keys = sim::run_keygen(&params, b"key/83", &mut rngs).unwrap();
    let x = pubkey(&keys);
    let old = Committee::full(&params);
    // Re-share to a NEW 2-of-3 committee with fresh ids {6,7,8}.
    let new_params = Params::new(3, 2).unwrap();
    let new = Committee::new(vec![6, 7, 8], new_params.t).unwrap();
    let new_keys = sim::run_reshare(&keys, &old, &new, b"reshare/83", &mut rngs, None).unwrap();
    assert_eq!(new_keys.len(), 3);
    assert!(new_keys.iter().map(|k| k.index).eq([6, 7, 8]));
    // The public key is unchanged.
    assert_eq!(pubkey(&new_keys), x);
    // The new committee presigns and signs end-to-end (non-`1..=n` ids, so
    // presign runs over the explicit committee).
    let mut new_rngs = sim::make_rngs(3, 84);
    let presigs = presign::presign_with_committee(&new, &new_keys, 1, &mut new_rngs, None).unwrap();
    let msg = b"post-reshare signature, new 2-of-3";
    let sig = sim::run_sign(&new_params, &presigs, msg, None).unwrap();
    assert_valid(&x, msg, &sig);
}

#[test]
fn reshare_to_overlapping_committee_signs() {
    // New committee ids overlap the old ones — fine, the re-sharing
    // polynomials are fresh.
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 85);
    let keys = sim::run_keygen(&params, b"key/85", &mut rngs).unwrap();
    let x = pubkey(&keys);
    let old = Committee::full(&params);
    let new = Committee::new(vec![2, 4, 5, 6, 7], 3).unwrap();
    let new_keys = sim::run_reshare(&keys, &old, &new, b"reshare/85", &mut rngs, None).unwrap();
    assert_eq!(pubkey(&new_keys), x);
    let mut new_rngs = sim::make_rngs(5, 86);
    let presigs = presign::presign_with_committee(&new, &new_keys, 1, &mut new_rngs, None).unwrap();
    let msg = b"post-reshare signature, overlapping committees";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&x, msg, &sig);
}

#[test]
fn reshare_cheating_dealer_is_blamed() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 87);
    let keys = sim::run_keygen(&params, b"key/87", &mut rngs).unwrap();
    let old = Committee::full(&params);
    let new = Committee::new(vec![6, 7, 8, 9, 10], 3).unwrap();

    // Bad sub-share: dealer 2 deals a wrong value to new member 8 — its
    // §6.1 defense fails too, so the dealer is blamed.
    let tamper = ReshareTamper {
        bad_deal: Some((2, 8)),
        ..Default::default()
    };
    let mut rngs_a = rngs.clone();
    let err =
        sim::run_reshare(&keys, &old, &new, b"reshare/87", &mut rngs_a, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Refresh);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }

    // Bad commitment: dealer 4's C_4 does not bind to its true old share
    // (C_4.points[0] != EvalCom(A[x], 4)) — identifiable on public data.
    let tamper = ReshareTamper {
        bad_commitment: Some(4),
        ..Default::default()
    };
    let err =
        sim::run_reshare(&keys, &old, &new, b"reshare/88", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Refresh);
            assert_eq!(abort.blamed, vec![4]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

// --- Key-independent presignatures (SPEC §8.7) ------------------------------

#[test]
fn ki_pool_signs_for_two_different_keys() {
    // THE headline property: ONE key-free pool serves ANY key.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 90);
    let keys_a = sim::run_keygen(&params, b"key/90a", &mut rngs).unwrap();
    let keys_b = sim::run_keygen(&params, b"key/90b", &mut rngs).unwrap();
    assert_ne!(pubkey(&keys_a), pubkey(&keys_b));

    // Two pool records per party, generated with NO key material.
    let ki1 = presign::presign_ki(&params, 1, &mut rngs, None).unwrap();
    let ki2 = presign::presign_ki(&params, 2, &mut rngs, None).unwrap();

    // Record 1 binds to key A online (2-round signing), verifies under X_A.
    let msg_a = b"KI pool record under key A";
    let sig_a = sim::run_sign_ki(&params, &keys_a, &ki1, msg_a, &mut rngs, None).unwrap();
    assert_valid(&pubkey(&keys_a), msg_a, &sig_a);

    // Record 2 of the SAME pool binds to the independent key B.
    let msg_b = b"same KI pool, under key B";
    let sig_b = sim::run_sign_ki(&params, &keys_b, &ki2, msg_b, &mut rngs, None).unwrap();
    assert_valid(&pubkey(&keys_b), msg_b, &sig_b);
}

#[test]
fn ki_sign_single_use_enforced() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 91);
    let keys = sim::run_keygen(&params, b"key/91", &mut rngs).unwrap();
    let ki = presign::presign_ki(&params, 1, &mut rngs, None).unwrap();

    // Per-party key-free pools; duplicate-id insert is rejected (§8.6(1)).
    let mut pools: Vec<KiPool> = ki
        .into_iter()
        .map(|rec| {
            let mut pool = KiPool::new();
            pool.insert(rec).unwrap();
            pool
        })
        .collect();
    let dup = presign::presign_ki(&params, 1, &mut rngs, None).unwrap();
    assert!(matches!(
        pools[0].insert(dup.into_iter().next().unwrap()),
        Err(Error::PresigStore(_))
    ));

    // First sign consumes id 1 in every pool and verifies under X.
    let msg = b"KI single-use signature";
    let sig = sim::run_sign_ki_pooled(&params, &keys, &mut pools, 1, msg, &mut rngs, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);

    // The same id can never be consumed again (nonce-reuse guard).
    assert!(pools.iter().all(|p| !p.contains(1)));
    let err =
        sim::run_sign_ki_pooled(&params, &keys, &mut pools, 1, msg, &mut rngs, None).unwrap_err();
    assert!(matches!(err, Error::PresigStore(_)));
}

#[test]
fn ki_sign_cheater_is_identified() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 92);
    let keys = sim::run_keygen(&params, b"key/92", &mut rngs).unwrap();

    // R1: party 2 broadcasts a wrong opening share (δ = ⟦u⟧−⟦α⟧).
    let ki = presign::presign_ki(&params, 1, &mut rngs, None).unwrap();
    let tamper = KiSignTamper {
        bad_open_share: Some(2),
        ..Default::default()
    };
    let mut rngs_a = rngs.clone();
    let err = sim::run_sign_ki(&params, &keys, &ki, b"m", &mut rngs_a, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Sign);
            assert_eq!(abort.blamed, vec![2]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }

    // R2: party 3 broadcasts a garbage signature share.
    let ki = presign::presign_ki(&params, 2, &mut rngs, None).unwrap();
    let tamper = KiSignTamper {
        bad_sign_share: Some((3, Scalar::from(0xdeadu64))),
        ..Default::default()
    };
    let err = sim::run_sign_ki(&params, &keys, &ki, b"m", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::Sign);
            assert_eq!(abort.blamed, vec![3]);
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}
