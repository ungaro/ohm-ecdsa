//! Consolidated fault-injection / blame-matrix suite (SPEC §10).
//!
//! This file is the systematic index for the headline identifiable-abort
//! claim (SPEC §11.2 C3: every abort names an actual cheater — and ONLY a
//! cheater). For every fault class of the §10.1 taxonomy there is an entry
//! below: the injecting tamper hook, and the test in this file that covers
//! it (or the node-crate test file, where the class is wire-level only).
//! Duplication with `tests/e2e.rs` is intentional: e2e tells the protocol
//! story, this file is the blame matrix.
//!
//! | Class | SPEC §10.1 fault (phase) | Injection hook | Covered by |
//! |-------|--------------------------|----------------|------------|
//! | F1 | reveal hash ≠ committed hash (KeyGen/Triples/Presign P1) | `DkgTamper::bad_reveal` (dealer's R2 reveal is well-formed but does not hash to its R1 commit) | `f1_reveal_hash_mismatch_blames_dealer` |
//! | F2 | dealt share fails `v_j·G == EvalCom(A, j)`, §6.1 complaint (dealing) | `DkgTamper::bad_deal` (dealer's defense invalid ⇒ dealer blamed) | `f2_keygen_bad_deal_blames_dealer`, `f2_refresh_bad_deal_blames_dealer`, `f2_reshare_bad_deal_blames_dealer` |
//! | F2 | §6.1 false accusation (defense verifies ⇒ accuser blamed) | `DkgTamper::corrupt_share` | `f2_keygen_false_accusation_blames_accuser` |
//! | F2 | wrong re-shared share (Triples T2/T3) | `TripleTamper::bad_reshare` | `f2_triples_bad_reshare_blames_dealer`, `f2_presign_triple_session_fault_blames_dealer` |
//! | F2 | re-sharing commitment not bound to the old share (§13.4 reshare) | `ReshareTamper::bad_commitment` | `f2_reshare_bad_commitment_blames_dealer` |
//! | F3 | invalid DLEQ product proof (Triples T2) | `TripleTamper::bad_product_proof` / `bad_product_proof_at` (batch) | `f3_triples_bad_product_proof_blames_prover`, `f3_batch_triples_bad_proof_blames_prover` |
//! | F4 | opening share fails commitment check (Presign P2/P4) | `PresignTamper::bad_open_share` | `f4_presign_bad_open_share_blames_sender` |
//! | F5 | `R_j ≠ EvalCom(A[k], j)` (Presign P3) | `PresignTamper::bad_nonce_point` | `f5_presign_bad_nonce_point_blames_sender` |
//! | F6 | `s_j·G ≠ EvalCom(m·A[u]+r·A[z], j)` (Sign S2) | `run_sign` / `run_sign_robust` tamper `(party, fake_share)` | `f6_sign_bad_share_blames_sender`, `robust_f6_sign_completes_and_blames`, `robust_f6_sign_tolerates_t_minus_1_cheaters` |
//! | F7 | final `(r,s)` fails ECDSA verification (Sign S3) | **no reachable injection point** — unreachable by construction: every share is point-verified against `m·A[u]+r·A[z]` before interpolation (`sign.rs::combine_verified`), so a combine that passed S2 cannot yield a failing signature; neither the core nor the node crate has a final-verify-then-blame path. Indirectly witnessed by every `assert_valid` in this file. | — |
//! | F8 | broadcast equivocation — two conflicting sender-signed values in one slot (§4.7 rule (3)) | **wire-level only** — needs two conflicting *signed envelopes*, which the core's `SimTransport` cannot express (it models §4.7 by delivering identical accepted sets) | `node/tests/echo_consistency.rs`: `equivocating_sender_never_splits_honest_acceptance`, `echo_of_unsigned_value_is_dropped_and_honest_keygen_completes` |
//!
//! §10.4 robustness (blame-and-continue, guaranteed output delivery) is
//! covered by the `robust_*` tests: the protocol COMPLETES and still names
//! the cheater. The dealing-phase classes (F1–F3) are not continuable
//! (SPEC §11.2 C6) — `robust_f3_bad_product_proof_still_aborts` pins that.
//!
//! Framing-freeness (C3 second clause): every test asserts the EXACT blame
//! set; `honest_robust_drivers_blame_nobody` is the positive control that
//! an honest run through the blame-reporting drivers reports no blame.

use std::collections::BTreeMap;

use k256::ecdsa::{signature::Verifier, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use ohm_ecdsa::dkg::DkgTamper;
use ohm_ecdsa::open::open;
use ohm_ecdsa::presign::{KeyShare, PresignTamper};
use ohm_ecdsa::refresh::ReshareTamper;
use ohm_ecdsa::sim;
use ohm_ecdsa::triples::{self, TripleShare, TripleTamper};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{Committee, Error, Params, PartyId, Phase};

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

/// The one assertion of this suite: an abort naming EXACTLY `blamed` in
/// `phase` — the cheater, and only the cheater (framing-freeness, C3).
fn assert_abort(err: Error, phase: Phase, blamed: &[PartyId]) {
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, phase, "wrong abort phase");
            assert_eq!(abort.blamed, blamed, "blame must name exactly the cheater");
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

// --- F1: commit-reveal hash mismatch (dealing phases) --------------------

#[test]
fn f1_reveal_hash_mismatch_blames_dealer() {
    // Dealer 2 reveals a well-formed commitment vector that does NOT hash
    // to its R1 commit (`DkgTamper::bad_reveal` perturbs the reveal, not
    // the commit). The commit-reveal consistency check runs before any
    // share check, so the abort blames dealer 2, and only dealer 2.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 101);
    let tamper = DkgTamper {
        bad_reveal: Some(2),
        ..Default::default()
    };
    let err =
        sim::run_keygen_with_tamper(&params, b"blame/101", &mut rngs, Some(&tamper)).unwrap_err();
    match err {
        Error::Abort { abort } => {
            assert_eq!(abort.phase, Phase::KeyGen);
            assert_eq!(abort.blamed, vec![2]);
            assert_eq!(abort.detail, "commit-reveal hash mismatch");
        }
        other => panic!("expected identifiable abort, got {other:?}"),
    }
}

// --- F2: §6.1 complaint subprotocol (bad deal / false accusation) ---------

#[test]
fn f2_keygen_bad_deal_blames_dealer() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 102);
    // Dealer 2 computes a wrong share for party 1; its §6.1 defense share
    // fails verification, so the DEALER is blamed.
    let tamper = DkgTamper {
        bad_deal: Some((2, 1)),
        ..Default::default()
    };
    let err =
        sim::run_keygen_with_tamper(&params, b"blame/102", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::KeyGen, &[2]);
}

#[test]
fn f2_keygen_false_accusation_blames_accuser() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 103);
    // Dealer 1's share to party 3 is corrupted in transit; the dealer's
    // defense verifies, so party 3's complaint is FALSE — the accuser is
    // blamed (§6.1 step 2, second branch).
    let tamper = DkgTamper {
        corrupt_share: Some((1, 3)),
        ..Default::default()
    };
    let err =
        sim::run_keygen_with_tamper(&params, b"blame/103", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::KeyGen, &[3]);
}

#[test]
fn f2_triples_bad_reshare_blames_dealer() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 104);
    // Party 2 re-shares a wrong share to party 3 (T2); caught in T3 via the
    // wire-equivalent §6.1 complaint resolution — the dealer is blamed.
    let tamper = TripleTamper {
        bad_reshare: Some((2, 3)),
        ..Default::default()
    };
    let err =
        triples::generate_with_tamper(&params, b"blame/104", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Triples, &[2]);
}

#[test]
fn f2_presign_triple_session_fault_blames_dealer() {
    // F2 inside the presign instance (SPEC §10.1: F1–F2 span
    // "KeyGen/Triples/Presign P1"): `PresignTamper::triple_tamper` forwards
    // to the FIRST triple session of the instance. The failure surfaces
    // with `Phase::Triples` because it is the triple sub-session that
    // detects it.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 105);
    let keys = sim::run_keygen(&params, b"blame/105", &mut rngs).unwrap();
    let tamper = PresignTamper {
        triple_tamper: Some(TripleTamper {
            bad_reshare: Some((1, 2)),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Triples, &[1]);
}

#[test]
fn f2_refresh_bad_deal_blames_dealer() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 106);
    let keys = sim::run_keygen(&params, b"blame/106", &mut rngs).unwrap();
    // §13.4 refresh: dealer 3 deals a wrong zero-constant share to party 1;
    // its defense fails verification too — the dealer is blamed.
    let tamper = DkgTamper {
        bad_deal: Some((3, 1)),
        ..Default::default()
    };
    let err =
        sim::run_refresh(&params, &keys, b"blame/106r", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Refresh, &[3]);
}

#[test]
fn f2_reshare_bad_deal_blames_dealer() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 107);
    let keys = sim::run_keygen(&params, b"blame/107", &mut rngs).unwrap();
    let old = Committee::full(&params);
    let new = Committee::new(vec![6, 7, 8], 2).unwrap();
    // §13.4 re-sharing: dealer 2 deals a wrong sub-share to new member 8;
    // the §6.1 defense fails as well — the dealer is blamed.
    let tamper = ReshareTamper {
        bad_deal: Some((2, 8)),
        ..Default::default()
    };
    let err =
        sim::run_reshare(&keys, &old, &new, b"blame/107r", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Refresh, &[2]);
}

#[test]
fn f2_reshare_bad_commitment_blames_dealer() {
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 108);
    let keys = sim::run_keygen(&params, b"blame/108", &mut rngs).unwrap();
    let old = Committee::full(&params);
    let new = Committee::new(vec![6, 7, 8], 2).unwrap();
    // Dealer 4's re-sharing commitment does not bind to its true old share
    // (`C_4.points[0] != EvalCom(A[x], 4)`) — identifiable on public data,
    // no complaint round needed.
    let tamper = ReshareTamper {
        bad_commitment: Some(4),
        ..Default::default()
    };
    let err =
        sim::run_reshare(&keys, &old, &new, b"blame/108r", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Refresh, &[4]);
}

// --- F3: invalid DLEQ product proof (Triples T2) --------------------------

#[test]
fn f3_triples_bad_product_proof_blames_prover() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 109);
    let tamper = TripleTamper {
        bad_product_proof: Some(1),
        ..Default::default()
    };
    let err =
        triples::generate_with_tamper(&params, b"blame/109", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Triples, &[1]);
}

#[test]
fn f3_batch_triples_bad_proof_blames_prover() {
    // §7.3 batch: one invalid proof among B ≥ 3 — the aggregate fast path
    // fails and the per-proof fallback attributes the blame to the exact
    // prover, with per-triple attribution in the detail.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 110);
    let tamper = TripleTamper {
        bad_product_proof_at: Some((2, 3)),
        ..Default::default()
    };
    let err =
        triples::generate_batch_with_tamper(&params, b"blame/110", 5, &mut rngs, Some(&tamper))
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

// --- F4: bad opening share (Presign P2/P4) --------------------------------

#[test]
fn f4_presign_bad_open_share_blames_sender() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 111);
    let keys = sim::run_keygen(&params, b"blame/111", &mut rngs).unwrap();
    // Party 2 broadcasts a wrong share in the P2 `v` opening.
    let tamper = PresignTamper {
        bad_open_share: Some(2),
        ..Default::default()
    };
    let err = sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Presign, &[2]);
}

// --- F5: bad nonce point (Presign P3) -------------------------------------

#[test]
fn f5_presign_bad_nonce_point_blames_sender() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 112);
    let keys = sim::run_keygen(&params, b"blame/112", &mut rngs).unwrap();
    // Party 3 broadcasts a wrong nonce point R_3.
    let tamper = PresignTamper {
        bad_nonce_point: Some(3),
        ..Default::default()
    };
    let err = sim::run_presign(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Presign, &[3]);
}

// --- F6: bad signature share (Sign S2) -------------------------------------

#[test]
fn f6_sign_bad_share_blames_sender() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 113);
    let keys = sim::run_keygen(&params, b"blame/113", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    // Party 2 broadcasts a garbage signature share.
    let err =
        sim::run_sign(&params, &presigs, b"m", Some((2, Scalar::from(0xdeadu64)))).unwrap_err();
    assert_abort(err, Phase::Sign, &[2]);
}

// --- §10.4 robustness: blame-and-CONTINUE (guaranteed output delivery) ----

#[test]
fn robust_f6_sign_completes_and_blames() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 114);
    let keys = sim::run_keygen(&params, b"blame/114", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"robust F6: bad share filtered, signature delivered";
    let (sig, blamed) =
        sim::run_sign_robust(&params, &presigs, msg, &[(2, Scalar::from(0xdeadu64))]).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_f6_sign_tolerates_t_minus_1_cheaters() {
    // The full adversarial budget: t−1 cheaters blamed, signature delivered.
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 115);
    let keys = sim::run_keygen(&params, b"blame/115", &mut rngs).unwrap();
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let msg = b"robust F6: t-1 cheaters, signature delivered";
    let tamper = [(1, Scalar::from(0xdeadu64)), (4, Scalar::from(0xbeefu64))];
    let (sig, blamed) = sim::run_sign_robust(&params, &presigs, msg, &tamper).unwrap();
    assert_eq!(blamed, vec![1, 4]);
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_f4_presign_completes_and_blames() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 116);
    let keys = sim::run_keygen(&params, b"blame/116", &mut rngs).unwrap();
    // Party 2's wrong `v`-opening share is filtered; the opening
    // interpolates over the remaining valid shares and the instance
    // completes WITHOUT party 2 (§10.4).
    let tamper = PresignTamper {
        bad_open_share: Some(2),
        ..Default::default()
    };
    let (presigs, blamed) =
        sim::run_presign_robust(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(presigs.len(), 2);
    assert!(presigs.iter().all(|p| p.index != 2));
    let msg = b"robust F4: presign completed over the honest majority";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_f5_presign_completes_and_blames() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 117);
    let keys = sim::run_keygen(&params, b"blame/117", &mut rngs).unwrap();
    // Party 3's wrong nonce point is filtered; R interpolates over the
    // valid points and the instance completes without party 3.
    let tamper = PresignTamper {
        bad_nonce_point: Some(3),
        ..Default::default()
    };
    let (presigs, blamed) =
        sim::run_presign_robust(&params, &keys, 1, &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![3]);
    assert_eq!(presigs.len(), 2);
    assert!(presigs.iter().all(|p| p.index != 3));
    let msg = b"robust F5: presign completed over the honest majority";
    let sig = sim::run_sign(&params, &presigs, msg, None).unwrap();
    assert_valid(&pubkey(&keys), msg, &sig);
}

#[test]
fn robust_f2_triples_completes_and_blames() {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 118);
    // Dealer 2 re-shares a wrong share to party 3 (T2); the honest majority
    // publicly reconstructs dealer 2's committed re-sharing polynomial and
    // continues — the triple is delivered, dealer 2 blamed (§10.4/C6 T3).
    let tamper = TripleTamper {
        bad_reshare: Some((2, 3)),
        ..Default::default()
    };
    let (triple, blamed) =
        triples::generate_robust(&params, b"blame/118", &mut rngs, Some(&tamper)).unwrap();
    assert_eq!(blamed, vec![2]);
    assert_eq!(triple.len(), 2);
    assert!(triple.iter().all(|(s, _)| s.index != 2));
    // The delivered triple is multiplicative at the public commitments.
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
fn robust_f3_bad_product_proof_still_aborts() {
    // F3 is a DEALING-phase fault: the prover's commitment binds it to a
    // wrong product, so reconstruction would recover a wrong-but-committed
    // polynomial. Not continuable even on the robust path (SPEC §11.2 C6:
    // F1–F3 go to expel-and-restart) — the abort must still name exactly
    // the prover.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 119);
    let tamper = TripleTamper {
        bad_product_proof: Some(1),
        ..Default::default()
    };
    let err =
        triples::generate_robust(&params, b"blame/119", &mut rngs, Some(&tamper)).unwrap_err();
    assert_abort(err, Phase::Triples, &[1]);
}

// --- Framing-freeness positive control (C3) --------------------------------

#[test]
fn honest_robust_drivers_blame_nobody() {
    // An honest run through every blame-reporting driver must report an
    // EMPTY blame list — no honest party is ever blamed.
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 120);
    let keys = sim::run_keygen(&params, b"blame/120", &mut rngs).unwrap();

    let (triple, blamed) = triples::generate_robust(&params, b"blame/120t", &mut rngs, None)
        .expect("honest robust triples completes");
    assert_eq!(triple.len(), 3);
    assert!(blamed.is_empty(), "honest triples blamed {blamed:?}");

    let (presigs, blamed) = sim::run_presign_robust(&params, &keys, 1, &mut rngs, None)
        .expect("honest robust presign completes");
    assert_eq!(presigs.len(), 3);
    assert!(blamed.is_empty(), "honest presign blamed {blamed:?}");

    let msg = b"honest run: nobody to blame";
    let (sig, blamed) = sim::run_sign_robust(&params, &presigs, msg, &[]).unwrap();
    assert!(blamed.is_empty(), "honest sign blamed {blamed:?}");
    assert_valid(&pubkey(&keys), msg, &sig);
}
