//! Identifiable abort (SPEC §9–§10) — the headline feature. Every signing
//! share is checked by point equality against public Feldman commitments,
//! so a wrong share is not just rejected: its sender is NAMED. The robust
//! variant (§10.4) blames the cheater and still delivers the signature.
//!
//! Run: `cargo run --example identifiable_abort`

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use ohm_ecdsa::{sim, Error, Params};

/// Verify with k256's ordinary ECDSA verifier and assert low-s (BIP-62).
fn verify(x: &ProjectivePoint, msg: &[u8], sig: &Signature) {
    let vk =
        VerifyingKey::from_sec1_bytes(x.to_affine().to_encoded_point(false).as_bytes()).unwrap();
    vk.verify(msg, sig).expect("signature must verify under X");
    assert!(
        !bool::from(sig.s().is_high()),
        "s must be low (BIP-62/EIP-2)"
    );
    println!("  signature verifies under X (low-s normalized)");
}

fn main() {
    println!("== Identifiable abort: 2-of-3, party 2 turns malicious ==");
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 0xB1A3E); // deterministic; tests only

    let keys = sim::run_keygen(&params, b"blame/key", &mut rngs).unwrap();
    let x = keys[0].com.points[0];
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    println!("  keygen + presig #1 done; party 2 will broadcast a wrong share");
    let msg = b"release the escrow";
    let fake = Scalar::from(0xBADu64); // party 2's tampered share value

    // Fail-fast path: the combine verifies each share against the public
    // commitments and aborts with the cheater's identity.
    println!();
    println!("== Attempt 1: fail-fast signing (SPEC §9) ==");
    let err = sim::run_sign(&params, &presigs, msg, Some((2, fake))).unwrap_err();
    match err {
        Error::Abort { abort } => println!(
            "  Error::Abort — phase: {}, blamed: {:?} ({})",
            abort.phase, abort.blamed, abort.detail
        ),
        other => panic!("expected identifiable abort, got {other:?}"),
    }

    // Robust path (§10.4): the same tamper is filtered out, party 2 is
    // blamed, and the remaining honest t = 2 shares still deliver.
    println!();
    println!("== Attempt 2: robust signing (SPEC §10.4) ==");
    let (sig, blamed) = sim::run_sign_robust(&params, &presigs, msg, &[(2, fake)]).unwrap();
    println!("  blamed {blamed:?} excluded; the honest 2 shares sufficed");
    verify(&x, msg, &sig);

    println!();
    println!("Lesson: wrong shares are caught by point equality — and the");
    println!("cheater is named, so the honest majority can still deliver.");
}
