//! 3-of-5 consortium custody: batched presignature generation (SPEC §8.5),
//! signing with only T = 3 of the 5 members, and HD-tweak derivation of
//! per-client account keys (SPEC §9.4) — one key ceremony, unlimited
//! sub-keys.
//!
//! Run: `cargo run --example consortium_custody`

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::{sim, Params};

/// Verify with k256's ordinary ECDSA verifier and assert low-s (BIP-62).
fn verify(x: &ProjectivePoint, msg: &[u8], sig: &Signature, under: &str) {
    let vk =
        VerifyingKey::from_sec1_bytes(x.to_affine().to_encoded_point(false).as_bytes()).unwrap();
    vk.verify(msg, sig).expect("signature must verify");
    assert!(
        !bool::from(sig.s().is_high()),
        "s must be low (BIP-62/EIP-2)"
    );
    println!("  signature verifies under {under} (low-s normalized)");
}

/// The records of `parties` out of one per-party batch (`p.index` is the
/// party id; `run_sign` accepts any subset of at least t records).
fn subset(records: Vec<Presignature>, parties: &[usize]) -> Vec<Presignature> {
    records
        .into_iter()
        .filter(|p| parties.contains(&p.index))
        .collect()
}

fn main() {
    println!("== 3-of-5 consortium: issuer, custodian, auditor, HSM, recovery ==");
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 0xC0C0); // deterministic; OS CSPRNG in production

    println!();
    println!("== KeyGen: commit-reveal DKG (SPEC §6) ==");
    let keys = sim::run_keygen(&params, b"consortium/key", &mut rngs).unwrap();
    let x = keys[0].com.points[0]; // the long-term public key
    println!("  X established; any 3 of 5 sign, up to 2 may be malicious");

    // Offline: one batched session mints presigs #1 and #2 for every party.
    println!();
    println!("== Offline: one batched session mints presigs #1 and #2 ==");
    let mut batch = sim::run_presign_batch(&params, &keys, &[1, 2], &mut rngs, None).unwrap();
    println!(
        "  {} records per party (§8.5 batching amortizes the commit-reveal)",
        batch[0].len()
    );
    let id1: Vec<Presignature> = batch.iter_mut().map(|records| records.remove(0)).collect();
    let id2: Vec<Presignature> = batch.iter_mut().map(|records| records.remove(0)).collect();

    // Online: only t = 3 members need to be online. Parties 2, 4, 5 sign.
    println!();
    println!("== Online: parties 2, 4, 5 sign (any T = 3 suffice) ==");
    let msg = b"wire 250000 USD to escrow";
    let sig = sim::run_sign(&params, &subset(id1, &[2, 4, 5]), msg, None).unwrap();
    println!("  one round; members 1 and 3 never participated");
    verify(&x, msg, &sig, "X");

    // HD tweak (§9.4): derive a per-client account key X' = X + τ·G. Each
    // party rebinds its record locally; the signature verifies under X'.
    println!();
    println!("== HD tweak (§9.4): per-client account key X' = X + tau*G ==");
    let tau = Scalar::from(777u64); // the client/account index, made public
    let mut tweaked = subset(id2, &[1, 3, 4]);
    for p in tweaked.iter_mut() {
        p.apply_tweak(&tau);
    }
    let x_child = x + ProjectivePoint::GENERATOR * tau;
    let msg = b"monthly statement payout, client 777";
    let sig = sim::run_sign(&params, &tweaked, msg, None).unwrap();
    println!("  each party updated its record locally — no new ceremony");
    verify(&x_child, msg, &sig, "X' = X + tau*G");

    println!();
    println!("One key ceremony serves the whole book: sub-keys are local math.");
}
