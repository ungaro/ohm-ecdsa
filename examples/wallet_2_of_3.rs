//! A 2-of-3 wallet: phone (1) + service (2) + recovery (3) — the README
//! "How it works" story, end to end. Any 2 of 3 parties sign; no single
//! party ever learns the key. Presignatures are stocked offline in
//! per-party single-use stores (SPEC §8.6) and consumed at signing time.
//!
//! Run: `cargo run --example wallet_2_of_3`

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;

use ohm_ecdsa::{sim, Error, Params, PresigStore};

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
    println!("== 2-of-3 wallet: phone (1) + service (2) + recovery (3) ==");
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 0xA11CE); // deterministic; OS CSPRNG in production

    println!();
    println!("== KeyGen: commit-reveal DKG (SPEC §6) ==");
    let keys = sim::run_keygen(&params, b"wallet/key", &mut rngs).unwrap();
    let x = keys[0].com.points[0]; // the long-term public key
    println!("  public key X established; each party holds only a share");

    // Offline: mint presignature #1 and stock the per-party stores.
    println!();
    println!("== Offline: stock presig #1 in each party's PresigStore ==");
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let mut stores: Vec<PresigStore> = (0..3).map(|_| PresigStore::new(x.to_affine())).collect();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    println!("  3 stores stocked (single-use, each bound to X)");

    // Online: phone + service sign. One broadcast round.
    println!();
    println!("== Online: phone (1) + service (2) sign \"send 0.1 BTC\" ==");
    let msg = b"send 0.1 BTC";
    let sig = sim::run_sign_stored(&params, &mut stores[..2], 1, msg, None).unwrap();
    println!("  one round; presig #1 consumed atomically from both stores");
    verify(&x, msg, &sig);

    // The id is spent everywhere: a second attempt must fail.
    println!();
    println!("== Presig #1 is spent: a second attempt fails ==");
    let err = sim::run_sign_stored(&params, &mut stores[..2], 1, msg, None).unwrap_err();
    match err {
        Error::PresigStore(e) => println!("  Error::PresigStore: {e} — nonce reuse prevented"),
        other => panic!("expected PresigStore, got {other:?}"),
    }

    // Disaster recovery: the phone is lost. Recovery + service still sign.
    println!();
    println!("== LOST PHONE: service (2) + recovery (3) sign instead ==");
    let presigs = sim::run_presign(&params, &keys, 2, &mut rngs, None).unwrap();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    println!("  fresh presig #2 stocked (phone's store is unreachable anyway)");
    let msg = b"sweep funds to the replacement wallet";
    let sig = sim::run_sign_stored(&params, &mut stores[1..3], 2, msg, None).unwrap();
    println!("  party 1 never participated — the 2-of-3 threshold held");
    verify(&x, msg, &sig);

    println!();
    println!("Any 2 of 3 sign; losing one device never locks the wallet.");
}
