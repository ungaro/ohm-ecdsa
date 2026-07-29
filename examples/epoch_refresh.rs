//! A long-lived key (SPEC §13.4): proactive share refresh on the same
//! committee, mandatory presignature invalidation on epoch change, and a
//! committee change that re-shares the key to brand-new operators — the
//! public key X never moves.
//!
//! Run: `cargo run --example epoch_refresh`

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;

use ohm_ecdsa::{presign, sim, Committee, Params, PresigStore};

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
    println!("== Long-lived 3-of-5 vault key: refresh, then re-share ==");
    let params = Params::new(5, 3).unwrap();
    let mut rngs = sim::make_rngs(5, 0xE900C); // deterministic; OS CSPRNG in production

    let keys = sim::run_keygen(&params, b"vault/key", &mut rngs).unwrap();
    let x = keys[0].com.points[0]; // the long-term public key
    println!("  keygen done: X = A[x].points[0], shares with parties 1..=5");

    // Stock an outstanding presignature in per-party stores.
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
    let mut stores: Vec<PresigStore> = (0..5).map(|_| PresigStore::new(x.to_affine())).collect();
    for (store, presig) in stores.iter_mut().zip(presigs) {
        store.insert(presig).unwrap();
    }
    println!("  presig #1 stocked in all 5 stores");

    // Epoch 2: proactive refresh — same committee, all-new shares.
    println!();
    println!("== Proactive refresh (§13.4): same committee, new epoch ==");
    let refreshed = sim::run_refresh(&params, &keys, b"vault/refresh/1", &mut rngs, None).unwrap();
    println!("  X unchanged: {}", x == refreshed[0].com.points[0]);
    let all_new = keys
        .iter()
        .zip(&refreshed)
        .all(|(old, new)| old.share != new.share);
    println!("  every share re-randomized: {all_new}");

    // §13.4/§8.6: outstanding presignatures are key-equivalent and MUST be
    // invalidated on every epoch change. Stores are caller-owned.
    for store in stores.iter_mut() {
        store.clear();
    }
    println!(
        "  stores cleared per §13.4; old presig #1 gone: {}",
        stores.iter().all(|s| !s.contains(1))
    );

    // Epoch 3: committee change — re-share to a NEW 2-of-3 committee with
    // fresh ids {6,7,8}. X is unchanged; only the old committee deals.
    println!();
    println!("== Committee change (§13.4): re-share to a NEW 2-of-3 committee ==");
    let old = Committee::full(&params);
    let new = Committee::new(vec![6, 7, 8], 2).unwrap();
    let new_keys =
        sim::run_reshare(&refreshed, &old, &new, b"vault/reshare/1", &mut rngs, None).unwrap();
    println!("  new committee: ids {:?}", new.ids());
    println!(
        "  X unchanged under the new committee: {}",
        x == new_keys[0].com.points[0]
    );

    // The new committee presigns and signs under the same X.
    println!();
    println!("== The new 2-of-3 committee signs under the same X ==");
    let new_params = Params::new(3, 2).unwrap();
    let mut new_rngs = sim::make_rngs(3, 0xE900D);
    // Ids are not 1..=n, so presign runs over the explicit committee.
    let presigs = presign::presign_with_committee(&new, &new_keys, 2, &mut new_rngs, None).unwrap();
    let msg = b"pay the auditors, epoch 3";
    let sig = sim::run_sign(&new_params, &presigs, msg, None).unwrap();
    verify(&x, msg, &sig);

    println!();
    println!("Shares and operators rotate; the public key — and every");
    println!("address derived from it — stays put.");
}
