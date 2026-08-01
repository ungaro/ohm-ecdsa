//! Property-based tests of the algebraic invariants (proptest).
//!
//! Each property cites the SPEC section stating the invariant. Cheap
//! pure-math properties run the default 256 cases; protocol-level ones
//! (triples / presign+sign) are capped to keep the binary fast.
//!
//! Randomness convention: protocol paths derive per-party RNGs from the
//! proptest-generated seed via `sim::make_rngs` (no OS randomness);
//! pure-math properties use a `StdRng` seeded the same way.

use k256::ecdsa::{signature::Verifier, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::BTreeMap;

use ohm_ecdsa::dleq;
use ohm_ecdsa::open::open;
use ohm_ecdsa::shamir::{interpolate_at, interpolate_at_zero, ShamirPoly};
use ohm_ecdsa::sim;
use ohm_ecdsa::triples;
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{scalar_from_digest, Error, Params, PartyId, Phase};

/// A (reduced mod q, near-uniform) random scalar.
fn arb_scalar() -> impl Strategy<Value = Scalar> {
    any::<[u8; 32]>().prop_map(|b| scalar_from_digest(&b))
}

/// Deterministic pseudo-random `t`-subset of `parties` keyed by `key`
/// (splitmix64 mixing — a strategy-level `subsequence` cannot depend on
/// earlier generated values, so the subset is derived in the body).
fn pick_subset(parties: &[PartyId], t: usize, key: u64) -> Vec<PartyId> {
    let mut keyed: Vec<(u64, PartyId)> = parties.iter().map(|&p| (mix(key, p), p)).collect();
    keyed.sort_unstable();
    keyed.into_iter().take(t).map(|(_, p)| p).collect()
}

fn mix(key: u64, p: PartyId) -> u64 {
    let mut z = key ^ (p as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

proptest! {
    // --- Shamir secret sharing (SPEC §4.1) ---------------------------------

    /// SPEC §4.1: a degree-(t−1) sharing reconstructs the secret from ANY
    /// t distinct party points via `interpolate_at_zero`.
    #[test]
    fn shamir_any_t_points_reconstruct_secret(
        secret in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        seed in any::<u64>(),
    ) {
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let parties: Vec<PartyId> = (1..=n).collect();
        let subset = pick_subset(&parties, t, seed ^ 0xA5A5);
        let shares: Vec<Scalar> = subset.iter().map(|&p| poly.eval(p)).collect();
        prop_assert_eq!(interpolate_at_zero(&subset, &shares), secret);
    }

    /// SPEC §4.1 (and §7.4.1 arbitrary evaluation points): `interpolate_at`
    /// over any t shares agrees with `eval_at` at an arbitrary point `x`.
    #[test]
    fn shamir_interpolate_at_matches_eval_at(
        secret in arb_scalar(),
        x in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        seed in any::<u64>(),
    ) {
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let parties: Vec<PartyId> = (1..=n).collect();
        let subset = pick_subset(&parties, t, seed ^ 0x5A5A);
        let shares: Vec<Scalar> = subset.iter().map(|&p| poly.eval(p)).collect();
        prop_assert_eq!(interpolate_at(&x, &subset, &shares), poly.eval_at(&x));
    }

    /// SPEC §4.1: reconstruction is subset-independent — two different
    /// t-subsets interpolate to the same value (at 0 and elsewhere).
    #[test]
    fn shamir_reconstruction_is_subset_independent(
        secret in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        seed in any::<u64>(),
    ) {
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let parties: Vec<PartyId> = (1..=n).collect();
        let s1 = pick_subset(&parties, t, seed ^ 0x1111);
        let s2 = pick_subset(&parties, t, seed ^ 0x2222);
        let sh1: Vec<Scalar> = s1.iter().map(|&p| poly.eval(p)).collect();
        let sh2: Vec<Scalar> = s2.iter().map(|&p| poly.eval(p)).collect();
        prop_assert_eq!(interpolate_at_zero(&s1, &sh1), secret);
        prop_assert_eq!(interpolate_at_zero(&s2, &sh2), secret);
    }

    // --- Feldman VSS (SPEC §4.2) -------------------------------------------

    /// SPEC §4.2: `verify_share` accepts every dealt share and rejects a
    /// perturbed one (point equality `share·G == EvalCom(A, j)`).
    #[test]
    fn vss_verify_accepts_dealt_rejects_perturbed(
        secret in arb_scalar(),
        perturb in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        party_key in any::<u64>(),
        seed in any::<u64>(),
    ) {
        prop_assume!(perturb != Scalar::ZERO);
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let j = 1 + (party_key as usize % n);
        prop_assert!(com.verify_share(j, &poly.eval(j)));
        prop_assert!(!com.verify_share(j, &(poly.eval(j) + perturb)));
        // The commitment's constant term commits to the secret itself.
        prop_assert_eq!(com.points[0], ProjectivePoint::GENERATOR * secret);
    }

    /// SPEC §4.2: the homomorphic commitment ops — `EvalCom` distributes
    /// over `add`, `scale`, and `add_const` at every evaluation point.
    #[test]
    fn vss_homomorphic_ops(
        s1 in arb_scalar(),
        s2 in arb_scalar(),
        c in arb_scalar(),
        t1 in 1usize..=4,
        t2 in 1usize..=4,
        x in arb_scalar(),
        seed in any::<u64>(),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let c1 = FeldmanCommitment::from_poly(&ShamirPoly::random(s1, t1, &mut rng));
        let c2 = FeldmanCommitment::from_poly(&ShamirPoly::random(s2, t2, &mut rng));
        // add (mixed lengths — §7.4.3 zero-padding): evaluation equality.
        let sum = c1.add(&c2);
        prop_assert_eq!(sum.points.len(), c1.points.len().max(c2.points.len()));
        prop_assert_eq!(
            sum.eval_at_point(&x),
            c1.eval_at_point(&x) + c2.eval_at_point(&x)
        );
        // scale.
        prop_assert_eq!(
            c1.scale(&c).eval_at_point(&x),
            c1.eval_at_point(&x) * c
        );
        // add_const shifts the constant term only.
        prop_assert_eq!(
            c1.add_const(&c).eval_at_point(&x),
            c1.eval_at_point(&x) + ProjectivePoint::GENERATOR * c
        );
    }

    /// SPEC §4.2 + §7.4.3: mixed-length `add`/`sum` zero-pad the shorter
    /// vector — appending identity points is appending zero high
    /// coefficients, so values and checks are unaffected.
    #[test]
    fn vss_add_sum_zero_pad_mixed_lengths(
        s1 in arb_scalar(),
        s2 in arb_scalar(),
        s3 in arb_scalar(),
        t1 in 1usize..=4,
        t2 in 1usize..=4,
        t3 in 1usize..=4,
        x in arb_scalar(),
        seed in any::<u64>(),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let c1 = FeldmanCommitment::from_poly(&ShamirPoly::random(s1, t1, &mut rng));
        let c2 = FeldmanCommitment::from_poly(&ShamirPoly::random(s2, t2, &mut rng));
        let c3 = FeldmanCommitment::from_poly(&ShamirPoly::random(s3, t3, &mut rng));
        let expect =
            c1.eval_at_point(&x) + c2.eval_at_point(&x) + c3.eval_at_point(&x);
        // `sum` over mixed lengths evaluates to the sum of evaluations.
        let total = FeldmanCommitment::sum(vec![c1.clone(), c2.clone(), c3.clone()]);
        prop_assert_eq!(total.points.len(), [t1, t2, t3].into_iter().max().unwrap());
        prop_assert_eq!(total.eval_at_point(&x), expect);
        // Adding an empty commitment is the identity (padding preserves
        // the padded commitment's own evaluations).
        let padded = c1.add(&FeldmanCommitment { points: vec![] });
        prop_assert_eq!(padded.points, c1.points);
    }

    // --- The verified-opening subprotocol (SPEC §4.6) ----------------------

    /// SPEC §4.6: `open` reconstructs the dealt value from honest shares.
    #[test]
    fn open_reconstructs_from_honest_shares(
        secret in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        seed in any::<u64>(),
    ) {
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let shares: BTreeMap<PartyId, Scalar> =
            (1..=n).map(|j| (j, poly.eval(j))).collect();
        prop_assert_eq!(open(t, &com, &shares, Phase::Presign).unwrap(), secret);
    }

    /// SPEC §4.6 (identifiable abort): a single wrong share is blamed with
    /// the right party id — `Error::Abort { blamed: [j] }`.
    #[test]
    fn open_blames_single_wrong_share(
        secret in arb_scalar(),
        t in 1usize..=4,
        extra in 0usize..=4,
        cheat_key in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let n = t + extra;
        let mut rng = StdRng::seed_from_u64(seed);
        let poly = ShamirPoly::random(secret, t, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let mut shares: BTreeMap<PartyId, Scalar> =
            (1..=n).map(|j| (j, poly.eval(j))).collect();
        let cheater = 1 + (cheat_key as usize % n);
        shares.insert(cheater, shares[&cheater] + Scalar::ONE);
        match open(t, &com, &shares, Phase::Presign) {
            Err(Error::Abort { abort }) => {
                prop_assert_eq!(abort.phase, Phase::Presign);
                prop_assert_eq!(abort.blamed, vec![cheater]);
            }
            other => return Err(TestCaseError::fail(format!(
                "expected identifiable abort, got {other:?}"
            ))),
        }
    }

    // --- Chaum–Pedersen DLEQ (SPEC §4.4) -----------------------------------

    /// SPEC §4.4: prove/verify roundtrip — `DLEQ(g1, x1; g2, x2)` with
    /// witness `x` verifies.
    #[test]
    fn dleq_prove_verify_roundtrip(
        x in arb_scalar(),
        beta in arb_scalar(),
        sid in proptest::collection::vec(any::<u8>(), 0..32),
        seed in any::<u64>(),
    ) {
        prop_assume!(beta != Scalar::ZERO); // g2 must be a non-trivial base
        let mut rng = StdRng::seed_from_u64(seed);
        let g1 = ProjectivePoint::GENERATOR;
        let g2 = g1 * beta;
        let (x1, x2, proof) = dleq::prove(&sid, b"prop/dleq", &x, &g1, &g2, &mut rng);
        prop_assert!(dleq::verify(&sid, b"prop/dleq", &g1, &x1, &g2, &x2, &proof));
    }

    /// SPEC §4.4: a tampered proof, a wrong statement, or a wrong session
    /// id fails verification.
    #[test]
    fn dleq_rejects_tampered_proof_and_wrong_statement(
        x in arb_scalar(),
        beta in arb_scalar(),
        sid in proptest::collection::vec(any::<u8>(), 0..32),
        other_sid in proptest::collection::vec(any::<u8>(), 0..32),
        seed in any::<u64>(),
    ) {
        prop_assume!(beta != Scalar::ZERO);
        prop_assume!(sid != other_sid);
        let mut rng = StdRng::seed_from_u64(seed);
        let g1 = ProjectivePoint::GENERATOR;
        let g2 = g1 * beta;
        let (x1, x2, proof) = dleq::prove(&sid, b"prop/dleq", &x, &g1, &g2, &mut rng);
        // Tampered response.
        let mut bad = proof.clone();
        bad.z += Scalar::ONE;
        prop_assert!(!dleq::verify(&sid, b"prop/dleq", &g1, &x1, &g2, &x2, &bad));
        // Wrong statement (x2 does not match the witness).
        prop_assert!(!dleq::verify(
            &sid,
            b"prop/dleq",
            &g1,
            &x1,
            &g2,
            &(x2 + g1),
            &proof
        ));
        // Wrong session id (Fiat–Shamir challenge binds the sid).
        prop_assert!(!dleq::verify(&other_sid, b"prop/dleq", &g1, &x1, &g2, &x2, &proof));
    }
}

proptest! {
    // Protocol-level properties are expensive: cap the case count.
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    // --- Beaver triples (SPEC §7) ------------------------------------------

    /// SPEC §7.2: the dealt triple is multiplicative — `c == a·b` — and the
    /// per-party shares verify against the public commitments (T3 checks).
    #[test]
    fn triples_are_multiplicative(seed in any::<u64>()) {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = sim::make_rngs(3, seed);
        let sid = format!("prop/triples/{seed}");
        let triple = triples::generate(&params, sid.as_bytes(), &mut rngs).unwrap();
        let public = &triple[0].1;
        // Per-party shares verify against the public commitments (§7.2 T3).
        for (share, _) in &triple {
            prop_assert!(public.ca.verify_share(share.index, &share.a));
            prop_assert!(public.cb.verify_share(share.index, &share.b));
            prop_assert!(public.cc.verify_share(share.index, &share.c));
        }
        // Reconstruct from any t = 2 shares; c == a·b (§7.2 degree reduction).
        let ids = [1usize, 2];
        let a = interpolate_at_zero(&ids, &[triple[0].0.a, triple[1].0.a]);
        let b = interpolate_at_zero(&ids, &[triple[0].0.b, triple[1].0.b]);
        let c = interpolate_at_zero(&ids, &[triple[0].0.c, triple[1].0.c]);
        prop_assert_eq!(c, a * b);
        // The commitments commit to exactly these values.
        prop_assert_eq!(public.ca.points[0], ProjectivePoint::GENERATOR * a);
        prop_assert_eq!(public.cb.points[0], ProjectivePoint::GENERATOR * b);
        prop_assert_eq!(public.cc.points[0], ProjectivePoint::GENERATOR * c);
    }

    // --- Presign + sign end-to-end (SPEC §8, §9) ----------------------------

    /// SPEC §8/§9 end-to-end invariants (2-of-3):
    /// * §9: the signature verifies under the joint key X and is low-s
    ///   (BIP-62/EIP-2), with `r` equal to the record's `r`;
    /// * §8 P4: `z == u·x` reconstructed through the record's shares;
    /// * §8 P3: `R == u⁻¹·G` — since `u := k⁻¹` and `[k] = v⁻¹·[a]`, this
    ///   is exactly the P2 invariant `v == a·u` (`k·u = 1 ⟺ v = a·u`);
    ///   (`v` itself never leaves `presign` — the record exposes `u`, `z`,
    ///   `R`, `r` only);
    /// * §8 P3: `r == F(R.x)` binds the record's scalar `r` to the point.
    #[test]
    fn presign_sign_end_to_end_invariants(
        seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = sim::make_rngs(3, seed);
        let sid = format!("prop/key/{seed}");
        let keys = sim::run_keygen(&params, sid.as_bytes(), &mut rngs).unwrap();
        let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();
        let sig = sim::run_sign(&params, &presigs, &msg, None).unwrap();

        // §9: valid ECDSA signature under X, low-s normalized.
        let x_point = keys[0].com.points[0];
        let vk = VerifyingKey::from_sec1_bytes(
            x_point.to_affine().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        vk.verify(&msg, &sig).expect("signature must verify under X");
        prop_assert!(!bool::from(sig.s().is_high()), "s must be low (BIP-62/EIP-2)");
        prop_assert_eq!(*sig.r(), presigs[0].r);

        // Reconstruct the shared secrets through the public records.
        let ids = [1usize, 2];
        let x = interpolate_at_zero(&ids, &[keys[0].share, keys[1].share]);
        let u = interpolate_at_zero(&ids, &[presigs[0].u_share, presigs[1].u_share]);
        let z = interpolate_at_zero(&ids, &[presigs[0].z_share, presigs[1].z_share]);
        prop_assert_eq!(x_point, ProjectivePoint::GENERATOR * x);
        prop_assert_eq!(presigs[0].u_com.points[0], ProjectivePoint::GENERATOR * u);
        prop_assert_eq!(presigs[0].z_com.points[0], ProjectivePoint::GENERATOR * z);

        // §8 P4: z = k⁻¹·x = u·x.
        prop_assert_eq!(z, u * x);

        // §8 P3: R = k·G with k = u⁻¹ (equivalently the P2 invariant
        // v == a·u, since [k] = v⁻¹·[a] and u = k⁻¹).
        let u_inv = Option::<Scalar>::from(u.invert()).expect("u = k⁻¹ is nonzero");
        prop_assert_eq!(
            ProjectivePoint::from(presigs[0].big_r),
            ProjectivePoint::GENERATOR * u_inv
        );

        // §8 P3: r = F(R.x) — the record's scalar r is bound to the point.
        let encoded = presigs[0].big_r.to_encoded_point(false);
        let r = scalar_from_digest(encoded.x().expect("uncompressed point has x"));
        prop_assert_eq!(r, presigs[0].r);

        // §9: s == k⁻¹·(m + r·x) = u·(m + r·x) — modulo the low-s
        // normalization (which may replace s with q − s).
        let m = sim::message_scalar(&msg);
        let s_expected = u * (m + presigs[0].r * x);
        prop_assert!(
            s_expected == *sig.s() || s_expected == -*sig.s(),
            "s must equal k⁻¹(m + r·x) up to low-s normalization"
        );
    }
}
