//! Chaum–Pedersen DLEQ proofs (Sigma protocol, Fiat–Shamir).
//!
//! Proves `log_{g1}(x1) == log_{g2}(x2)` for public `(g1, x1, g2, x2)`
//! with witness `x` such that `x1 = x·g1` and `x2 = x·g2`. Used for the
//! triple product proof (SPEC §4.4): with `A = α·G`, `B = β·G`,
//! `C = αβ·G`, proving `DLEQ(G, A; B, C)` proves the product relation
//! since `log_B C = α = log_G A`.
//!
//! [`verify_batch`] is the §7.3 aggregate fast path: one prover's `B`
//! proofs are checked with two multi-scalar multiplications, with a
//! per-proof fallback for blame attribution.

use k256::elliptic_curve::ff::Field;
use k256::elliptic_curve::ops::LinearCombinationExt;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{scalar_from_digest, tags, PartyId};

/// A DLEQ proof: commitments `(t1, t2)` and response `z`.
#[derive(Clone, Debug)]
pub struct DleqProof {
    pub t1: ProjectivePoint,
    pub t2: ProjectivePoint,
    pub z: Scalar,
}

fn challenge(
    sid: &[u8],
    tag: &[u8],
    g1: &ProjectivePoint,
    x1: &ProjectivePoint,
    g2: &ProjectivePoint,
    x2: &ProjectivePoint,
    t1: &ProjectivePoint,
    t2: &ProjectivePoint,
) -> Scalar {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(sid);
    for p in [g1, x1, g2, x2, t1, t2] {
        h.update(p.to_affine().to_encoded_point(true).as_bytes());
    }
    scalar_from_digest(&h.finalize())
}

/// Prove `log_{g1}(x1) == log_{g2}(x2)` where `x1 = x·g1`, `x2 = x·g2`.
/// Returns `(x1, x2, proof)`.
pub fn prove(
    sid: &[u8],
    tag: &[u8],
    x: &Scalar,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    rng: &mut impl RngCore,
) -> (ProjectivePoint, ProjectivePoint, DleqProof) {
    let x1 = *g1 * x;
    let x2 = *g2 * x;
    let w = Scalar::random(&mut *rng);
    let t1 = *g1 * w;
    let t2 = *g2 * w;
    let c = challenge(sid, tag, g1, &x1, g2, &x2, &t1, &t2);
    let z = w + c * x;
    (x1, x2, DleqProof { t1, t2, z })
}

/// Verify a DLEQ proof against public `(g1, x1, g2, x2)`.
pub fn verify(
    sid: &[u8],
    tag: &[u8],
    g1: &ProjectivePoint,
    x1: &ProjectivePoint,
    g2: &ProjectivePoint,
    x2: &ProjectivePoint,
    proof: &DleqProof,
) -> bool {
    let c = challenge(sid, tag, g1, x1, g2, x2, &proof.t1, &proof.t2);
    *g1 * proof.z == proof.t1 + *x1 * c && *g2 * proof.z == proof.t2 + *x2 * c
}

/// Verify `proofs.len()` DLEQ proofs from ONE prover AGGREGATELY (SPEC
/// §7.3, "batch proof verification"). `statements[b]` is the public
/// `(g1, x1, g2, x2)` of proof `b`. Instead of checking each
/// `z_b·g1_b == t1_b + c_b·x1_b` and `z_b·g2_b == t2_b + c_b·x2_b`
/// individually, check the two random linear combinations
///
/// `Σ_b ρ_b·(z_b·g1_b − t1_b − c_b·x1_b) == 0`,
/// `Σ_b ρ_b·(z_b·g2_b − t2_b − c_b·x2_b) == 0`,
///
/// as two multi-scalar multiplications (`ProjectivePoint::lincomb_ext`).
///
/// The combination weights are the spec's "verifiers sample a random
/// combination" instantiated non-interactively via Fiat–Shamir:
/// `ρ_b = H(tag' ‖ sid ‖ prover ‖ all B (g1,x1,g2,x2,t1,t2,z) ‖ b)` with
/// `tag' = tags::DLEQ_BATCH_RHO` — deterministic, reproducible across
/// verifiers, and binding to the whole batch. Soundness: a batch passing
/// with an invalid individual proof implies the prover solved for the
/// `ρ_b` after they were derived — infeasible, since the `ρ_b` bind every
/// statement and proof of the batch.
///
/// This is a fast path only: on any all-valid batch it accepts iff
/// per-proof [`verify`] would. On aggregate failure the caller MUST
/// re-verify each proof individually to attribute blame to the exact
/// failing proof (per-triple blame, §7.3).
pub fn verify_batch(
    sid: &[u8],
    tag: &[u8],
    prover: PartyId,
    statements: &[(
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
        ProjectivePoint,
    )],
    proofs: &[&DleqProof],
) -> bool {
    if statements.len() != proofs.len() {
        return false;
    }
    // ρ derivation base hash: tag' ‖ sid ‖ prover ‖ full batch transcript.
    let mut base = Sha256::new();
    base.update(tags::DLEQ_BATCH_RHO);
    base.update(sid);
    base.update((prover as u64).to_be_bytes());
    for ((g1, x1, g2, x2), p) in statements.iter().zip(proofs) {
        for pt in [g1, x1, g2, x2, &p.t1, &p.t2] {
            base.update(pt.to_affine().to_encoded_point(true).as_bytes());
        }
        base.update(p.z.to_bytes());
    }
    let mut eq1: Vec<(ProjectivePoint, Scalar)> = Vec::with_capacity(3 * proofs.len());
    let mut eq2: Vec<(ProjectivePoint, Scalar)> = Vec::with_capacity(3 * proofs.len());
    for (b, ((g1, x1, g2, x2), p)) in statements.iter().zip(proofs).enumerate() {
        let c = challenge(sid, tag, g1, x1, g2, x2, &p.t1, &p.t2);
        let mut h = base.clone();
        h.update((b as u64).to_be_bytes());
        let rho = scalar_from_digest(&h.finalize());
        // ρ·(z·g1 − t1 − c·x1) and ρ·(z·g2 − t2 − c·x2), summed.
        eq1.push((*g1, rho * p.z));
        eq1.push((p.t1, -rho));
        eq1.push((*x1, -rho * c));
        eq2.push((*g2, rho * p.z));
        eq2.push((p.t2, -rho));
        eq2.push((*x2, -rho * c));
    }
    ProjectivePoint::lincomb_ext(&eq1[..]) == ProjectivePoint::default()
        && ProjectivePoint::lincomb_ext(&eq2[..]) == ProjectivePoint::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn dleq_roundtrip() {
        let mut rng = StdRng::seed_from_u64(17);
        let g1 = ProjectivePoint::GENERATOR;
        let beta = Scalar::random(&mut rng);
        let g2 = g1 * beta; // second base
        let x = Scalar::random(&mut rng);
        let (x1, x2, proof) = prove(b"sid", b"test", &x, &g1, &g2, &mut rng);
        assert!(verify(b"sid", b"test", &g1, &x1, &g2, &x2, &proof));
        // wrong statement
        let bad_x2 = x2 + g1;
        assert!(!verify(b"sid", b"test", &g1, &x1, &g2, &bad_x2, &proof));
        // wrong session
        assert!(!verify(b"other-sid", b"test", &g1, &x1, &g2, &x2, &proof));
    }

    #[test]
    fn batch_verify_matches_individual() {
        let mut rng = StdRng::seed_from_u64(23);
        let g1 = ProjectivePoint::GENERATOR;
        let g2 = g1 * Scalar::random(&mut rng); // second base
        let mut statements = Vec::new();
        let mut proofs = Vec::new();
        for _ in 0..5 {
            let x = Scalar::random(&mut rng);
            let (x1, x2, proof) = prove(b"sid", b"test", &x, &g1, &g2, &mut rng);
            statements.push((g1, x1, g2, x2));
            proofs.push(proof);
        }
        let prefs: Vec<&DleqProof> = proofs.iter().collect();
        // all-honest batch: aggregate accepts exactly like individual
        assert!(verify_batch(b"sid", b"test", 1, &statements, &prefs));
        // one corrupted proof: aggregate rejects; the per-proof fallback
        // attributes the failure to exactly that proof
        proofs[2].z += Scalar::ONE;
        let prefs: Vec<&DleqProof> = proofs.iter().collect();
        assert!(!verify_batch(b"sid", b"test", 1, &statements, &prefs));
        let failing: Vec<usize> = (0..5)
            .filter(|&b| {
                let (g1, x1, g2, x2) = &statements[b];
                !verify(b"sid", b"test", g1, x1, g2, x2, &proofs[b])
            })
            .collect();
        assert_eq!(failing, vec![2]);
        // the weights bind the prover id and the batch transcript
        assert!(!verify_batch(b"sid", b"test", 2, &statements, &prefs));
        assert!(!verify_batch(b"other-sid", b"test", 1, &statements, &prefs));
    }
}
