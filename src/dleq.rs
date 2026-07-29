//! Chaum–Pedersen DLEQ proofs (Sigma protocol, Fiat–Shamir).
//!
//! Proves `log_{g1}(x1) == log_{g2}(x2)` for public `(g1, x1, g2, x2)`
//! with witness `x` such that `x1 = x·g1` and `x2 = x·g2`. Used for the
//! triple product proof (SPEC §4.4): with `A = α·G`, `B = β·G`,
//! `C = αβ·G`, proving `DLEQ(G, A; B, C)` proves the product relation
//! since `log_B C = α = log_G A`.

use k256::elliptic_curve::ff::Field;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::scalar_from_digest;

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
}
