//! Feldman commitments to Shamir sharing polynomials.
//!
//! A sharing polynomial `p(X) = Σ a_ℓ·X^ℓ` is committed as the point
//! vector `A_ℓ = a_ℓ·G`. Share verification is pure point equality —
//! this is what makes every opening in OHM-ECDSA identifiable without
//! any NIZK proofs (SPEC §4.2).

use k256::{ProjectivePoint, Scalar};

use crate::{shamir::ShamirPoly, PartyId};

/// Commitment to a sharing polynomial: `points[ℓ] = a_ℓ·G`.
#[derive(Clone, Debug)]
pub struct FeldmanCommitment {
    pub points: Vec<ProjectivePoint>,
}

impl FeldmanCommitment {
    /// Commit to the polynomial behind a sharing.
    pub fn from_poly(p: &ShamirPoly) -> Self {
        Self {
            points: p
                .coeffs
                .iter()
                .map(|c| ProjectivePoint::GENERATOR * c)
                .collect(),
        }
    }

    /// Public commitment to the share of party `j`: `Σ j^ℓ·A_ℓ`.
    pub fn eval_at(&self, j: PartyId) -> ProjectivePoint {
        let x = Scalar::from(j as u64);
        let mut acc = ProjectivePoint::IDENTITY;
        let mut xpow = Scalar::ONE;
        for a in &self.points {
            acc += *a * xpow;
            xpow *= x;
        }
        acc
    }

    /// Verify that `share` is party `j`'s share under this commitment.
    pub fn verify_share(&self, j: PartyId, share: &Scalar) -> bool {
        ProjectivePoint::GENERATOR * share == self.eval_at(j)
    }

    /// Commitment to the sum of two sharings (same degree).
    pub fn add(&self, rhs: &Self) -> Self {
        assert_eq!(
            self.points.len(),
            rhs.points.len(),
            "commitment degree mismatch"
        );
        Self {
            points: self
                .points
                .iter()
                .zip(rhs.points.iter())
                .map(|(a, b)| *a + *b)
                .collect(),
        }
    }

    /// Commitment to a scalar multiple of a sharing.
    pub fn scale(&self, c: &Scalar) -> Self {
        Self {
            points: self.points.iter().map(|a| *a * c).collect(),
        }
    }

    /// Commitment to a sharing whose constant term is shifted by `c`.
    pub fn add_const(&self, c: &Scalar) -> Self {
        let mut points = self.points.clone();
        points[0] = points[0] + ProjectivePoint::GENERATOR * c;
        Self { points }
    }

    /// Componentwise sum of many commitments (same degree).
    pub fn sum(coms: impl IntoIterator<Item = Self>) -> Self {
        let mut it = coms.into_iter();
        let first = it.next().expect("at least one commitment");
        it.fold(first, |acc, c| acc.add(&c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn commit_and_verify() {
        let mut rng = StdRng::seed_from_u64(11);
        let secret = Scalar::random(&mut rng);
        let poly = ShamirPoly::random(secret, 2, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        for j in 1..=3usize {
            assert!(com.verify_share(j, &poly.eval(j)));
            let bad = poly.eval(j) + Scalar::ONE;
            assert!(!com.verify_share(j, &bad));
        }
        // commitment to the secret itself
        assert_eq!(com.points[0], ProjectivePoint::GENERATOR * secret);
    }

    #[test]
    fn homomorphic_ops() {
        let mut rng = StdRng::seed_from_u64(13);
        let p1 = ShamirPoly::random(Scalar::random(&mut rng), 2, &mut rng);
        let p2 = ShamirPoly::random(Scalar::random(&mut rng), 2, &mut rng);
        let c1 = FeldmanCommitment::from_poly(&p1);
        let c2 = FeldmanCommitment::from_poly(&p2);
        let csum = c1.add(&c2);
        // sum of shares verifies under sum of commitments
        for j in 1..=2usize {
            let s = p1.eval(j) + p2.eval(j);
            assert!(csum.verify_share(j, &s));
        }
        let five = Scalar::from(5u64);
        let cscaled = c1.scale(&five);
        assert!(cscaled.verify_share(1, &(p1.eval(1) * five)));
        let cshift = c1.add_const(&five);
        assert!(cshift.verify_share(1, &(p1.eval(1) + five)));
    }
}
