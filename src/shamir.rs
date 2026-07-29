//! Shamir secret sharing over the secp256k1 scalar field.
//!
//! Sharing polynomials have degree `t - 1` where `t` is the signing
//! threshold (any `t` shares reconstruct). Evaluation points are the
//! party indices `1..=n`; index `0` is reserved for the secret.

use k256::elliptic_curve::ff::Field;
use k256::Scalar;
use rand::RngCore;
use zeroize::Zeroize;

use crate::PartyId;

/// A polynomial `p(X) = c_0 + c_1·X + …` over 𝔽_q; `c_0` is the secret.
#[derive(Clone, Debug)]
pub struct ShamirPoly {
    pub coeffs: Vec<Scalar>,
}

impl Drop for ShamirPoly {
    fn drop(&mut self) {
        // Compiler-fenced erasure of the coefficients (they include the
        // secret `c_0`): k256's `Scalar` implements `zeroize::DefaultIsZeroes`,
        // so this is a volatile write, not an elidable plain store (SPEC §13.3).
        self.coeffs.zeroize();
    }
}

impl ShamirPoly {
    /// Sample a uniform random degree-`(t-1)` polynomial with `p(0) = secret`.
    pub fn random(secret: Scalar, t: usize, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(t);
        coeffs.push(secret);
        for _ in 1..t {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Self { coeffs }
    }

    /// Evaluate at party index `j` (must be ≥ 1).
    pub fn eval(&self, j: PartyId) -> Scalar {
        debug_assert!(j >= 1, "party indices start at 1; 0 is the secret");
        let x = Scalar::from(j as u64);
        let mut acc = Scalar::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }
}

/// Lagrange coefficients for interpolation at `x = 0` over `parties`.
pub fn lagrange_coeffs(parties: &[PartyId]) -> Vec<Scalar> {
    lagrange_coeffs_at(&Scalar::ZERO, parties)
}

/// Lagrange coefficients for interpolation at `x` over `parties`.
pub fn lagrange_coeffs_at(x: &Scalar, parties: &[PartyId]) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(parties.len());
    for (i, &pi) in parties.iter().enumerate() {
        let xi = Scalar::from(pi as u64);
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (k, &pk) in parties.iter().enumerate() {
            if k == i {
                continue;
            }
            let xk = Scalar::from(pk as u64);
            num *= *x - xk;
            den *= xi - xk;
        }
        let den_inv = Option::<Scalar>::from(den.invert()).expect("party indices must be distinct");
        out.push(num * den_inv);
    }
    out
}

/// Interpolate `p(0)` from `shares` held at `parties` (same order).
pub fn interpolate_at_zero(parties: &[PartyId], shares: &[Scalar]) -> Scalar {
    interpolate_at(&Scalar::ZERO, parties, shares)
}

/// Interpolate `p(x)` from `shares` held at `parties` (same order).
pub fn interpolate_at(x: &Scalar, parties: &[PartyId], shares: &[Scalar]) -> Scalar {
    debug_assert_eq!(parties.len(), shares.len());
    let lambdas = lagrange_coeffs_at(x, parties);
    let mut acc = Scalar::ZERO;
    for (l, s) in lambdas.iter().zip(shares.iter()) {
        acc += *l * *s;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn interpolate_at_arbitrary_point() {
        let mut rng = StdRng::seed_from_u64(9);
        let secret = Scalar::random(&mut rng);
        let poly = ShamirPoly::random(secret, 2, &mut rng);
        let parties: Vec<PartyId> = vec![1, 3];
        let shares: Vec<Scalar> = parties.iter().map(|&p| poly.eval(p)).collect();
        // Reconstructing at another party's point reproduces its share
        // (used by the §10.4 public reconstruction of a cheater's poly).
        assert_eq!(
            interpolate_at(&Scalar::from(2u64), &parties, &shares),
            poly.eval(2)
        );
        assert_eq!(interpolate_at_zero(&parties, &shares), secret);
    }

    #[test]
    fn scalar_zeroize_is_native() {
        // All Drop impls rely on k256's `Scalar` implementing
        // `zeroize::Zeroize` natively (via `DefaultIsZeroes`); pin that
        // assumption so a k256 upgrade that drops the impl fails loudly.
        let mut s = Scalar::from(42u64);
        s.zeroize();
        assert_eq!(s, Scalar::ZERO);
        let mut v = vec![Scalar::from(1u64), Scalar::from(2u64)];
        v.zeroize();
        // `Vec::zeroize` erases every element, then clears the vector.
        assert!(v.is_empty());
    }

    #[test]
    fn share_and_reconstruct() {
        let mut rng = StdRng::seed_from_u64(7);
        let secret = Scalar::random(&mut rng);
        let poly = ShamirPoly::random(secret, 3, &mut rng);
        let parties: Vec<PartyId> = vec![1, 2, 3, 4, 5];
        let shares: Vec<Scalar> = parties.iter().map(|&p| poly.eval(p)).collect();
        // any 3 of 5
        for subset in [&[0usize, 1, 2][..], &[0, 2, 4][..], &[2, 3, 4][..]] {
            let ps: Vec<PartyId> = subset.iter().map(|&i| parties[i]).collect();
            let ss: Vec<Scalar> = subset.iter().map(|&i| shares[i]).collect();
            assert_eq!(interpolate_at_zero(&ps, &ss), secret);
        }
    }
}
