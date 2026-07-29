//! The verified-opening subprotocol `Open` (SPEC §4.6).
//!
//! Every opening in OHM-ECDSA goes through `open`: each broadcast share
//! is checked against the public commitment; a mismatch is an
//! identifiable abort blaming the sender. Interpolation uses the first
//! `t` valid shares.

use std::collections::BTreeMap;

use k256::Scalar;

use crate::shamir::{interpolate_at, interpolate_at_zero};
use crate::vss::FeldmanCommitment;
use crate::{Error, IdentifiableAbort, PartyId, Phase, Result};

/// Open a committed sharing from broadcast shares.
///
/// * `t` — number of shares needed to interpolate (the sharing's degree
///   plus one; for packed degree-`d` sharings this is `d + 1`, SPEC
///   §7.4.3).
/// * `com` — public commitment to the sharing polynomial.
/// * `shares` — broadcast shares keyed by sender.
/// * `phase` — used for abort attribution.
///
/// Returns the opened secret. If any share fails verification the call
/// returns `Error::Abort` blaming the sender(s) — this is the structural
/// identifiable-abort mechanism.
pub fn open(
    t: usize,
    com: &FeldmanCommitment,
    shares: &BTreeMap<PartyId, Scalar>,
    phase: Phase,
) -> Result<Scalar> {
    open_at(&Scalar::ZERO, t, com, shares, phase)
}

/// [`open`] interpolating at an arbitrary point instead of 0 (SPEC §7.4:
/// packed slot openings interpolate at the slot point `e_b = -(b)`).
/// Share verification is unchanged — point equality against the public
/// commitment at the senders' party points; only the interpolation point
/// moves.
pub fn open_at(
    point: &Scalar,
    t: usize,
    com: &FeldmanCommitment,
    shares: &BTreeMap<PartyId, Scalar>,
    phase: Phase,
) -> Result<Scalar> {
    let mut valid_parties = Vec::new();
    let mut valid_shares = Vec::new();
    let mut blamed = Vec::new();
    for (&j, s) in shares {
        if com.verify_share(j, s) {
            valid_parties.push(j);
            valid_shares.push(*s);
        } else {
            blamed.push(j);
        }
    }
    if !blamed.is_empty() {
        return Err(Error::Abort {
            abort: IdentifiableAbort {
                phase,
                blamed,
                detail: "share failed commitment check during opening".into(),
            },
        });
    }
    if valid_parties.len() < t {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: t,
        });
    }
    valid_parties.truncate(t);
    valid_shares.truncate(t);
    if *point == Scalar::ZERO {
        return Ok(interpolate_at_zero(&valid_parties, &valid_shares));
    }
    Ok(interpolate_at(point, &valid_parties, &valid_shares))
}

/// Robust variant of [`open`] (SPEC §10.4): bad shares are filtered out
/// and their senders blamed, and the value is reconstructed from the first
/// `t` valid shares. Because `n ≥ 2t−1`, excluding up to `t−1` cheaters
/// still leaves at least `t` honest shares (guaranteed output delivery).
///
/// `_phase` is accepted for symmetry with [`open`]; in the robust variant
/// blame is *returned*, not raised. Returns the opened secret and the
/// blamed senders; errors with `Error::NotEnoughShares` only if fewer
/// than `t` valid shares remain.
pub fn open_robust(
    t: usize,
    com: &FeldmanCommitment,
    shares: &BTreeMap<PartyId, Scalar>,
    _phase: Phase,
) -> Result<(Scalar, Vec<PartyId>)> {
    let mut valid_parties = Vec::new();
    let mut valid_shares = Vec::new();
    let mut blamed = Vec::new();
    for (&j, s) in shares {
        if com.verify_share(j, s) {
            valid_parties.push(j);
            valid_shares.push(*s);
        } else {
            blamed.push(j);
        }
    }
    if valid_parties.len() < t {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: t,
        });
    }
    valid_parties.truncate(t);
    valid_shares.truncate(t);
    Ok((interpolate_at_zero(&valid_parties, &valid_shares), blamed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::ShamirPoly;
    use k256::elliptic_curve::ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn open_ok_and_blame() {
        let mut rng = StdRng::seed_from_u64(23);
        let secret = Scalar::random(&mut rng);
        let poly = ShamirPoly::random(secret, 2, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let shares: BTreeMap<PartyId, Scalar> = (1..=3).map(|j| (j, poly.eval(j))).collect();
        assert_eq!(open(2, &com, &shares, Phase::Presign).unwrap(), secret);

        let mut bad = shares.clone();
        bad.insert(2, bad[&2] + Scalar::ONE);
        match open(2, &com, &bad, Phase::Presign) {
            Err(Error::Abort { abort }) => assert_eq!(abort.blamed, vec![2]),
            other => panic!("expected identifiable abort, got {:?}", other),
        }
    }

    #[test]
    fn open_robust_filters_and_blames() {
        let mut rng = StdRng::seed_from_u64(29);
        let secret = Scalar::random(&mut rng);
        let poly = ShamirPoly::random(secret, 2, &mut rng);
        let com = FeldmanCommitment::from_poly(&poly);
        let shares: BTreeMap<PartyId, Scalar> = (1..=3).map(|j| (j, poly.eval(j))).collect();

        // One bad share: filtered out and blamed, value still reconstructed.
        let mut bad = shares.clone();
        bad.insert(2, bad[&2] + Scalar::ONE);
        let (opened, blamed) = open_robust(2, &com, &bad, Phase::Presign).unwrap();
        assert_eq!(opened, secret);
        assert_eq!(blamed, vec![2]);

        // Fewer than t valid shares: error.
        let mut worse = shares.clone();
        worse.insert(1, worse[&1] + Scalar::ONE);
        worse.insert(2, worse[&2] + Scalar::ONE);
        match open_robust(2, &com, &worse, Phase::Presign) {
            Err(Error::NotEnoughShares { got: 1, need: 2 }) => {}
            other => panic!("expected NotEnoughShares, got {:?}", other),
        }
    }
}
