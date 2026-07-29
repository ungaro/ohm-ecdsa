//! One-round online signing (SPEC §9).
//!
//! Each party broadcasts `s_j = m·u_j + r·z_j`. Since the signature
//! sharing is a public linear combination of committed sharings, every
//! share is verified against `A[s] = m·A[u] + r·A[z]` by point equality —
//! a bad share identifies its sender before it can enter interpolation.

use k256::Scalar;

use crate::presign::Presignature;
use crate::shamir::interpolate_at_zero;
use crate::{Error, IdentifiableAbort, Params, PartyId, Phase, Result};

/// A broadcast signature share.
#[derive(Clone, Debug)]
pub struct SignShare {
    pub from: PartyId,
    pub s: Scalar,
}

/// Local computation of this party's signature share.
pub fn sign_share(presig: &Presignature, m: &Scalar) -> SignShare {
    SignShare {
        from: presig.index,
        s: *m * presig.u_share + presig.r * presig.z_share,
    }
}

/// Verify and combine signature shares into `(r, s)`.
///
/// `meta` is any party's presignature record (the commitments are
/// identical across parties). Returns `Error::Abort` blaming any party
/// whose share fails the commitment check.
pub fn combine(
    params: &Params,
    meta: &Presignature,
    m: &Scalar,
    shares: &[SignShare],
) -> Result<(Scalar, Scalar)> {
    let s_com = meta.u_com.scale(m).add(&meta.z_com.scale(&meta.r));
    let mut valid_parties = Vec::new();
    let mut valid_shares = Vec::new();
    let mut blamed = Vec::new();
    for sh in shares {
        if s_com.verify_share(sh.from, &sh.s) {
            valid_parties.push(sh.from);
            valid_shares.push(sh.s);
        } else {
            blamed.push(sh.from);
        }
    }
    if !blamed.is_empty() {
        return Err(Error::Abort {
            abort: IdentifiableAbort {
                phase: Phase::Sign,
                blamed,
                detail: "signature share failed commitment check".into(),
            },
        });
    }
    if valid_parties.len() < params.t {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: params.t,
        });
    }
    valid_parties.truncate(params.t);
    valid_shares.truncate(params.t);
    let s = interpolate_at_zero(&valid_parties, &valid_shares);
    Ok((meta.r, s))
}

/// Robust variant of [`combine`] (SPEC §10.4): bad signature shares are
/// filtered out and their senders blamed, and `(r, s)` is interpolated
/// from the first `t` valid shares. Errors with `Error::NotEnoughShares`
/// only if fewer than `t` valid shares remain.
pub fn combine_robust(
    params: &Params,
    meta: &Presignature,
    m: &Scalar,
    shares: &[SignShare],
) -> Result<((Scalar, Scalar), Vec<PartyId>)> {
    let s_com = meta.u_com.scale(m).add(&meta.z_com.scale(&meta.r));
    let mut valid_parties = Vec::new();
    let mut valid_shares = Vec::new();
    let mut blamed = Vec::new();
    for sh in shares {
        if s_com.verify_share(sh.from, &sh.s) {
            valid_parties.push(sh.from);
            valid_shares.push(sh.s);
        } else {
            blamed.push(sh.from);
        }
    }
    if valid_parties.len() < params.t {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: params.t,
        });
    }
    valid_parties.truncate(params.t);
    valid_shares.truncate(params.t);
    let s = interpolate_at_zero(&valid_parties, &valid_shares);
    Ok(((meta.r, s), blamed))
}
