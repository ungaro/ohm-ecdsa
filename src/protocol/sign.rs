//! One-round online signing (SPEC §9).
//!
//! Each party broadcasts `s_j = m·u_j + r·z_j`. Since the signature
//! sharing is a public linear combination of committed sharings, every
//! share is verified against `A[s] = m·A[u] + r·A[z]` by point equality —
//! a bad share identifies its sender before it can enter interpolation.
//!
//! [`combine_at`] is the packed-mode entry point (SPEC §7.4.3): the
//! presignature is a degree-`d` sharing, so interpolation runs at the
//! record's slot point `e_b` with quorum `d + 1 = t + B − 1`. Share
//! verification is unchanged — only the interpolation point and quorum
//! move.
//!
//! Key-independent pool records (SPEC §8.7) sign with a 2-round online
//! protocol: R1 opens `δ = Open(⟦u⟧−⟦α⟧)`, `ε = Open(⟦x⟧−⟦β⟧)` against
//! a fresh Beaver triple (β masks the key exactly as in §8 P4); R2
//! broadcasts `s_j = m·u_j + r·z_j` with `z_j` computed locally from the
//! triple share and the opened masks ([`ki_z_share`]). [`combine_ki`]
//! verifies each share against `m·A[u] + r·A[z]` — same point-equality
//! semantics as [`combine`], with `A[z]` formed online ([`ki_z_com`]).
//!
//! [`combine_robust`] / [`combine_ki_robust`] are the §10.4 blame-and-
//! continue variants: bad shares are filtered and blamed, and the
//! signature is interpolated from the first `t` valid shares.

use k256::Scalar;

use crate::presign::{KiPresignature, Presignature};
use crate::shamir::{interpolate_at, interpolate_at_zero};
use crate::triples::{TriplePublic, TripleShare};
use crate::vss::FeldmanCommitment;
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
    combine_at(params.t, &Scalar::ZERO, meta, m, shares)
}

/// [`combine`] interpolating at an arbitrary point with an explicit
/// quorum (SPEC §7.4.3: packed presignatures are degree-`d` sharings, so
/// the signature share sharing interpolates at the record's slot point
/// `e_b = -(b)` and needs `d + 1 = t + B − 1` shares). Every share is
/// still verified against `m·A[u] + r·A[z]` by point equality —
/// verification semantics are unchanged; only the interpolation point
/// and quorum move.
pub fn combine_at(
    quorum: usize,
    point: &Scalar,
    meta: &Presignature,
    m: &Scalar,
    shares: &[SignShare],
) -> Result<(Scalar, Scalar)> {
    let s_com = meta.u_com.scale(m).add(&meta.z_com.scale(&meta.r));
    combine_verified(quorum, point, meta.r, &s_com, shares)
}

/// Verify every share against `s_com` by point equality (blaming any
/// failure) and interpolate `(r, s)` from the first `quorum` valid shares
/// at `point` (`Scalar::ZERO` interpolates at 0).
fn combine_verified(
    quorum: usize,
    point: &Scalar,
    r: Scalar,
    s_com: &FeldmanCommitment,
    shares: &[SignShare],
) -> Result<(Scalar, Scalar)> {
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
    if valid_parties.len() < quorum {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: quorum,
        });
    }
    valid_parties.truncate(quorum);
    valid_shares.truncate(quorum);
    if *point == Scalar::ZERO {
        return Ok((r, interpolate_at_zero(&valid_parties, &valid_shares)));
    }
    Ok((r, interpolate_at(point, &valid_parties, &valid_shares)))
}

// --- Key-independent online signing (SPEC §8.7) ---------------------------

/// Fault-injection hooks for the 2-round KI online signing (tests).
#[derive(Debug, Default)]
pub struct KiSignTamper {
    /// This party broadcasts a wrong R1 opening share (δ = ⟦u⟧−⟦α⟧).
    pub bad_open_share: Option<PartyId>,
    /// This party broadcasts this replacement R2 signature share.
    pub bad_sign_share: Option<(PartyId, Scalar)>,
}

/// Party `j`'s online `z`-share from its triple share and the opened R1
/// masks (SPEC §8.7 R2 — EXACTLY the §8 P4 formula, run online; the
/// product `u·x` is Beaver-derived, never computed directly, SPEC §12).
pub fn ki_z_share(triple: &TripleShare, delta: &Scalar, eps: &Scalar) -> Scalar {
    triple.c + *delta * triple.b + *eps * triple.a + *delta * *eps
}

/// Public commitment to `z = u·x` from the triple commitments and the
/// opened R1 masks (SPEC §8.7 — same homomorphic combination as §8 P4).
pub fn ki_z_com(triple: &TriplePublic, delta: &Scalar, eps: &Scalar) -> FeldmanCommitment {
    triple
        .cc
        .clone()
        .add(&triple.cb.scale(delta))
        .add(&triple.ca.scale(eps))
        .add_const(&(*delta * *eps))
}

/// Local R2 signature share for a key-independent presignature (SPEC
/// §8.7): `s_j = m·u_j + r·z_j`, with `z_j` from [`ki_z_share`].
pub fn sign_share_ki(presig: &KiPresignature, z_share: &Scalar, m: &Scalar) -> SignShare {
    SignShare {
        from: presig.index,
        s: *m * presig.u_share + presig.r * *z_share,
    }
}

/// Verified combine for KI online signing (SPEC §8.7 R2): identical
/// semantics to [`combine`] — every share point-checked against
/// `m·A[u] + r·A[z]`, failure is `Error::Abort` blaming the sender — with
/// `A[z]` formed online from the R1 openings ([`ki_z_com`]). `meta` is any
/// party's pool record (the commitments are identical across parties).
pub fn combine_ki(
    params: &Params,
    meta: &KiPresignature,
    z_com: &FeldmanCommitment,
    m: &Scalar,
    shares: &[SignShare],
) -> Result<(Scalar, Scalar)> {
    let s_com = meta.u_com.scale(m).add(&z_com.scale(&meta.r));
    combine_verified(params.t, &Scalar::ZERO, meta.r, &s_com, shares)
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
    combine_robust_verified(params.t, meta.r, &s_com, shares)
}

/// Robust variant of [`combine_ki`] (SPEC §10.4): identical semantics to
/// [`combine_robust`] — bad shares filtered, senders blamed, `(r, s)`
/// interpolated from the first `t` valid shares — with `A[z]` formed
/// online from the R1 openings ([`ki_z_com`]). `meta` is any party's pool
/// record (the commitments are identical across parties).
pub fn combine_ki_robust(
    params: &Params,
    meta: &KiPresignature,
    z_com: &FeldmanCommitment,
    m: &Scalar,
    shares: &[SignShare],
) -> Result<((Scalar, Scalar), Vec<PartyId>)> {
    let s_com = meta.u_com.scale(m).add(&z_com.scale(&meta.r));
    combine_robust_verified(params.t, meta.r, &s_com, shares)
}

/// The shared §10.4 robust combine body: filter shares failing the
/// point-equality check against `s_com` (senders blamed), interpolate
/// `(r, s)` from the first `quorum` valid shares at 0.
fn combine_robust_verified(
    quorum: usize,
    r: Scalar,
    s_com: &FeldmanCommitment,
    shares: &[SignShare],
) -> Result<((Scalar, Scalar), Vec<PartyId>)> {
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
    if valid_parties.len() < quorum {
        return Err(Error::NotEnoughShares {
            got: valid_parties.len(),
            need: quorum,
        });
    }
    valid_parties.truncate(quorum);
    valid_shares.truncate(quorum);
    let s = interpolate_at_zero(&valid_parties, &valid_shares);
    Ok(((r, s), blamed))
}
