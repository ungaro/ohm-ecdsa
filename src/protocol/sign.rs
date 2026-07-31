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
//!
//! [`rerand_gamma`] / [`sign_share_rerand`] / [`combine_rerand`] are the
//! **EXPERIMENTAL** multiplicative re-randomization CANDIDATE (SPEC §9.4:
//! `k′ = γk` with `γ = H(sid ‖ id ‖ M ‖ τ ‖ X)`, the only
//! inverse-compatible mitigation direction for the GS21 cube-root attack,
//! since additive `k′ = k + δ` has no local formula in `[u] = [k⁻¹]`
//! shares). Every step is a local scalar scaling; commitments scale by the
//! same public factors, so every point-equality check survives unchanged
//! and the online phase stays one round. **The security lemma is OPEN
//! (SPEC §11.3(8)) — this API exists for analysis and testing only, is
//! off by default, and is not for production use.**

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use crate::presign::{KiPresignature, Presignature};
use crate::shamir::{interpolate_at, interpolate_at_zero};
use crate::triples::{TriplePublic, TripleShare};
use crate::vss::FeldmanCommitment;
use crate::{scalar_from_digest, tags, Error, IdentifiableAbort, Params, PartyId, Phase, Result};

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

// --- EXPERIMENTAL multiplicative re-randomization (SPEC §9.4 candidate) --
//
// **EXPERIMENTAL — candidate mitigation, security lemma open (SPEC
// §11.3(8)); not for production use.** Everything in this section is off
// by default: nothing in the standard signing path calls it.

/// **EXPERIMENTAL — candidate mitigation, security lemma open (SPEC
/// §11.3(8)); not for production use.**
///
/// The re-randomization factor `γ = H(sid ‖ id ‖ M ‖ τ ‖ X)` (SPEC §9.4
/// candidate), domain-separated under [`tags::RERAND_GAMMA`] with
/// length-prefixed variable-length fields (sid) and fixed-width encodings
/// elsewhere (canonical 32-byte scalars, compressed SEC1 point).
///
/// `γ` must be nonzero for `k′ = γk` to be a re-randomization at all: the
/// hash reduces to zero with probability `~2⁻²⁵⁶` per attempt — negligible
/// but real — so a zero digest is re-hashed with an incremented counter
/// byte (the counter is part of the hash input, starting at 0).
pub fn rerand_gamma(
    sid: &[u8],
    id: u64,
    m: &Scalar,
    tweak: Option<&Scalar>,
    x_point: &AffinePoint,
) -> Scalar {
    let mut counter = 0u8;
    loop {
        let mut h = Sha256::new();
        h.update(tags::RERAND_GAMMA);
        h.update([counter]);
        h.update((sid.len() as u64).to_be_bytes());
        h.update(sid);
        h.update(id.to_be_bytes());
        h.update(m.to_bytes());
        match tweak {
            Some(tau) => {
                h.update([1u8]);
                h.update(tau.to_bytes());
            }
            None => h.update([0u8]),
        }
        h.update(x_point.to_encoded_point(true).as_bytes());
        let gamma = scalar_from_digest(&h.finalize());
        if gamma != Scalar::ZERO {
            return gamma;
        }
        counter = counter.wrapping_add(1);
    }
}

/// `γ⁻¹` and `r′ = F(γ·R)` for a re-randomized signing session (F is the
/// SPEC §8 x-coordinate mapping, as in presign). Panics if `gamma` is zero
/// — [`rerand_gamma`] never returns zero.
fn rerand_factors(big_r: &AffinePoint, gamma: &Scalar) -> (Scalar, Scalar) {
    let gamma_inv = Option::<Scalar>::from(gamma.invert())
        .expect("rerand gamma must be nonzero (rerand_gamma guarantees this)");
    let r_prime_point = (ProjectivePoint::from(*big_r) * gamma).to_affine();
    let encoded = r_prime_point.to_encoded_point(false);
    let r_prime = scalar_from_digest(encoded.x().expect("uncompressed point has x"));
    (gamma_inv, r_prime)
}

/// **EXPERIMENTAL — candidate mitigation, security lemma open (SPEC
/// §11.3(8)); not for production use.**
///
/// Local re-randomized signature share (SPEC §9.4 candidate): with
/// `r′ = F(γ·R)`,
///
/// * `u′_j = γ⁻¹·u_j`,
/// * `z′_j = γ⁻¹·(z_j + τ·u_j)` when a tweak `τ` is present (the §9.4
///   additive child-key update folded into the scaling — equivalent to
///   [`Presignature::apply_tweak`] followed by the `γ⁻¹` scaling), else
///   `z′_j = γ⁻¹·z_j`,
/// * `s_j = m·u′_j + r′·z′_j`.
///
/// All local scalar scalings; no interaction. `r′ = 0` is possible with
/// negligible probability (`γ` is RO-derived); it surfaces as a
/// `Signature::from_scalars` failure at the caller, as `r = 0` does in
/// the standard path.
pub fn sign_share_rerand(
    presig: &Presignature,
    m: &Scalar,
    gamma: &Scalar,
    tweak: Option<&Scalar>,
) -> SignShare {
    let (gamma_inv, r_prime) = rerand_factors(&presig.big_r, gamma);
    let u_prime = gamma_inv * presig.u_share;
    let z_prime = match tweak {
        Some(tau) => gamma_inv * (presig.z_share + *tau * presig.u_share),
        None => gamma_inv * presig.z_share,
    };
    SignShare {
        from: presig.index,
        s: *m * u_prime + r_prime * z_prime,
    }
}

/// **EXPERIMENTAL — candidate mitigation, security lemma open (SPEC
/// §11.3(8)); not for production use.**
///
/// Verified combine for re-randomized signing (SPEC §9.4 candidate):
/// identical blame semantics to [`combine`] — every share is verified by
/// point equality against `m·A[u′] + r′·A[z′]`, a failure is
/// `Error::Abort` blaming the sender — where the commitments scale by the
/// same PUBLIC factors as the shares:
///
/// * `A[u′] = γ⁻¹·A[u]`,
/// * `A[z′] = γ⁻¹·(A[z] + τ·A[u])` with a tweak, else `γ⁻¹·A[z]`.
///
/// The scaled commitment check is NOT optional: it is what keeps
/// identifiable abort intact under re-randomization. Returns `(r′, s)`
/// with `r′ = F(γ·R)`. `meta` is any party's presignature record (the
/// commitments are identical across parties).
pub fn combine_rerand(
    params: &Params,
    meta: &Presignature,
    m: &Scalar,
    gamma: &Scalar,
    tweak: Option<&Scalar>,
    shares: &[SignShare],
) -> Result<(Scalar, Scalar)> {
    let (gamma_inv, r_prime) = rerand_factors(&meta.big_r, gamma);
    let u_prime_com = meta.u_com.scale(&gamma_inv);
    let z_prime_com = match tweak {
        Some(tau) => meta.z_com.add(&meta.u_com.scale(tau)).scale(&gamma_inv),
        None => meta.z_com.scale(&gamma_inv),
    };
    let s_com = u_prime_com.scale(m).add(&z_prime_com.scale(&r_prime));
    combine_verified(params.t, &Scalar::ZERO, r_prime, &s_com, shares)
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
