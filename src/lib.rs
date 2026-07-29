//! OHM-ECDSA — open honest-majority threshold ECDSA (reference implementation).
//!
//! Implements the construction described in `SPEC.md`:
//!
//! * [`shamir`] — Shamir sharing over the secp256k1 scalar field
//! * [`vss`] — Feldman commitments; every opening is verified by point equality
//! * [`dleq`] — Chaum–Pedersen DLEQ proofs (used for triple product proofs)
//! * [`dkg`] — commit-then-reveal Pedersen DKG (anti-rushing)
//! * [`triples`] — Beaver triple factory with verifiable degree reduction
//! * [`presign`] — key-dependent presignatures `([k⁻¹], [k⁻¹x], R)`
//! * [`sign`] — one-round online signing with per-share verification
//! * [`store`] — single-use presignature store (SPEC §8.6)
//! * [`sim`] — single-threaded reference orchestrator (models the broadcast
//!   channel; swap in a real transport for deployment)
//!
//! Security: this is a *reference* implementation of an *unreviewed draft*
//! protocol. It has not been audited. See SPEC.md §13 for the hardening
//! checklist (zeroization, side channels, transport, policy).

pub mod dkg;
pub mod dleq;
mod error;
pub mod open;
pub mod presign;
pub mod shamir;
pub mod sign;
pub mod sim;
pub mod store;
pub mod triples;
pub mod vss;

pub use error::{Error, IdentifiableAbort, Phase, Result};
pub use store::PresigStore;

/// Party identifier: parties are numbered `1..=n`.
pub type PartyId = usize;

/// Threshold parameters: `t` of `n` parties sign; `n >= 2t - 1` (honest majority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub n: usize,
    pub t: usize,
}

impl Params {
    pub fn new(n: usize, t: usize) -> Result<Self> {
        if t < 1 {
            return Err(Error::InvalidParams("threshold must be >= 1"));
        }
        if n < 2 * t - 1 {
            return Err(Error::InvalidParams("honest majority requires n >= 2t - 1"));
        }
        Ok(Self { n, t })
    }

    /// Party ids `1..=n`.
    pub fn parties(&self) -> Vec<PartyId> {
        (1..=self.n).collect()
    }
}

/// Domain-separation tags for hashing / Fiat–Shamir transcripts.
pub(crate) mod tags {
    pub const DKG_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/dkg-commit";
    pub const DKG_BATCH_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/dkg-batch-commit";
    pub const TRIPLE_PRODUCT: &[u8] = b"OHM-ECDSA/v0.1/triple-product";
}

/// Hash a Feldman commitment vector into a transcript digest.
pub(crate) fn hash_commitment(
    sid: &[u8],
    tag: &[u8],
    party: PartyId,
    com: &vss::FeldmanCommitment,
) -> [u8; 32] {
    hash_commitments(sid, tag, party, std::slice::from_ref(com))
}

/// Hash the concatenation of several Feldman commitment vectors into one
/// transcript digest (batch VSS, SPEC §7.3: the R1 hash covers
/// `encode(A⁽¹⁾ ‖ … ‖ A⁽ᴮ⁾)`).
pub(crate) fn hash_commitments(
    sid: &[u8],
    tag: &[u8],
    party: PartyId,
    coms: &[vss::FeldmanCommitment],
) -> [u8; 32] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    h.update(sid);
    h.update((party as u64).to_be_bytes());
    for com in coms {
        for p in &com.points {
            h.update(p.to_affine().to_encoded_point(true).as_bytes());
        }
    }
    h.finalize().into()
}

/// Reduce a 32-byte digest to a scalar (mod q).
#[allow(deprecated)] // generic-array 0.14 from_slice; fine for a 32-byte fixed input
pub(crate) fn scalar_from_digest(digest: &[u8]) -> Scalar {
    use k256::elliptic_curve::ops::Reduce;
    use k256::{FieldBytes, U256};
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from_slice(digest))
}

use k256::Scalar;
