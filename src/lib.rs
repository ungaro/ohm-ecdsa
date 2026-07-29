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
//! * [`policy`] — §10.3 policy after blame (expel-and-restart committee)
//! * [`refresh`] — §13.4 committee maintenance: proactive refresh and
//!   committee-change re-sharing (public key unchanged)
//! * [`sim`] — single-threaded reference orchestrator (models the broadcast
//!   channel; swap in a real transport for deployment)
//! * [`transport`] — the explicit transport seam (SPEC §13.1/§13.2):
//!   `Envelope` message contract, sync `Transport` trait, `SimTransport`
//!   reference implementation, transport-driven DKG driver
//!
//! Security: this is a *reference* implementation of an *unreviewed draft*
//! protocol. It has not been audited. See SPEC.md §13 for the hardening
//! checklist (zeroization, side channels, transport, policy).

pub mod dkg;
pub mod dleq;
mod error;
pub mod open;
pub mod policy;
pub mod presign;
pub mod refresh;
pub mod shamir;
pub mod sign;
pub mod sim;
pub mod store;
pub mod transport;
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

/// An explicit party-id set for one protocol instance (SPEC §10.3).
///
/// The default committee of [`Params`] is `1..=n`; after an expulsion the
/// §10.3 restart runs the fresh instance over the *surviving original ids*
/// (possibly non-contiguous, e.g. `{1,3,4,5,6}`) — their long-term key
/// shares live at those Shamir evaluation points, so fresh sharings must
/// be dealt at the same points. All per-party arrays (`rngs`, `keys`,
/// outputs) are indexed by POSITION in `ids`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committee {
    /// Committee members, sorted ascending; evaluation points for sharing.
    ids: Vec<PartyId>,
    /// Signing threshold (any `t` shares reconstruct).
    t: usize,
}

impl Committee {
    /// Build a committee over explicit ids. Enforces the honest-majority
    /// bound `ids.len() >= 2t - 1`, uniqueness, and `id >= 1` (evaluation
    /// point 0 is reserved for the secret). Ids are stored sorted.
    pub fn new(mut ids: Vec<PartyId>, t: usize) -> Result<Self> {
        if t < 1 {
            return Err(Error::InvalidParams("threshold must be >= 1"));
        }
        if ids.len() < 2 * t - 1 {
            return Err(Error::InvalidParams("honest majority requires n >= 2t - 1"));
        }
        ids.sort_unstable();
        if ids[0] == 0 {
            return Err(Error::InvalidParams(
                "party ids start at 1; 0 is the secret",
            ));
        }
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::InvalidParams("duplicate party ids"));
        }
        Ok(Self { ids, t })
    }

    /// The default `1..=n` committee of `params`.
    pub fn full(params: &Params) -> Self {
        Self::new(params.parties(), params.t).expect("Params enforces n >= 2t - 1")
    }

    /// Committee members (sorted) — the Shamir evaluation points.
    pub fn ids(&self) -> &[PartyId] {
        &self.ids
    }

    /// Signing threshold.
    pub fn t(&self) -> usize {
        self.t
    }

    /// Committee size.
    pub fn n(&self) -> usize {
        self.ids.len()
    }

    /// Position of party `j` in the id list (per-party arrays are
    /// positional); `None` if `j` is not a member.
    pub fn position(&self, j: PartyId) -> Option<usize> {
        self.ids.iter().position(|&p| p == j)
    }
}

/// Domain-separation tags for hashing / Fiat–Shamir transcripts.
pub(crate) mod tags {
    pub const DKG_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/dkg-commit";
    pub const DKG_BATCH_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/dkg-batch-commit";
    pub const TRIPLE_PRODUCT: &[u8] = b"OHM-ECDSA/v0.1/triple-product";
    pub const SESSION_ID: &[u8] = b"OHM-ECDSA/v0.1/session-id";
    pub const REFRESH_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/refresh-commit";
    pub const RESHARE_COMMIT: &[u8] = b"OHM-ECDSA/v0.1/reshare-commit";
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

/// Derive a session id (SPEC §13.1):
/// `sid = H(genesis ‖ key-id ‖ presig-id ‖ protocol-tag)`.
///
/// `genesis` anchors the deployment (e.g. a setup-ceremony digest),
/// `key_id` the long-term key, `presig_id` the presignature (`None` for
/// keygen/triples sessions), and `tag` the protocol session kind. Fields
/// are length-prefixed so the encoding is unambiguous; the hash is
/// domain-separated under [`tags::SESSION_ID`]. Pure helper — existing
/// call sites keep their current sid conventions.
pub fn session_id(genesis: &[u8], key_id: &[u8], presig_id: Option<u64>, tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tags::SESSION_ID);
    h.update((genesis.len() as u64).to_be_bytes());
    h.update(genesis);
    h.update((key_id.len() as u64).to_be_bytes());
    h.update(key_id);
    match presig_id {
        Some(id) => {
            h.update([1u8]);
            h.update(id.to_be_bytes());
        }
        None => h.update([0u8]),
    }
    h.update((tag.len() as u64).to_be_bytes());
    h.update(tag);
    h.finalize().into()
}

use k256::Scalar;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_deterministic_and_domain_separated() {
        let base = session_id(b"genesis", b"key-1", Some(7), b"presign");
        assert_eq!(base, session_id(b"genesis", b"key-1", Some(7), b"presign"));
        // Every input field domain-separates the output.
        assert_ne!(base, session_id(b"genesis2", b"key-1", Some(7), b"presign"));
        assert_ne!(base, session_id(b"genesis", b"key-2", Some(7), b"presign"));
        assert_ne!(base, session_id(b"genesis", b"key-1", Some(8), b"presign"));
        assert_ne!(base, session_id(b"genesis", b"key-1", None, b"presign"));
        assert_ne!(base, session_id(b"genesis", b"key-1", Some(7), b"triples"));
        // Length-prefixing: field boundaries are unambiguous.
        assert_ne!(
            session_id(b"ab", b"c", None, b"t"),
            session_id(b"a", b"bc", None, b"t")
        );
    }
}
