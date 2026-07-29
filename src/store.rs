//! Single-use presignature store (SPEC §8.6).
//!
//! One store per long-term key (§8.6(4): no cross-key use, enforced
//! structurally). Note that `z = u·x` gives no linear public relation
//! between `A[z]`, `A[u]`, `A[x]`, so key-binding cannot be re-verified
//! from commitments alone; the binding is by construction (one store per
//! key). The store's job is enforcing the security-critical §8.6 rules:
//! single-use with atomic consume (§8.6(1)) — nonce reuse exposes the
//! long-term key directly.

use std::collections::BTreeMap;

use k256::AffinePoint;

use crate::presign::Presignature;
use crate::{Error, Result};

/// Per-party presignature store bound to exactly one long-term key
/// (SPEC §8.6).
///
/// Dropping the store drops any remaining [`Presignature`]s; their
/// `Drop` scrubs the scalars (best-effort erase, §8.6(3) — see the
/// documented §13.3 gap: no `zeroize` crate, no `mlock`).
#[derive(Debug)]
pub struct PresigStore {
    public_key: AffinePoint,
    records: BTreeMap<u64, Presignature>,
}

impl PresigStore {
    /// Create an empty store bound to `public_key` (the DKG output `X`).
    pub fn new(public_key: AffinePoint) -> Self {
        Self {
            public_key,
            records: BTreeMap::new(),
        }
    }

    /// The long-term public key this store is bound to (§8.6(4)).
    pub fn public_key(&self) -> &AffinePoint {
        &self.public_key
    }

    /// Insert a presignature; rejects a duplicate id (nonce-reuse guard,
    /// §8.6(1)).
    pub fn insert(&mut self, presig: Presignature) -> Result<()> {
        if self.records.contains_key(&presig.id) {
            return Err(Error::PresigStore("duplicate presignature id"));
        }
        self.records.insert(presig.id, presig);
        Ok(())
    }

    /// Atomically remove and return the record for `id` — exactly once
    /// (§8.6(1): transactional delete).
    pub fn consume(&mut self, id: u64) -> Result<Presignature> {
        self.records
            .remove(&id)
            .ok_or(Error::PresigStore("unknown or consumed presignature id"))
    }

    /// Number of stored (unconsumed) presignatures.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no presignatures.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether `id` is present and unconsumed.
    pub fn contains(&self, id: u64) -> bool {
        self.records.contains_key(&id)
    }
}
