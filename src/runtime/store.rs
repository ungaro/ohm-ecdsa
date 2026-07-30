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

use crate::presign::{KiPresignature, Presignature};
use crate::{Error, Result};

/// Per-party presignature store bound to exactly one long-term key
/// (SPEC §8.6).
///
/// Dropping the store drops any remaining [`Presignature`]s; their
/// `Drop` erases the scalars via `zeroize` (compiler-fenced, §8.6(3) —
/// `mlock`/HSM-backed storage remains a deployment concern, §13.3).
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

    /// Drop ALL stored presignatures (SPEC §13.4): a key-share refresh or
    /// committee change invalidates every outstanding presignature — they
    /// are key-equivalent (§8.6), so they must never outlive the epoch they
    /// were created in. Dropping the records applies their `Drop`
    /// erasure. Deployments MUST call this on every epoch change.
    pub fn clear(&mut self) {
        self.records.clear();
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

/// Key-free pool of KEY-INDEPENDENT presignature records (SPEC §8.7).
///
/// The pool-level counterpart of [`PresigStore`] for records that are not
/// yet bound to any key: the same §8.6(1) single-use discipline — atomic
/// consume, duplicate-id rejection — WITHOUT the one-key binding (binding
/// happens online, when a record is consumed for a specific key; see
/// [`crate::sim::run_sign_ki_pooled`]). Because KI records carry no
/// key-equivalent material, a §13.4 epoch change does NOT invalidate the
/// pool (there is no `clear` mandate). Dropping the pool drops any
/// remaining records; their `Drop` erases the scalars via `zeroize`.
#[derive(Debug, Default)]
pub struct KiPool {
    records: BTreeMap<u64, KiPresignature>,
}

impl KiPool {
    /// Create an empty key-free pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record; rejects a duplicate id (nonce-reuse guard,
    /// §8.6(1)).
    pub fn insert(&mut self, record: KiPresignature) -> Result<()> {
        if self.records.contains_key(&record.id) {
            return Err(Error::PresigStore("duplicate presignature id"));
        }
        self.records.insert(record.id, record);
        Ok(())
    }

    /// Atomically remove and return the record for `id` — exactly once
    /// (§8.6(1): transactional delete).
    pub fn consume(&mut self, id: u64) -> Result<KiPresignature> {
        self.records
            .remove(&id)
            .ok_or(Error::PresigStore("unknown or consumed presignature id"))
    }

    /// Number of stored (unconsumed) records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the pool holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether `id` is present and unconsumed.
    pub fn contains(&self, id: u64) -> bool {
        self.records.contains_key(&id)
    }
}
