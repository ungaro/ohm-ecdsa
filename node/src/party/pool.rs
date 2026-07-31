//! H5 (SPEC §8.6): the presignature POOL MANAGER — a per-node
//! maintenance layer over the M3b durable store ([`DiskPresigStore`])
//! and the H2 concurrent-session machinery. One manager thread per node
//! keeps the pool filled and enforces record expiry:
//!
//! * **Target level.** The manager keeps `target` live records in the
//!   store: whenever `stored < target` it runs ONE production session
//!   per tick (the caller's `produce` closure — the demo wires it to
//!   `PartyNode::presign` over the wire, so concurrent production and
//!   online signing are exactly the H2 multi-session path) and persists
//!   the record. Signing drains the pool (`PartyNode::sign_stored`'s
//!   atomic consume is unchanged); the manager refills on its next
//!   ticks.
//! * **Expiry (§8.6(3)).** Records carry a created-at timestamp (the
//!   store's v2 sealed payload, stamped from the manager's clock —
//!   injectable for deterministic tests; legacy v1 sealed records fall
//!   back to the file mtime). With `ttl_secs > 0`, a record older than
//!   the TTL is ERASED via [`DiskPresigStore::expire`] (tombstone
//!   fsync'd first, sealed file removed, id burned forever) and never
//!   served to sign. `ttl_secs = 0` means records never expire (the
//!   default). Expiry is a LOCAL per-node policy: nothing synchronizes
//!   the nodes' clocks, so the same id may expire at different nodes a
//!   beat apart — a sign racing expiry fails loudly (unknown id) rather
//!   than serving a stale record; deployments set the TTL well above
//!   the expected residence time.
//! * **Crash/restart discipline.** Ids are allocated monotonically and
//!   re-seeded from the store's `max_seen_id` (live ∪ consumed ∪
//!   expired tombstones) at startup, so an id is never re-issued. A
//!   crash mid-production loses at most the in-flight session (never
//!   persisted — safe direction); the retried session's insert dedups
//!   against the persisted record, so a restart never over-produces.
//! * **Single-writer invariant.** Exactly ONE `PoolManager` per node:
//!   it is the only WRITER (insert + expire). Signing only CONSUMES
//!   through the store's atomic consume. Two managers on one store
//!   would double-produce (each seeing `stored < target`) — don't.
//!
//! The manager never touches verification: production is the ordinary
//! per-node presign driver with every share point-checked; a cheating
//! peer surfaces as `Error::Abort` through the `produce` closure and
//! stops the loop loudly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ohm_ecdsa::presign::Presignature;
use ohm_ecdsa::Error;

use crate::persist::{DiskPresigStore, PersistError};

/// The system clock in unix seconds — the default [`PoolManager`] clock.
pub fn system_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pool maintenance configuration.
pub struct PoolConfig {
    /// Keep this many live records in the store.
    pub target: usize,
    /// Time-to-live per record in seconds; 0 = records never expire
    /// (the default). With a TTL, aged records are erased (§8.6(3)) and
    /// replaced with fresh ones.
    pub ttl_secs: u64,
    /// Log label (the demo passes `pool node-K`).
    pub label: String,
}

impl PoolConfig {
    /// A config with the default label (`pool`).
    pub fn new(target: usize, ttl_secs: u64) -> Self {
        Self {
            target,
            ttl_secs,
            label: "pool".to_string(),
        }
    }
}

/// The manager's cumulative counters, shared so the owner can read them
/// while the manager runs on its own thread.
#[derive(Default)]
pub struct PoolCounters {
    produced: AtomicU64,
    expired: AtomicU64,
    failed: AtomicU64,
}

impl PoolCounters {
    /// Records actually persisted by THIS manager (crash/restart dedup
    /// re-inserts are not counted — they were produced by a past life).
    pub fn produced(&self) -> u64 {
        self.produced.load(Ordering::SeqCst)
    }

    /// Records erased by TTL expiry.
    pub fn expired(&self) -> u64 {
        self.expired.load(Ordering::SeqCst)
    }

    /// Production sessions that FAILED and had their id burned
    /// ([`PoolManager::tick_tolerant`], A7 soak) — aborts from an
    /// injected fault, round timeouts while a peer is down.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::SeqCst)
    }
}

/// A point-in-time pool snapshot (logs and the demo's `FACTORY` line).
pub struct PoolStats {
    /// The configured target level.
    pub target: usize,
    /// Live records in the store right now.
    pub stored: usize,
    /// Cumulative persisted records (this manager).
    pub produced: u64,
    /// Cumulative TTL erasures (this manager).
    pub expired: u64,
}

/// The per-node pool manager — see the module docs. `produce(id)` runs
/// ONE production session for a fresh id and returns the record (the
/// manager persists it with its clock's timestamp); it must be
/// side-effect-free w.r.t. the store (the manager is the single writer).
pub struct PoolManager {
    store: Arc<Mutex<Option<DiskPresigStore>>>,
    cfg: PoolConfig,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    produce: Box<dyn FnMut(u64) -> Result<Presignature, PersistError> + Send>,
    next_id: u64,
    counters: Arc<PoolCounters>,
}

impl PoolManager {
    /// A manager over the node's shared store handle
    /// ([`crate::PartyNode::store_handle`]) with the system clock.
    pub fn with_system_clock(
        store: Arc<Mutex<Option<DiskPresigStore>>>,
        cfg: PoolConfig,
        produce: impl FnMut(u64) -> Result<Presignature, PersistError> + Send + 'static,
    ) -> Result<Self, PersistError> {
        Self::new(store, cfg, system_clock, produce)
    }

    /// A manager with an injectable clock (deterministic TTL tests).
    /// Id allocation resumes above the store's `max_seen_id`, so a
    /// restarted manager never re-issues an id and persisted records
    /// count toward the target.
    pub fn new(
        store: Arc<Mutex<Option<DiskPresigStore>>>,
        cfg: PoolConfig,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
        produce: impl FnMut(u64) -> Result<Presignature, PersistError> + Send + 'static,
    ) -> Result<Self, PersistError> {
        let next_id = {
            let guard = store.lock().expect("store mutex poisoned");
            let store = guard
                .as_ref()
                .ok_or(Error::PresigStore("no store configured"))?;
            store.max_seen_id() + 1
        };
        Ok(Self {
            store,
            cfg,
            clock: Box::new(clock),
            produce: Box::new(produce),
            next_id,
            counters: Arc::new(PoolCounters::default()),
        })
    }

    fn with_store<R>(&self, f: impl FnOnce(&mut DiskPresigStore) -> R) -> Result<R, PersistError> {
        let mut guard = self.store.lock().expect("store mutex poisoned");
        let store = guard
            .as_mut()
            .ok_or(Error::PresigStore("no store configured"))?;
        Ok(f(store))
    }

    /// The shared counters handle (readable while the manager runs).
    pub fn counters(&self) -> Arc<PoolCounters> {
        Arc::clone(&self.counters)
    }

    /// The id the next production session will use (monotonic per
    /// manager; seeded from the persisted state at construction).
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    /// A point-in-time snapshot (stored is read live from the store).
    pub fn stats(&self) -> PoolStats {
        let stored = self
            .store
            .lock()
            .expect("store mutex poisoned")
            .as_ref()
            .map_or(0, |s| s.len());
        PoolStats {
            target: self.cfg.target,
            stored,
            produced: self.counters.produced(),
            expired: self.counters.expired(),
        }
    }

    /// The TTL-expiry phase of a maintenance pass (§8.6(3)): erase aged
    /// records; they are never served again (consume only serves live
    /// ids).
    fn expire_aged(&self, now: u64) -> Result<(), PersistError> {
        if self.cfg.ttl_secs > 0 {
            let threshold = now.saturating_sub(self.cfg.ttl_secs);
            let aged = self.with_store(|s| s.expired_before(threshold))?;
            for id in aged {
                if self.with_store(|s| s.expire(id))?? {
                    self.counters.expired.fetch_add(1, Ordering::SeqCst);
                    eprintln!(
                        "[{}] presignature {id} expired (ttl {}s) — erased",
                        self.cfg.label, self.cfg.ttl_secs
                    );
                }
            }
        }
        Ok(())
    }

    /// One maintenance pass: expire aged records (§8.6(3)), then produce
    /// ONE record if the pool is below target. Production errors
    /// propagate (the run loop stops loudly) — except `ZeroValue`
    /// (~2⁻¹²⁸ per session): the id is burned and the next tick retries
    /// with a fresh one, the same rule as the drivers.
    pub fn tick(&mut self) -> Result<PoolStats, PersistError> {
        let now = (self.clock)();
        self.expire_aged(now)?;
        // Refill: one record per tick while below target.
        if self.with_store(|s| s.len())? < self.cfg.target {
            let id = self.next_id;
            self.next_id += 1;
            match (self.produce)(id) {
                Ok(record) => match self.with_store(|s| s.insert_at(&record, now))? {
                    Ok(()) => {
                        self.counters.produced.fetch_add(1, Ordering::SeqCst);
                        eprintln!("[{}] presignature {id} produced", self.cfg.label);
                    }
                    // Crash/restart dedup: the record is already
                    // persisted (a previous life produced it) — count it
                    // as stored, never over-produce.
                    Err(PersistError::Protocol(Error::PresigStore(_))) => {}
                    Err(e) => return Err(e),
                },
                Err(PersistError::Protocol(Error::ZeroValue(_))) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(self.stats())
    }

    /// A7 soak: [`Self::tick`] variant that TOLERATES production-session
    /// failure and keeps the loop alive — an abort from an injected
    /// fault or a round timeout while a peer is down fails the ONE
    /// session, not the pool. The failed id is BURNED DURABLY
    /// ([`DiskPresigStore::burn`]): a retried session must never reuse a
    /// presignature id (hence a sid) a past attempt used — the wire may
    /// still hold acceptor/journal state for it (a fresh payload in a
    /// stale slot is indistinguishable from an equivocation), and a
    /// crash/restart re-seeds id allocation from `max_seen_id`, which
    /// only covers DURABLY burned ids. Failures are counted
    /// ([`PoolCounters::failed`]); store I/O errors still propagate
    /// (local corruption is not a tolerable session fault). Production
    /// outcomes are consistent across the committee (identifiable
    /// aborts, session timeouts), so every node's manager burns the
    /// same ids and the id spaces stay aligned.
    pub fn tick_tolerant(&mut self) -> Result<PoolStats, PersistError> {
        let now = (self.clock)();
        self.expire_aged(now)?;
        if self.with_store(|s| s.len())? < self.cfg.target {
            let id = self.next_id;
            self.next_id += 1;
            match (self.produce)(id) {
                Ok(record) => match self.with_store(|s| s.insert_at(&record, now))? {
                    Ok(()) => {
                        self.counters.produced.fetch_add(1, Ordering::SeqCst);
                        eprintln!("[{}] presignature {id} produced", self.cfg.label);
                    }
                    Err(PersistError::Protocol(Error::PresigStore(_))) => {}
                    Err(e) => return Err(e),
                },
                Err(e) => {
                    self.with_store(|s| s.burn(id))??;
                    self.counters.failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!(
                        "[{}] production of presignature {id} failed ({e}) — id burned, \
                         next tick retries with a fresh one",
                        self.cfg.label
                    );
                }
            }
        }
        Ok(self.stats())
    }

    /// The maintenance loop: tick every 20 ms until `stop` is set; on a
    /// maintenance error, set `failed` and return (loud, fail closed).
    pub fn run(&mut self, stop: &AtomicBool, failed: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            if let Err(e) = self.tick() {
                eprintln!("[{}] pool maintenance failed: {e}", self.cfg.label);
                failed.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
