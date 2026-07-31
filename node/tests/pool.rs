//! H5 pool manager tests (SPEC §8.6): the per-node pool maintenance
//! layer over the durable store — refill-to-target under drain, TTL
//! expiry with secure erase (§8.6(3)) and never-served guarantees, and
//! crash/restart discipline (persisted records count toward the target,
//! ids are never re-issued). Deterministic: sim-produced records, an
//! injectable clock, no mesh.
//!
//! Also covers the store's H5 record format: the v2 sealed payload
//! (created-at stamp) and the legacy v1 SEALED record (accepted, mtime
//! fallback) — legacy CLEARTEXT stays rejected (persist.rs tests).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use k256::{AffinePoint, ProjectivePoint};
use ohm_ecdsa::presign::{KeyShare, Presignature};
use ohm_ecdsa::sim;
use ohm_ecdsa::transport::Encode;
use ohm_ecdsa::{Error, Params};
use ohm_ecdsa_node::persist::{DiskPresigStore, PersistError};
use ohm_ecdsa_node::pool::{self, PoolConfig, PoolManager};
use ohm_ecdsa_node::seal::StorageKey;

/// Deterministic storage key for the sealed store (H5).
fn sk() -> StorageKey {
    StorageKey::from_secret(&[9u8; 32])
}

/// A fresh empty temp directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-pool-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// One sim keygen the test records are produced under.
struct Fixture {
    params: Params,
    keys: Vec<KeyShare>,
    x: AffinePoint,
}

fn fixture() -> Fixture {
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 11);
    let keys = sim::run_keygen(&params, b"ohm-ecdsa-node/pool-test/keygen", &mut rngs).unwrap();
    let x = keys[0].com.points[0].to_affine();
    Fixture { params, keys, x }
}

/// One sim-produced record (party 1's) for `id` — deterministic.
fn produce_record(fix: &Fixture, id: u64) -> Presignature {
    let mut rngs = sim::make_rngs(fix.params.n, 1000 + id);
    sim::run_presign(&fix.params, &fix.keys, id, &mut rngs, None)
        .unwrap()
        .into_iter()
        .next()
        .expect("one record per party")
}

/// The test producer closure (what the CLI wires to `PartyNode::presign`).
fn produce(fix: &Arc<Fixture>) -> impl FnMut(u64) -> Result<Presignature, PersistError> {
    let fix = Arc::clone(fix);
    move |id| Ok(produce_record(&fix, id))
}

type StoreHandle = Arc<Mutex<Option<DiskPresigStore>>>;

fn open_store(dir: &Path, x: &AffinePoint) -> StoreHandle {
    let store = DiskPresigStore::open(dir, x, &sk()).unwrap();
    Arc::new(Mutex::new(Some(store)))
}

/// A manual clock for deterministic TTL tests.
fn manual_clock(secs: u64) -> (Arc<AtomicU64>, impl Fn() -> u64 + Send + Sync) {
    let clock = Arc::new(AtomicU64::new(secs));
    let read = {
        let clock = Arc::clone(&clock);
        move || clock.load(Ordering::SeqCst)
    };
    (clock, read)
}

#[test]
fn pool_refills_to_target_under_drain() {
    let dir = tmpdir("refill");
    let fix = Arc::new(fixture());
    let store = open_store(&dir, &fix.x);
    let mut mgr =
        PoolManager::with_system_clock(store.clone(), PoolConfig::new(3, 0), produce(&fix))
            .unwrap();
    // Fill to target: one record per tick, then production pauses.
    for _ in 0..3 {
        mgr.tick().unwrap();
    }
    assert_eq!(mgr.stats().stored, 3);
    assert_eq!(mgr.counters().produced(), 3);
    assert_eq!(mgr.next_id(), 4);
    mgr.tick().unwrap();
    assert_eq!(
        mgr.counters().produced(),
        3,
        "at target: no over-production"
    );
    // Drain two records (signing consumes); the manager refills with
    // FRESH ids.
    {
        let mut g = store.lock().unwrap();
        let s = g.as_mut().unwrap();
        s.consume(1).unwrap();
        s.consume(2).unwrap();
        assert_eq!(s.len(), 1);
    }
    mgr.tick().unwrap();
    mgr.tick().unwrap();
    let stats = mgr.stats();
    assert_eq!(stats.stored, 3, "refilled to target after the drain");
    assert_eq!(stats.produced, 5);
    let g = store.lock().unwrap();
    let s = g.as_ref().unwrap();
    assert!(s.contains(3) && s.contains(4) && s.contains(5));
    assert_eq!(s.oldest_live_id(), Some(3), "FIFO drain order");
    assert_eq!(s.max_seen_id(), 5);
    drop(g);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pool_expires_records_and_never_serves() {
    let dir = tmpdir("expiry");
    let fix = Arc::new(fixture());
    let store = open_store(&dir, &fix.x);
    let (clock, read) = manual_clock(1000);
    let mut mgr = PoolManager::new(store.clone(), PoolConfig::new(2, 100), read, produce(&fix))
        .expect("store configured");
    mgr.tick().unwrap();
    mgr.tick().unwrap();
    assert_eq!(mgr.stats().stored, 2, "ids 1, 2 stamped at t=1000");
    assert_eq!(
        store.lock().unwrap().as_ref().unwrap().created_at(1),
        Some(1000)
    );
    // Advance past the TTL: both records are erased in the next tick,
    // which then refills one fresh record (stamped t=1101).
    clock.store(1101, Ordering::SeqCst);
    mgr.tick().unwrap();
    assert_eq!(mgr.counters().expired(), 2);
    {
        let g = store.lock().unwrap();
        let s = g.as_ref().unwrap();
        assert!(!s.contains(1) && !s.contains(2));
        assert!(s.contains(3));
        assert_eq!(s.created_at(3), Some(1101));
    }
    // The sealed files are removed; empty expiry tombstones burn the ids.
    assert!(!dir.join("1.presig").exists());
    assert!(dir.join("1.expired").exists());
    assert!(!dir.join("2.presig").exists());
    assert!(dir.join("2.expired").exists());
    {
        let mut g = store.lock().unwrap();
        let s = g.as_mut().unwrap();
        // Never served: consume surfaces the store's unknown-id error.
        let err = s.consume(1).unwrap_err();
        assert!(matches!(err, PersistError::Protocol(Error::PresigStore(_))));
        // Never re-issuable and not re-expirable.
        assert!(!s.expire(1).unwrap(), "already expired");
        let rec = produce_record(&fix, 1);
        let err = s.insert_at(&rec, 1101).unwrap_err();
        assert!(
            matches!(err, PersistError::Protocol(Error::PresigStore(_))),
            "an expired id stays burned: {err:?}"
        );
    }
    // The fresh refill (stamped 1101) does NOT expire at 1101; the pool
    // refills to target.
    mgr.tick().unwrap();
    assert_eq!(mgr.counters().expired(), 2);
    assert_eq!(mgr.stats().stored, 2);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pool_ttl_zero_never_expires() {
    let dir = tmpdir("no-ttl");
    let fix = Arc::new(fixture());
    let store = open_store(&dir, &fix.x);
    let (clock, read) = manual_clock(1000);
    let mut mgr = PoolManager::new(store.clone(), PoolConfig::new(1, 0), read, produce(&fix))
        .expect("store configured");
    mgr.tick().unwrap();
    assert_eq!(mgr.stats().stored, 1);
    // Far future, ttl 0: nothing expires, nothing over-produces.
    clock.store(u64::MAX / 2, Ordering::SeqCst);
    mgr.tick().unwrap();
    assert_eq!(mgr.counters().expired(), 0);
    assert_eq!(mgr.stats().stored, 1);
    assert!(store.lock().unwrap().as_ref().unwrap().contains(1));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pool_restart_counts_persisted_records_toward_target() {
    let dir = tmpdir("restart");
    let fix = Arc::new(fixture());
    // First life: fill the pool to the target.
    {
        let store = open_store(&dir, &fix.x);
        let mut mgr =
            PoolManager::with_system_clock(store.clone(), PoolConfig::new(3, 0), produce(&fix))
                .unwrap();
        for _ in 0..3 {
            mgr.tick().unwrap();
        }
        assert_eq!(mgr.stats().stored, 3);
    } // simulated crash: manager and store dropped
      // Restart on the same directory: persisted records count toward the
      // target and id allocation resumes above the persisted max.
    let store = open_store(&dir, &fix.x);
    let mut mgr =
        PoolManager::with_system_clock(store.clone(), PoolConfig::new(3, 0), produce(&fix))
            .unwrap();
    assert_eq!(mgr.next_id(), 4, "ids are never re-issued across a restart");
    mgr.tick().unwrap();
    assert_eq!(
        mgr.counters().produced(),
        0,
        "persisted records count toward the target"
    );
    assert_eq!(mgr.stats().stored, 3);
    // Drain one: the refill uses the NEXT id.
    store.lock().unwrap().as_mut().unwrap().consume(1).unwrap();
    mgr.tick().unwrap();
    assert_eq!(mgr.counters().produced(), 1);
    let g = store.lock().unwrap();
    let s = g.as_ref().unwrap();
    assert!(s.contains(4));
    assert_eq!(s.len(), 3);
    drop(g);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn legacy_sealed_v1_record_accepted_with_mtime_fallback() {
    let dir = tmpdir("v1");
    let fix = Arc::new(fixture());
    // Hand-encode two PRE-TTL v1 payloads (no version byte, no timestamp)
    // and seal them exactly as the pre-pool H5 store did.
    for id in [7u64, 8] {
        let rec = produce_record(&fix, id);
        let mut plain = Vec::new();
        plain.extend_from_slice(&rec.id.to_be_bytes());
        plain.extend_from_slice(&(rec.index as u64).to_be_bytes());
        rec.r.encode(&mut plain);
        ProjectivePoint::from(rec.big_r).encode(&mut plain);
        rec.u_share.encode(&mut plain);
        rec.z_share.encode(&mut plain);
        rec.u_com.encode(&mut plain);
        rec.z_com.encode(&mut plain);
        let mut purpose = b"presig-record".to_vec();
        purpose.extend_from_slice(&id.to_be_bytes());
        let sealed = sk().seal(&purpose, &plain);
        fs::write(dir.join(format!("{id}.presig")), &sealed).unwrap();
    }
    // The legacy records are ACCEPTED at open, stamped from the file
    // mtime (records are immutable after the atomic rename).
    let store = open_store(&dir, &fix.x);
    {
        let g = store.lock().unwrap();
        let s = g.as_ref().unwrap();
        assert_eq!(s.len(), 2);
        for id in [7u64, 8] {
            let ts = s.created_at(id).expect("mtime fallback stamps the record");
            assert!(ts > 0 && ts <= pool::system_clock());
        }
    }
    // And a v1 record stays consumable (the payload decodes exactly).
    let back = store.lock().unwrap().as_mut().unwrap().consume(7).unwrap();
    assert_eq!(back.id, 7);
    // TTL expiry applies to the mtime fallback too: a manager whose
    // clock is far past mtime + ttl erases the remaining legacy record
    // (target 0 — expiry only, no production).
    let far = pool::system_clock() + 10_000;
    let (_clock, read) = manual_clock(far);
    let mut mgr = PoolManager::new(store.clone(), PoolConfig::new(0, 100), read, produce(&fix))
        .expect("store configured");
    mgr.tick().unwrap();
    assert_eq!(mgr.counters().expired(), 1);
    assert!(!dir.join("8.presig").exists());
    assert!(dir.join("8.expired").exists());
    assert!(mgr.stats().stored == 0 && mgr.counters().produced() == 0);
    fs::remove_dir_all(&dir).ok();
}
