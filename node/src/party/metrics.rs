//! A6 operability: the pull-based metrics snapshot (SPEC §13.1
//! operations).
//!
//! A running node accumulates counters across the layers — the mesh
//! ([`crate::mesh::MeshMetrics`]: frames, drops per reason, reconnects,
//! sessions), the acceptor caps, the H5 pool manager
//! ([`crate::pool::PoolStats`]) and the M3b durable store (live /
//! consumed / expired records, A4 integrity warnings). This module
//! renders them as ONE stable, greppable text block and appends it to a
//! metrics file:
//!
//! * one `#`-prefixed header line carrying the node id, the committee,
//! * the pid and the uptime, then one `name value` pair per line;
//! * no ANSI, no timestamps embedded in counter names — appended blocks
//!   are self-delimiting, a scraper reads the LAST block (e.g. a cron
//!   `tail` piped into any monitoring stack);
//! * pool counters appear only when a pool manager was registered
//!   ([`MetricsReporter::set_pool`]); store counters appear only when
//!   the node opened a durable store (`--data-dir`).
//!
//! Deliberately PULL-BASED: there is no HTTP endpoint and no push. A
//! production deployment that wants Prometheus-style scraping wraps the
//! file with its own exporter; the reference crate stays std-only.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::party::PartyNode;
use crate::pool::{PoolCounters, PoolStats};

/// The CLI reporter's snapshot interval (`node --metrics-file`).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);

/// The registered pool source (target + live counters), shared between
/// the factory demo and the reporter thread.
type PoolSlot = Arc<Mutex<Option<(usize, Arc<PoolCounters>)>>>;

/// Render one snapshot block for `node`: a `#`-prefixed header line
/// (node id, committee, pid, uptime) followed by one `name value`
/// counter pair per line. `pool` is the pool manager's point-in-time
/// stats when the node runs one (`--factory N`); the store counters are
/// read live from the node's store handle and appear only when a
/// durable store is configured.
pub fn snapshot(node: &PartyNode, pool: Option<&PoolStats>, started: Instant) -> String {
    let m = node.metrics();
    let committee = node
        .committee()
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut out = format!(
        "# ohm-ecdsa-node metrics node={} committee={committee} pid={} uptime_s={}\n",
        node.id(),
        std::process::id(),
        started.elapsed().as_secs()
    );
    let mut line = |name: &str, value: u64| {
        out.push_str(name);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    };
    line("tls_enabled", node.tls_enabled() as u64);
    line("frames_sent", m.frames_sent);
    line("frames_received", m.frames_received);
    line("frames_dropped_bad_signature", m.dropped_bad_signature);
    line("frames_dropped_misrouted", m.dropped_misrouted);
    line("frames_dropped_rate_limited", m.dropped_rate_limited);
    line("frames_dropped_oversize", m.dropped_oversize);
    line("frames_dropped_inbox_full", m.dropped_inbox_full);
    line("acceptor_drops", node.acceptor_drops());
    line("equivocations", node.equivocation_count());
    line("accepts_rate_limited", m.accepts_rate_limited);
    line("handshake_rejects", m.handshake_rejects);
    line("reconnects", m.reconnects);
    line("sessions_active", node.sessions_active() as u64);
    line("sessions_completed", m.sessions_completed);
    if let Some(p) = pool {
        line("pool_target", p.target as u64);
        line("pool_stored", p.stored as u64);
        line("pool_produced", p.produced);
        line("pool_expired", p.expired);
    }
    let store = node.store_handle();
    let guard = store.lock().expect("store mutex poisoned");
    if let Some(s) = guard.as_ref() {
        line("store_live", s.len() as u64);
        line("store_consumed", s.consumed_count() as u64);
        line("store_expired", s.expired_count() as u64);
        // A4: the integrity warnings collected at `open` — nonzero
        // means the store's integrity could not be fully verified
        // (see docs/runbook.md §5/§6).
        line(
            "store_integrity_warnings",
            s.integrity_warnings().len() as u64,
        );
    }
    out
}

/// Append one snapshot block to the metrics file (creating it and any
/// parent directories). Best-effort by the reporter; a full disk fails
/// the write loudly via the returned error, never the node.
pub fn append(path: &Path, block: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(block.as_bytes())
}

/// The background reporter wired by `node --metrics-file PATH`:
/// appends one snapshot block every `interval` while the node runs and
/// one FINAL block on drop (clean shutdown). The reporter only reads —
/// it never touches verification, the store, or the mesh.
pub struct MetricsReporter {
    path: PathBuf,
    node: Arc<PartyNode>,
    started: Instant,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    /// The registered pool manager (target + live counters), if any.
    pool: PoolSlot,
}

impl MetricsReporter {
    /// Start the reporter thread (first snapshot after `interval`).
    pub fn start(path: PathBuf, node: Arc<PartyNode>, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let pool: PoolSlot = Arc::new(Mutex::new(None));
        let handle = {
            let reporter = Self {
                path: path.clone(),
                node: Arc::clone(&node),
                started: Instant::now(),
                stop: Arc::clone(&stop),
                handle: None,
                pool: Arc::clone(&pool),
            };
            thread::spawn(move || {
                // Sleep in slices so shutdown stays responsive.
                let mut waited = Duration::ZERO;
                loop {
                    if reporter.stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if waited >= interval {
                        reporter.write_once();
                        waited = Duration::ZERO;
                    }
                    thread::sleep(Duration::from_millis(100));
                    waited += Duration::from_millis(100);
                }
            })
        };
        Self {
            path,
            node,
            started: Instant::now(),
            stop,
            handle: Some(handle),
            pool,
        }
    }

    /// Register the pool manager's live counters (`--factory N`): from
    /// then on every snapshot carries the `pool_*` lines.
    pub fn set_pool(&self, target: usize, counters: Arc<PoolCounters>) {
        *self.pool.lock().expect("metrics mutex poisoned") = Some((target, counters));
    }

    /// Build and append one snapshot block (failures are logged, never
    /// fatal — metrics must not take the node down).
    fn write_once(&self) {
        let pool_stats = {
            let registered = self.pool.lock().expect("metrics mutex poisoned");
            registered.as_ref().map(|(target, counters)| {
                let stored = self
                    .node
                    .store_handle()
                    .lock()
                    .expect("store mutex poisoned")
                    .as_ref()
                    .map_or(0, |s| s.len());
                PoolStats {
                    target: *target,
                    stored,
                    produced: counters.produced(),
                    expired: counters.expired(),
                }
            })
        };
        let block = snapshot(&self.node, pool_stats.as_ref(), self.started);
        if let Err(e) = append(&self.path, &block) {
            eprintln!(
                "[node {}] metrics write to {} failed: {e}",
                self.node.id(),
                self.path.display()
            );
        }
    }
}

impl Drop for MetricsReporter {
    /// Stop the reporter thread and append the FINAL snapshot block (the
    /// one a scraper reads after a clean shutdown).
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.write_once();
    }
}
