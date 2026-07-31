//! The full-mesh TCP layer (SPEC §13.1): `std::net` with blocking
//! threads, no external runtime (M1; tokio is M3).
//!
//! Topology: every node listens, and opens one outgoing connection to
//! every peer. A pair of nodes therefore has two connections between
//! them, each used in one direction only — sends go out on a node's own
//! outgoing connections, receives arrive on its accepted ones. This
//! avoids any in-band handshake for connection attribution: every frame
//! is already sender-signed (§10.2), so the receiver attributes messages
//! cryptographically, not by connection.
//!
//! Every accepted connection is served by one reader thread that
//! length-delimits frames, verifies signatures ([`WireMessage::verify`]),
//! applies the §4.7 first-echo rule for broadcasts, and feeds the shared
//! mailbox. Unknown senders, bad signatures, and misrouted P2P are
//! dropped and logged — they never reach the mailbox.
//!
//! Two M2 additions, both config-driven and off by default:
//!
//! * self-echo loopback ([`Node::set_self_echo_loopback`]): the node's own
//!   echo is also delivered to its own mailbox. M1's orchestrator acceptor
//!   saw every node's mailbox, so every honest echo was counted globally;
//!   a per-node acceptor (M2, [`crate::party`]) sees only its own mailbox
//!   and must count its own echo explicitly to reach the same
//!   `⌈(n+1)/2⌉`-of-others acceptance rule.
//! * artificial send delay ([`Node::set_send_delay`]): every outgoing
//!   frame is written after a fixed sleep (on a helper thread), simulating
//!   a per-link network latency for the `mesh_perf` benchmark.
//!
//! M3c (OPTIONAL, [`Node::bind_tls`]): every connection is wrapped in
//! mutually-authenticated TLS 1.3 with committee-pinned certificates
//! ([`crate::tls`], SPEC §13.1). Plain TCP remains the default.
//!
//! H2 (network resilience, still localhost reference scale):
//!
//! * **Reconnection** ([`ReconnectConfig`]): every message this node
//!   sends is journaled per session id BEFORE the write is attempted
//!   ([`Node::retire_session`] drops a finished session's entries — the
//!   drivers call it; there is NO crash recovery of finished rounds by
//!   design). When a send fails (or the outgoing connection is gone),
//!   one reconnect task per peer re-dials with capped exponential
//!   backoff + jitter, and on success RE-SENDS the whole journal: the
//!   resync semantics are "re-deliver every message of every in-flight
//!   session, in original order per session". Re-delivery is safe
//!   because the receive path is idempotent — the §4.7 first-echo rule
//!   dedups per broadcast slot and the acceptors dedup per
//!   `(sid, phase, round, from)`. Messages for rounds that already
//!   completed are re-sent too (a session is retired only when its
//!   driver returns) and are absorbed by the same dedup.
//! * **Clean shutdown** ([`Node::shutdown`], also on `Drop`): sets a
//!   flag, unblocks the accept loop with a dummy self-connection, closes
//!   the outgoing connections (peer readers see EOF), and joins every
//!   tracked thread (accept, readers, reconnectors) with a 5 s deadline.
//!   Reader threads poll their socket with [`READ_POLL`], so a blocked
//!   reader notices the flag within one poll interval. There is no
//!   SIGINT handler (std has no signal API; a deployment wraps
//!   [`Node::shutdown`] in its own signal handling).
//! * **IO timeouts**: writes carry [`WRITE_TIMEOUT`] (a dead peer fails
//!   the send instead of parking the writer); the blocking rustls
//!   handshake runs under [`tls::HANDSHAKE_TIMEOUT`] via socket
//!   timeouts (see `src/tls.rs`); read stalls are bounded by the
//!   drivers' ROUND timeout (partial accepted set, fail closed — a
//!   stalled peer fails its round loudly) and never block shutdown.
//! * **DoS guards**: a per-connection frame-rate window
//!   ([`rate_cap_per_second`], pre-verification, drops the connection),
//!   per-variant frame size bounds ([`wire::FrameBound`], derived from
//!   protocol message sizes), a listener accept-rate window and an
//!   mTLS handshake concurrency cap, and a bounded mailbox
//!   ([`INBOX_BOUND`], drops + counts when full). Counters are exposed
//!   via [`Node::metrics`]. Guards only drop/delay — signature and
//!   commitment verification is never bypassed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use ohm_ecdsa::transport::{Decode, Encode};
use ohm_ecdsa::{PartyId, Phase};
use rand::Rng;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::tls::CommitteeTls;
use crate::wire::{frame_bytes, read_frame, write_frame, FrameBound, Received, WireMessage};

/// A broadcast slot `(sid, phase, round, from)`: at most one echo per
/// node per slot (the §4.7 first-echo rule — an equivocating sender
/// cannot collect echoes for two different values from the same node).
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// Read-side poll interval: reader threads block at most this long
/// before re-checking the shutdown flag. NOT a liveness timeout — peer
/// stalls are bounded by the drivers' round timeout, not by the socket.
pub const READ_POLL: Duration = Duration::from_millis(250);

/// Write timeout on every outgoing connection: a dead peer fails the
/// send (triggering reconnect) instead of parking the writer thread.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded mailbox between the reader threads and the acceptor
/// (collector): full means the acceptor is not keeping up — frames are
/// dropped and counted (`MeshMetrics::dropped_inbox_full`).
pub const INBOX_BOUND: usize = 65536;

/// Per-connection frame-rate cap (H2): a peer legitimately sends at
/// most `n` frames per protocol round per connection (its own original
/// plus echoes of the other `n − 1` broadcasts, plus P2P), and the
/// drivers run rounds sequentially. The cap allows `1024` rounds per
/// second worth of frames — orders of magnitude above observed
/// localhost session rates — and exists to kill garbage floods cheaply,
/// BEFORE signature verification. It does NOT protect against a
/// committee member flooding at near-protocol rates (the acceptor-level
/// caps in `src/party.rs` bound that memory).
pub fn rate_cap_per_second(n: usize) -> u32 {
    1024 * n.max(1) as u32
}

/// Listener accept-rate cap (H2): `32` accepted connections per second
/// per committee member. Legitimate accepts are the `n − 1` startup
/// connections plus reconnects (backoff-capped, so ≤ one per peer per
/// [`ReconnectConfig::initial`]); everything beyond is poke/scan noise.
pub fn accept_cap_per_second(n: usize) -> u32 {
    32 * n.max(1) as u32
}

/// mTLS handshake concurrency cap (H2): a handshake is the one
/// expensive accept-side operation (a stalled peer holds a thread for
/// up to [`tls::HANDSHAKE_TIMEOUT`]); cap how many run concurrently.
/// `4n` leaves ample headroom over the `n − 1` legitimate handshakes.
pub fn handshake_cap(n: usize) -> usize {
    4 * n.max(1)
}

/// Reconnection policy (H2): capped exponential backoff with up to
/// +100% uniform jitter per attempt. The default is unlimited attempts
/// (a node's job is to keep the mesh up); `max_attempts` bounds it for
/// tests/embedders that prefer to give up.
#[derive(Clone, Copy, Debug)]
pub struct ReconnectConfig {
    /// Delay before the first re-dial.
    pub initial: Duration,
    /// Backoff multiplier per failed attempt.
    pub factor: f64,
    /// Backoff ceiling.
    pub cap: Duration,
    /// `None` = retry forever (the default).
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            factor: 2.0,
            cap: Duration::from_secs(5),
            max_attempts: None,
        }
    }
}

/// Drop/reject/reconnect counters (H2). Every guard that drops a frame
/// or a connection increments exactly one counter — a silent drop is a
/// bug. Snapshot via [`Node::metrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeshMetrics {
    /// Unknown sender or bad §10.2/echo signature.
    pub dropped_bad_signature: u64,
    /// P2P frame addressed to a different node.
    pub dropped_misrouted: u64,
    /// Connection dropped after exceeding the per-connection rate cap.
    pub dropped_rate_limited: u64,
    /// Frame exceeding its variant's size bound (`wire::FrameBound`).
    pub dropped_oversize: u64,
    /// Frame dropped because the bounded mailbox was full.
    pub dropped_inbox_full: u64,
    /// Accepted socket dropped over the listener accept-rate cap.
    pub accepts_rate_limited: u64,
    /// mTLS handshake rejected (unpinned/plaintext/timeout/oversubscribed).
    pub handshake_rejects: u64,
    /// Successful reconnections of an outgoing connection.
    pub reconnects: u64,
}

/// A framed-message stream: plain TCP, or TLS 1.3 over TCP (M3c). The
/// wire format inside the stream is identical either way.
pub(crate) trait IoStream: Read + Write + Send {
    /// Socket-level read/write timeouts (H2). Plain TCP maps to
    /// `TcpStream::set_{read,write}_timeout`; rustls `StreamOwned`
    /// delegates to the underlying socket.
    fn set_io_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()>;
}

impl IoStream for TcpStream {
    fn set_io_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(read)?;
        self.set_write_timeout(write)
    }
}

impl IoStream for StreamOwned<ClientConnection, TcpStream> {
    fn set_io_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.sock.set_io_timeouts(read, write)
    }
}

impl IoStream for StreamOwned<ServerConnection, TcpStream> {
    fn set_io_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.sock.set_io_timeouts(read, write)
    }
}

pub(crate) type BoxedStream = Box<dyn IoStream>;

/// Shared per-node state: the outgoing half of the mesh plus the keys.
pub(crate) struct NodeShared<M> {
    id: PartyId,
    key: SigningKey,
    registry: BTreeMap<PartyId, VerifyingKey>,
    /// Outgoing connections, one per peer (replaced on reconnect).
    out: Mutex<BTreeMap<PartyId, Arc<Mutex<BoxedStream>>>>,
    /// Peer dial addresses, for reconnection after startup (H2).
    peers: Mutex<BTreeMap<PartyId, SocketAddr>>,
    /// Peers with a reconnect task already running.
    reconnecting: Mutex<BTreeSet<PartyId>>,
    /// Reconnection policy (H2).
    reconnect: Mutex<ReconnectConfig>,
    /// Per-session-id journal of every message this node SENT for
    /// in-flight sessions (H2 re-sync: re-sent in order on reconnect).
    journal: Mutex<BTreeMap<Vec<u8>, Vec<WireMessage<M>>>>,
    /// Broadcast slots this node already echoed.
    echoed: Mutex<BTreeSet<SlotKey>>,
    /// The mailbox every verified message is delivered to.
    inbox: SyncSender<Received<M>>,
    /// Deliver this node's own echoes to its own mailbox (M2 per-node
    /// acceptor; see the module docs).
    self_echo_loopback: Mutex<bool>,
    /// Artificial per-link send delay (benchmarks; 0 = off).
    send_delay: Mutex<Duration>,
    /// M3c mTLS material (None = plain TCP, the localhost default).
    tls: Option<Arc<CommitteeTls>>,
    /// Set by [`Node::shutdown`]: every loop in this module exits.
    shutdown: AtomicBool,
    /// Tracked thread handles (accept, readers, reconnectors), joined
    /// by [`Node::shutdown`].
    handles: Mutex<Vec<JoinHandle<()>>>,
    /// Drop/reject counters (H2).
    metrics: Mutex<MeshMetrics>,
    /// mTLS handshakes currently running (H2 concurrency cap).
    handshakes: AtomicUsize,
}

impl<M> NodeShared<M> {
    fn bump(&self, f: impl Fn(&mut MeshMetrics)) {
        f(&mut self.metrics.lock().expect("mesh mutex poisoned"));
    }
}

/// One node of the full mesh: a listener plus one outgoing connection
/// to every peer. [`Node::shutdown`] (also run on `Drop`) stops the
/// accept loop, closes the outgoing connections, and joins the tracked
/// threads with a deadline.
pub struct Node<M> {
    id: PartyId,
    local: SocketAddr,
    pub(crate) shared: Arc<NodeShared<M>>,
}

impl<M: Clone + Encode + Decode + FrameBound + Send + 'static> Node<M> {
    /// Bind the listener and start the accept loop. Peer connections are
    /// established by [`Node::connect`] once every node of the committee
    /// is bound. Plain TCP (the localhost default); [`Node::bind_tls`]
    /// adds M3c mTLS. The mailbox is bounded ([`INBOX_BOUND`]): a full
    /// mailbox drops + counts frames rather than growing without limit.
    pub fn bind(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: SyncSender<Received<M>>,
    ) -> io::Result<Self> {
        Self::bind_inner(id, bind, key, registry, inbox, None)
    }

    /// [`Node::bind`] with M3c mTLS on every connection (SPEC §13.1):
    /// outgoing connections present this node's certificate and accept
    /// only the pinned certificate of the expected peer; incoming
    /// connections must present a pinned committee certificate. There
    /// is no plaintext fallback once TLS is configured.
    pub fn bind_tls(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: SyncSender<Received<M>>,
        tls: Arc<CommitteeTls>,
    ) -> io::Result<Self> {
        Self::bind_inner(id, bind, key, registry, inbox, Some(tls))
    }

    fn bind_inner(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: SyncSender<Received<M>>,
        tls: Option<Arc<CommitteeTls>>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        let local = listener.local_addr()?;
        let shared = Arc::new(NodeShared {
            id,
            key: SigningKey::from(key),
            registry,
            out: Mutex::new(BTreeMap::new()),
            peers: Mutex::new(BTreeMap::new()),
            reconnecting: Mutex::new(BTreeSet::new()),
            reconnect: Mutex::new(ReconnectConfig::default()),
            journal: Mutex::new(BTreeMap::new()),
            echoed: Mutex::new(BTreeSet::new()),
            inbox,
            self_echo_loopback: Mutex::new(false),
            send_delay: Mutex::new(Duration::ZERO),
            tls,
            shutdown: AtomicBool::new(false),
            handles: Mutex::new(Vec::new()),
            metrics: Mutex::new(MeshMetrics::default()),
            handshakes: AtomicUsize::new(0),
        });
        let accept_shared = Arc::clone(&shared);
        let handle = thread::spawn(move || accept_loop(listener, accept_shared));
        shared
            .handles
            .lock()
            .expect("mesh mutex poisoned")
            .push(handle);
        Ok(Self { id, local, shared })
    }

    /// This node's id.
    pub fn id(&self) -> PartyId {
        self.id
    }

    /// The address the listener actually bound (with port 0: the
    /// ephemeral port the OS picked).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Deliver this node's own echoes to its own mailbox (M2 per-node
    /// acceptor mode; see the module docs). Off by default — M1's
    /// orchestrator acceptor counts echoes globally and must NOT see
    /// duplicates.
    pub fn set_self_echo_loopback(&self, on: bool) {
        *self.shared.self_echo_loopback.lock().expect("mesh mutex") = on;
    }

    /// Artificial per-link send delay (benchmarks; simulated WAN).
    pub fn set_send_delay(&self, delay: Duration) {
        *self.shared.send_delay.lock().expect("mesh mutex") = delay;
    }

    /// The reconnection policy (H2; default [`ReconnectConfig::default`]
    /// = unlimited retries, 100 ms → 5 s capped backoff + jitter).
    pub fn set_reconnect(&self, cfg: ReconnectConfig) {
        *self.shared.reconnect.lock().expect("mesh mutex") = cfg;
    }

    /// A snapshot of the drop/reject/reconnect counters (H2).
    pub fn metrics(&self) -> MeshMetrics {
        *self.shared.metrics.lock().expect("mesh mutex poisoned")
    }

    /// Drop the journal entries of a FINISHED session (H2): `sid_prefix`
    /// matches the session's sid and every derived sub-session sid (the
    /// drivers build them by suffix concatenation, e.g. `sid ‖ "/t1"`).
    /// In-flight sessions must NOT be retired — their journal is the
    /// reconnect re-sync state.
    pub(crate) fn retire_session(&self, sid_prefix: &[u8]) {
        self.shared
            .journal
            .lock()
            .expect("mesh mutex poisoned")
            .retain(|sid, _| !sid.starts_with(sid_prefix));
    }

    /// Open the outgoing connection to every peer in `addrs` (skipping
    /// self), retrying with backoff until the whole mesh is up
    /// (localhost scale: peers are expected to come up). With M3c TLS
    /// configured, each connection runs the mTLS client handshake
    /// pinned to the EXPECTED peer's certificate; a handshake failure
    /// fails the whole connect (no plaintext fallback). The peer
    /// addresses are remembered for post-startup reconnection (H2).
    pub fn connect(&self, addrs: &[(PartyId, SocketAddr)]) -> io::Result<()> {
        for &(peer, addr) in addrs {
            if peer == self.id {
                continue;
            }
            self.shared
                .peers
                .lock()
                .expect("mesh mutex poisoned")
                .insert(peer, addr);
            // Startup retry/backoff: the committee is expected to come
            // up (localhost scale). TCP connect failures retry; an mTLS
            // handshake failure fails the whole connect (no fallback).
            let mut last_err = None;
            let boxed = {
                let mut attempt = None;
                for _ in 0..100 {
                    match dial(&self.shared, peer, addr) {
                        Ok(b) => {
                            attempt = Some(b);
                            break;
                        }
                        Err(e) => {
                            last_err = Some(e);
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
                match attempt {
                    Some(b) => b,
                    None => return Err(last_err.expect("at least one connect attempt")),
                }
            };
            self.shared
                .out
                .lock()
                .expect("mesh mutex poisoned")
                .insert(peer, Arc::new(Mutex::new(boxed)));
        }
        Ok(())
    }

    /// Send one wire message to one peer (P2P entry point). The message
    /// is journaled BEFORE the write is attempted (H2: a failed write
    /// triggers reconnection and the journal re-sync re-delivers it).
    pub(crate) fn send_to(&self, to: PartyId, msg: &WireMessage<M>) {
        journal_push(&self.shared, msg);
        send_raw(&self.shared, to, msg);
    }

    /// Send one wire message to every peer (broadcast/echo entry point;
    /// journaled once, H2).
    pub(crate) fn send_all(&self, msg: &WireMessage<M>) {
        send_all(&self.shared, msg);
    }

    /// TEST HOOK (H2): drop the outgoing connection to `peer` and start
    /// the reconnector, simulating a mid-session link failure. The
    /// journal re-sync re-delivers in-flight messages.
    #[doc(hidden)]
    pub fn debug_drop_outgoing(&self, peer: PartyId) {
        self.shared
            .out
            .lock()
            .expect("mesh mutex poisoned")
            .remove(&peer);
        kick_reconnect(&self.shared, peer);
    }
}

impl<M> Node<M> {
    /// Clean shutdown (H2): stop accepting, close the outgoing
    /// connections (peer readers see EOF), signal every reader and
    /// reconnect task, and join the tracked threads with a 5 s
    /// deadline. Idempotent; also run on `Drop`. Threads that ignore
    /// the deadline are logged and detached (std cannot kill threads).
    pub fn shutdown(&self) {
        if self.shared.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        // Unblock the accept loop's `incoming()` wait.
        let _ = TcpStream::connect(self.local);
        // Close the outgoing connections: sends fail fast (no reconnect
        // — the flag is set) and the peers' readers see EOF.
        let out = std::mem::take(&mut *self.shared.out.lock().expect("mesh mutex"));
        drop(out);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let handles = self.shared.handles.lock().expect("mesh mutex");
                if handles.iter().all(|h| h.is_finished()) {
                    break;
                }
            }
            if Instant::now() > deadline {
                eprintln!(
                    "[node {}] shutdown: some mesh threads did not exit within 5 s (detached)",
                    self.id
                );
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut handles = self.shared.handles.lock().expect("mesh mutex");
        for h in handles.drain(..) {
            if h.is_finished() {
                let _ = h.join();
            }
            // Unfinished handles are dropped = detached (logged above).
        }
    }
}

impl<M> Drop for Node<M> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Journal one sent message under its session id (H2): broadcasts and
/// echoes key on the carried envelope's sid. Journaled BEFORE the
/// write is attempted, so a message lost to a dead connection is still
/// re-delivered by the reconnect re-sync.
fn journal_push<M: Clone>(shared: &NodeShared<M>, msg: &WireMessage<M>) {
    let sid = match msg {
        WireMessage::Original(se) => &se.envelope.sid,
        WireMessage::Echo { original, .. } => &original.envelope.sid,
    };
    shared
        .journal
        .lock()
        .expect("mesh mutex poisoned")
        .entry(sid.clone())
        .or_default()
        .push(msg.clone());
}

/// Dial one peer: TCP connect + nodelay + (M3c) the pinned mTLS client
/// handshake, then the H2 write timeout.
fn dial<M>(shared: &NodeShared<M>, peer: PartyId, addr: SocketAddr) -> io::Result<BoxedStream> {
    let stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    let boxed: BoxedStream = match &shared.tls {
        Some(tls) => Box::new(tls.client_handshake(peer, stream)?),
        None => Box::new(stream),
    };
    boxed.set_io_timeouts(None, Some(WRITE_TIMEOUT))?;
    Ok(boxed)
}

/// Start (at most) one reconnect task for `peer` (H2). No-op when the
/// peer was never connected, a task is already running, or the node is
/// shutting down.
fn kick_reconnect<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    shared: &Arc<NodeShared<M>>,
    peer: PartyId,
) {
    if shared.shutdown.load(Ordering::SeqCst) {
        return;
    }
    let addr = shared
        .peers
        .lock()
        .expect("mesh mutex poisoned")
        .get(&peer)
        .copied();
    let Some(addr) = addr else { return };
    if !shared
        .reconnecting
        .lock()
        .expect("mesh mutex poisoned")
        .insert(peer)
    {
        return;
    }
    let task = Arc::clone(shared);
    let handle = thread::spawn(move || {
        reconnect_loop(&task, peer, addr);
        task.reconnecting
            .lock()
            .expect("mesh mutex poisoned")
            .remove(&peer);
    });
    shared
        .handles
        .lock()
        .expect("mesh mutex poisoned")
        .push(handle);
}

/// The reconnect task (H2): capped exponential backoff + jitter; on
/// success installs the new connection and re-sends the journal of
/// every in-flight session (the re-sync — see the module docs).
fn reconnect_loop<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    shared: &Arc<NodeShared<M>>,
    peer: PartyId,
    addr: SocketAddr,
) {
    let cfg = *shared.reconnect.lock().expect("mesh mutex poisoned");
    let mut delay = cfg.initial;
    let mut attempt = 0u32;
    let mut rng = rand::thread_rng();
    loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        if cfg.max_attempts.is_some_and(|max| attempt >= max) {
            eprintln!(
                "[node {}] reconnect to {peer}: giving up after {attempt} attempts",
                shared.id
            );
            return;
        }
        attempt += 1;
        // Up to +100% jitter; sleep in slices so shutdown stays responsive.
        let jitter = Duration::from_millis(rng.gen_range(0..=delay.as_millis() as u64));
        let wake = Instant::now() + delay + jitter;
        while Instant::now() < wake {
            if shared.shutdown.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        match dial(shared, peer, addr) {
            Ok(boxed) => {
                eprintln!(
                    "[node {}] reconnected to {peer} (attempt {attempt})",
                    shared.id
                );
                shared
                    .out
                    .lock()
                    .expect("mesh mutex poisoned")
                    .insert(peer, Arc::new(Mutex::new(boxed)));
                shared.bump(|m| m.reconnects += 1);
                resend_journal(shared, peer);
                return;
            }
            Err(e) => {
                eprintln!("[node {}] reconnect to {peer} failed: {e}", shared.id);
                let next = delay.mul_f64(cfg.factor);
                delay = next.min(cfg.cap);
            }
        }
    }
}

/// Re-send every journaled (in-flight session) message to `peer`, in
/// original per-session order (H2 re-sync). A failure mid-resend
/// re-triggers the reconnector; the remaining messages stay journaled.
fn resend_journal<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    shared: &Arc<NodeShared<M>>,
    peer: PartyId,
) {
    let msgs: Vec<WireMessage<M>> = shared
        .journal
        .lock()
        .expect("mesh mutex poisoned")
        .values()
        .flatten()
        .cloned()
        .collect();
    for msg in &msgs {
        let conn = shared
            .out
            .lock()
            .expect("mesh mutex poisoned")
            .get(&peer)
            .cloned();
        let Some(c) = conn else {
            kick_reconnect(shared, peer);
            return;
        };
        let failed = match c.lock() {
            Ok(mut s) => write_frame(&mut *s, msg).is_err(),
            Err(_) => true,
        };
        if failed {
            kick_reconnect(shared, peer);
            return;
        }
    }
}

fn send_raw<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    shared: &Arc<NodeShared<M>>,
    to: PartyId,
    msg: &WireMessage<M>,
) {
    if shared.shutdown.load(Ordering::SeqCst) {
        return;
    }
    let conn = {
        shared
            .out
            .lock()
            .expect("mesh mutex poisoned")
            .get(&to)
            .cloned()
    };
    let Some(c) = conn else {
        eprintln!("[node {}] no connection to {to}", shared.id);
        kick_reconnect(shared, to);
        return;
    };
    let delay = *shared.send_delay.lock().expect("mesh mutex");
    if delay.is_zero() {
        match c.lock() {
            Ok(mut s) => {
                if let Err(e) = write_frame(&mut *s, msg) {
                    eprintln!("[node {}] send to {to} failed: {e}", shared.id);
                    kick_reconnect(shared, to);
                }
            }
            Err(_) => kick_reconnect(shared, to),
        }
        return;
    }
    // Delayed send (simulated link latency): encode once, write after the
    // sleep on a helper thread so the sender is not blocked.
    let frame = match frame_bytes(msg) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[node {}] encode for {to} failed: {e}", shared.id);
            return;
        }
    };
    let id = shared.id;
    let task = Arc::clone(shared);
    thread::spawn(move || {
        thread::sleep(delay);
        match c.lock() {
            Ok(mut s) => {
                if let Err(e) = s.write_all(&frame) {
                    eprintln!("[node {id}] send to {to} failed: {e}");
                    kick_reconnect(&task, to);
                }
            }
            Err(_) => kick_reconnect(&task, to),
        }
    });
}

fn send_all<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    shared: &Arc<NodeShared<M>>,
    msg: &WireMessage<M>,
) {
    journal_push(shared, msg);
    // Broadcast to the union of the connected peers and the dial set —
    // a peer whose connection dropped (reconnect pending) gets its
    // reconnector kicked so the journaled message is re-delivered.
    let connected: Vec<PartyId> = shared
        .out
        .lock()
        .expect("mesh mutex poisoned")
        .keys()
        .copied()
        .collect();
    let dial_peers: Vec<PartyId> = shared
        .peers
        .lock()
        .expect("mesh mutex poisoned")
        .keys()
        .copied()
        .collect();
    let mut seen = BTreeSet::new();
    for p in connected.into_iter().chain(dial_peers) {
        if seen.insert(p) {
            send_raw(shared, p, msg);
        }
    }
}

fn accept_loop<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    listener: TcpListener,
    shared: Arc<NodeShared<M>>,
) {
    // H2 listener guards: an accept-rate window (cheap early filter for
    // pokes/scans) and an mTLS handshake concurrency cap.
    let accept_cap = accept_cap_per_second(shared.registry.len());
    let hs_cap = handshake_cap(shared.registry.len());
    let mut window = (Instant::now(), 0u32);
    for stream in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        match stream {
            Ok(s) => {
                if window.0.elapsed() >= Duration::from_secs(1) {
                    window = (Instant::now(), 0);
                }
                window.1 += 1;
                if window.1 > accept_cap {
                    shared.bump(|m| m.accepts_rate_limited += 1);
                    eprintln!(
                        "[node {}] accept rate cap exceeded: dropping connection",
                        shared.id
                    );
                    continue;
                }
                let task = Arc::clone(&shared);
                let reader = thread::spawn(move || {
                    // M3c: the mTLS server handshake runs BEFORE any
                    // frame is read; an unpinned/plaintext peer is
                    // rejected here and never reaches the reader loop.
                    // H2: the handshake is concurrency-capped and runs
                    // under `tls::HANDSHAKE_TIMEOUT`.
                    let boxed: BoxedStream = match &task.tls {
                        Some(tls) => {
                            let in_flight = task.handshakes.fetch_add(1, Ordering::SeqCst) + 1;
                            if in_flight > hs_cap {
                                task.handshakes.fetch_sub(1, Ordering::SeqCst);
                                task.bump(|m| m.handshake_rejects += 1);
                                eprintln!(
                                    "[node {}] tls: handshake concurrency cap — dropping peer",
                                    task.id
                                );
                                return;
                            }
                            let result = tls.server_handshake(s);
                            task.handshakes.fetch_sub(1, Ordering::SeqCst);
                            match result {
                                Ok((stream, peer)) => {
                                    eprintln!(
                                        "[node {}] tls: peer authenticated as party {peer}",
                                        task.id
                                    );
                                    Box::new(stream)
                                }
                                Err(e) => {
                                    task.bump(|m| m.handshake_rejects += 1);
                                    eprintln!("[node {}] tls: rejecting peer: {e}", task.id);
                                    return;
                                }
                            }
                        }
                        None => Box::new(s),
                    };
                    reader_loop(boxed, &task)
                });
                shared
                    .handles
                    .lock()
                    .expect("mesh mutex poisoned")
                    .push(reader);
            }
            Err(e) => {
                if shared.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                eprintln!("[node {}] accept failed: {e}", shared.id)
            }
        }
    }
}

fn reader_loop<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    mut stream: BoxedStream,
    shared: &Arc<NodeShared<M>>,
) {
    // H2: bounded blocking reads (shutdown poll, NOT a liveness
    // timeout), per-connection rate window, per-variant frame bounds.
    if let Err(e) = stream.set_io_timeouts(Some(READ_POLL), None) {
        eprintln!("[node {}] setting read timeout failed: {e}", shared.id);
        return;
    }
    let n = shared.registry.len();
    let max_frame = WireMessage::<M>::max_frame(n);
    let rate_cap = rate_cap_per_second(n);
    let mut window = (Instant::now(), 0u32);
    loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        if window.0.elapsed() >= Duration::from_secs(1) {
            window = (Instant::now(), 0);
        }
        match read_frame(&mut stream, max_frame) {
            Ok(Some((msg, len))) => {
                window.1 += 1;
                if window.1 > rate_cap {
                    shared.bump(|m| m.dropped_rate_limited += 1);
                    eprintln!(
                        "[node {}] per-connection rate cap exceeded: dropping connection",
                        shared.id
                    );
                    return;
                }
                if len as u64 > msg.variant_max(n) {
                    shared.bump(|m| m.dropped_oversize += 1);
                    eprintln!(
                        "[node {}] frame exceeds its variant's size bound: dropping connection",
                        shared.id
                    );
                    return;
                }
                handle(msg, shared);
            }
            Ok(None) => return, // peer closed the connection
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue; // READ_POLL tick: re-check the shutdown flag
            }
            Err(e) => {
                if !shared.shutdown.load(Ordering::SeqCst) {
                    eprintln!("[node {}] dropping connection: {e}", shared.id);
                }
                return;
            }
        }
    }
}

/// The receive path: verify, apply the first-echo rule, deliver to the
/// mailbox. Signature/consistency checks are never optional.
fn handle<M: Clone + Encode + Decode + FrameBound + Send + 'static>(
    msg: WireMessage<M>,
    shared: &Arc<NodeShared<M>>,
) {
    if !msg.verify(&shared.registry) {
        shared.bump(|m| m.dropped_bad_signature += 1);
        eprintln!(
            "[node {}] dropped message: unknown sender or bad signature",
            shared.id
        );
        return;
    }
    let deliver = |received: Received<M>| {
        if shared.inbox.try_send(received).is_err() {
            shared.bump(|m| m.dropped_inbox_full += 1);
        }
    };
    match msg {
        WireMessage::Original(se) => {
            if let Some(to) = se.envelope.to {
                // P2P is not echoed; drop misrouted copies.
                if to != shared.id {
                    shared.bump(|m| m.dropped_misrouted += 1);
                    eprintln!("[node {}] dropped misrouted p2p for {to}", shared.id);
                    return;
                }
            } else {
                // §4.7: echo the FIRST valid value per broadcast slot.
                let slot: SlotKey = (
                    se.envelope.sid.clone(),
                    se.envelope.phase,
                    se.envelope.round,
                    se.envelope.from,
                );
                let first = shared
                    .echoed
                    .lock()
                    .expect("mesh mutex poisoned")
                    .insert(slot);
                if first {
                    let echo = WireMessage::echo(shared.id, se.clone(), &shared.key);
                    send_all(shared, &echo);
                    // M2 per-node acceptor mode: count this node's own
                    // echo in its own mailbox (M1's orchestrator acceptor
                    // saw it through the peers' mailboxes).
                    if *shared.self_echo_loopback.lock().expect("mesh mutex") {
                        deliver(Received::Echo {
                            echoer: shared.id,
                            original: se.clone(),
                        });
                    }
                }
            }
            deliver(Received::Original(se));
        }
        WireMessage::Echo {
            echoer, original, ..
        } => {
            deliver(Received::Echo { echoer, original });
        }
    }
}
