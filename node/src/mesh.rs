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

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use ohm_ecdsa::transport::{Decode, Encode};
use ohm_ecdsa::{PartyId, Phase};

use crate::tls::CommitteeTls;
use crate::wire::{frame_bytes, read_frame, write_frame, Received, WireMessage};

/// A broadcast slot `(sid, phase, round, from)`: at most one echo per
/// node per slot (the §4.7 first-echo rule — an equivocating sender
/// cannot collect echoes for two different values from the same node).
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// A framed-message stream: plain TCP, or TLS 1.3 over TCP (M3c). The
/// wire format inside the stream is identical either way.
pub(crate) trait IoStream: Read + Write + Send {}
impl<T: Read + Write + Send> IoStream for T {}
pub(crate) type BoxedStream = Box<dyn IoStream>;

/// Shared per-node state: the outgoing half of the mesh plus the keys.
pub(crate) struct NodeShared<M> {
    id: PartyId,
    key: SigningKey,
    registry: BTreeMap<PartyId, VerifyingKey>,
    /// Outgoing connections, one per peer.
    out: Mutex<BTreeMap<PartyId, Arc<Mutex<BoxedStream>>>>,
    /// Broadcast slots this node already echoed.
    echoed: Mutex<BTreeSet<SlotKey>>,
    /// The mailbox every verified message is delivered to.
    inbox: Sender<Received<M>>,
    /// Deliver this node's own echoes to its own mailbox (M2 per-node
    /// acceptor; see the module docs).
    self_echo_loopback: Mutex<bool>,
    /// Artificial per-link send delay (benchmarks; 0 = off).
    send_delay: Mutex<Duration>,
    /// M3c mTLS material (None = plain TCP, the localhost default).
    tls: Option<Arc<CommitteeTls>>,
}

/// One node of the full mesh: a listener plus one outgoing connection to
/// every peer. Dropping the node closes its outgoing connections (peer
/// readers then see EOF); listener/reader threads are daemon-style and
/// exit with the process (M1 simplification — clean shutdown is M3).
pub struct Node<M> {
    id: PartyId,
    local: SocketAddr,
    pub(crate) shared: Arc<NodeShared<M>>,
}

impl<M: Clone + Encode + Decode + Send + 'static> Node<M> {
    /// Bind the listener and start the accept loop. Peer connections are
    /// established by [`Node::connect`] once every node of the committee
    /// is bound. Plain TCP (the localhost default); [`Node::bind_tls`]
    /// adds M3c mTLS.
    pub fn bind(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: Sender<Received<M>>,
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
        inbox: Sender<Received<M>>,
        tls: Arc<CommitteeTls>,
    ) -> io::Result<Self> {
        Self::bind_inner(id, bind, key, registry, inbox, Some(tls))
    }

    fn bind_inner(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: Sender<Received<M>>,
        tls: Option<Arc<CommitteeTls>>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(bind)?;
        let local = listener.local_addr()?;
        let shared = Arc::new(NodeShared {
            id,
            key: SigningKey::from(key),
            registry,
            out: Mutex::new(BTreeMap::new()),
            echoed: Mutex::new(BTreeSet::new()),
            inbox,
            self_echo_loopback: Mutex::new(false),
            send_delay: Mutex::new(Duration::ZERO),
            tls,
        });
        let accept_shared = Arc::clone(&shared);
        thread::spawn(move || accept_loop(listener, accept_shared));
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

    /// Open the outgoing connection to every peer in `addrs` (skipping
    /// self), retrying with backoff until the whole mesh is up
    /// (localhost scale: peers are expected to come up). With M3c TLS
    /// configured, each connection runs the mTLS client handshake
    /// pinned to the EXPECTED peer's certificate; a handshake failure
    /// fails the whole connect (no plaintext fallback).
    pub fn connect(&self, addrs: &[(PartyId, SocketAddr)]) -> io::Result<()> {
        for &(peer, addr) in addrs {
            if peer == self.id {
                continue;
            }
            let stream = connect_retry(addr)?;
            stream.set_nodelay(true)?;
            let boxed: BoxedStream = match &self.shared.tls {
                Some(tls) => Box::new(tls.client_handshake(peer, stream)?),
                None => Box::new(stream),
            };
            self.shared
                .out
                .lock()
                .expect("mesh mutex poisoned")
                .insert(peer, Arc::new(Mutex::new(boxed)));
        }
        Ok(())
    }

    /// Send one wire message to one peer. A dead peer is logged, not
    /// fatal: the round's timeout policy surfaces it (§13.1).
    pub(crate) fn send_to(&self, to: PartyId, msg: &WireMessage<M>) {
        send_to(&self.shared, to, msg);
    }

    /// Send one wire message to every peer.
    pub(crate) fn send_all(&self, msg: &WireMessage<M>) {
        send_all(&self.shared, msg);
    }
}

fn send_to<M: Clone + Encode + Send + 'static>(
    shared: &NodeShared<M>,
    to: PartyId,
    msg: &WireMessage<M>,
) {
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
        return;
    };
    let delay = *shared.send_delay.lock().expect("mesh mutex");
    if delay.is_zero() {
        if let Ok(mut s) = c.lock() {
            if let Err(e) = write_frame(&mut *s, msg) {
                eprintln!("[node {}] send to {to} failed: {e}", shared.id);
            }
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
    thread::spawn(move || {
        thread::sleep(delay);
        if let Ok(mut s) = c.lock() {
            if let Err(e) = s.write_all(&frame) {
                eprintln!("[node {id}] send to {to} failed: {e}");
            }
        }
    });
}

fn send_all<M: Clone + Encode + Send + 'static>(shared: &NodeShared<M>, msg: &WireMessage<M>) {
    let peers: Vec<PartyId> = shared
        .out
        .lock()
        .expect("mesh mutex poisoned")
        .keys()
        .copied()
        .collect();
    for p in peers {
        send_to(shared, p, msg);
    }
}

/// Startup connect with retry/backoff (SPEC §13.1 leaves reconnection
/// policy to the deployment; M1 retries at startup only, localhost
/// scale).
fn connect_retry(addr: SocketAddr) -> io::Result<TcpStream> {
    let mut last_err = None;
    for _ in 0..100 {
        match TcpStream::connect(addr) {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    Err(last_err.expect("at least one connect attempt"))
}

fn accept_loop<M: Clone + Encode + Decode + Send + 'static>(
    listener: TcpListener,
    shared: Arc<NodeShared<M>>,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    // M3c: the mTLS server handshake runs BEFORE any
                    // frame is read; an unpinned/plaintext peer is
                    // rejected here and never reaches the reader loop.
                    let boxed: BoxedStream = match &shared.tls {
                        Some(tls) => match tls.server_handshake(s) {
                            Ok((stream, peer)) => {
                                eprintln!(
                                    "[node {}] tls: peer authenticated as party {peer}",
                                    shared.id
                                );
                                Box::new(stream)
                            }
                            Err(e) => {
                                eprintln!("[node {}] tls: rejecting peer: {e}", shared.id);
                                return;
                            }
                        },
                        None => Box::new(s),
                    };
                    reader_loop(boxed, shared)
                });
            }
            Err(e) => eprintln!("[node {}] accept failed: {e}", shared.id),
        }
    }
}

fn reader_loop<M: Clone + Encode + Decode + Send + 'static>(
    mut stream: BoxedStream,
    shared: Arc<NodeShared<M>>,
) {
    loop {
        match read_frame(&mut stream) {
            Ok(Some(msg)) => handle(msg, &shared),
            Ok(None) => return, // peer closed the connection
            Err(e) => {
                eprintln!("[node {}] dropping connection: {e}", shared.id);
                return;
            }
        }
    }
}

/// The receive path: verify, apply the first-echo rule, deliver to the
/// mailbox. Signature/consistency checks are never optional.
fn handle<M: Clone + Encode + Send + 'static>(msg: WireMessage<M>, shared: &NodeShared<M>) {
    if !msg.verify(&shared.registry) {
        eprintln!(
            "[node {}] dropped message: unknown sender or bad signature",
            shared.id
        );
        return;
    }
    match msg {
        WireMessage::Original(se) => {
            if let Some(to) = se.envelope.to {
                // P2P is not echoed; drop misrouted copies.
                if to != shared.id {
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
                        let _ = shared.inbox.send(Received::Echo {
                            echoer: shared.id,
                            original: se.clone(),
                        });
                    }
                }
            }
            let _ = shared.inbox.send(Received::Original(se));
        }
        WireMessage::Echo {
            echoer, original, ..
        } => {
            let _ = shared.inbox.send(Received::Echo { echoer, original });
        }
    }
}
