//! The full-mesh TCP layer (SPEC §13.1): `std::net` with blocking
//! threads, no external runtime (M1; tokio is M2).
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

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use ohm_ecdsa::{PartyId, Phase};

use crate::wire::{read_frame, write_frame, Received, WireMessage};

/// A broadcast slot `(sid, phase, round, from)`: at most one echo per
/// node per slot (the §4.7 first-echo rule — an equivocating sender
/// cannot collect echoes for two different values from the same node).
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// Shared per-node state: the outgoing half of the mesh plus the keys.
pub(crate) struct NodeShared {
    id: PartyId,
    key: SigningKey,
    registry: BTreeMap<PartyId, VerifyingKey>,
    /// Outgoing connections, one per peer.
    out: Mutex<BTreeMap<PartyId, Arc<Mutex<TcpStream>>>>,
    /// Broadcast slots this node already echoed.
    echoed: Mutex<BTreeSet<SlotKey>>,
    /// The mailbox every verified message is delivered to.
    inbox: Sender<Received>,
}

/// One node of the full mesh: a listener plus one outgoing connection to
/// every peer. Dropping the node closes its outgoing connections (peer
/// readers then see EOF); listener/reader threads are daemon-style and
/// exit with the process (M1 simplification — clean shutdown is M2).
pub struct Node {
    id: PartyId,
    local: SocketAddr,
    pub(crate) shared: Arc<NodeShared>,
}

impl Node {
    /// Bind the listener and start the accept loop. Peer connections are
    /// established by [`Node::connect`] once every node of the committee
    /// is bound.
    pub fn bind(
        id: PartyId,
        bind: SocketAddr,
        key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        inbox: Sender<Received>,
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

    /// Open the outgoing connection to every peer in `addrs` (skipping
    /// self), retrying with backoff until the whole mesh is up
    /// (localhost scale: peers are expected to come up).
    pub fn connect(&self, addrs: &[(PartyId, SocketAddr)]) -> io::Result<()> {
        for &(peer, addr) in addrs {
            if peer == self.id {
                continue;
            }
            let stream = connect_retry(addr)?;
            stream.set_nodelay(true)?;
            self.shared
                .out
                .lock()
                .expect("mesh mutex poisoned")
                .insert(peer, Arc::new(Mutex::new(stream)));
        }
        Ok(())
    }

    /// Send one wire message to one peer. A dead peer is logged, not
    /// fatal: the round's timeout policy surfaces it (§13.1).
    pub(crate) fn send_to(&self, to: PartyId, msg: &WireMessage) {
        send_to(&self.shared, to, msg);
    }

    /// Send one wire message to every peer.
    pub(crate) fn send_all(&self, msg: &WireMessage) {
        send_all(&self.shared, msg);
    }
}

fn send_to(shared: &NodeShared, to: PartyId, msg: &WireMessage) {
    let conn = {
        shared
            .out
            .lock()
            .expect("mesh mutex poisoned")
            .get(&to)
            .cloned()
    };
    match conn {
        Some(c) => {
            if let Ok(mut s) = c.lock() {
                if let Err(e) = write_frame(&mut *s, msg) {
                    eprintln!("[node {}] send to {to} failed: {e}", shared.id);
                }
            }
        }
        None => eprintln!("[node {}] no connection to {to}", shared.id),
    }
}

fn send_all(shared: &NodeShared, msg: &WireMessage) {
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

fn accept_loop(listener: TcpListener, shared: Arc<NodeShared>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let shared = Arc::clone(&shared);
                thread::spawn(move || reader_loop(s, shared));
            }
            Err(e) => eprintln!("[node {}] accept failed: {e}", shared.id),
        }
    }
}

fn reader_loop(mut stream: TcpStream, shared: Arc<NodeShared>) {
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
fn handle(msg: WireMessage, shared: &NodeShared) {
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
