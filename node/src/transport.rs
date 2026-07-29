//! [`MeshTransport`]: the core `Transport<SignedEnvelope<DkgMessage>>`
//! trait over the real-TCP mesh, with §4.7 echo-broadcast acceptance.
//!
//! Acceptance rule (SPEC §4.7, "accept `m` for `i` upon `⌈(n+1)/2⌉`
//! consistent echoes"): a broadcast value from sender `i` is accepted
//! once `⌈(n+1)/2⌉` DISTINCT parties OTHER than `i` echoed it. The
//! sender's own copy is never counted — counting it would let an
//! equivocating sender reach the majority for two different values at
//! `n = 3` (its own copy plus one echo each), breaking the §4.7
//! consistency property. Together with the mesh's first-echo rule this
//! yields:
//!
//! * consistency — two different values cannot both collect
//!   `⌈(n+1)/2⌉` echoes from honest parties (their echo sets would have
//!   to overlap in an honest party that echoed twice);
//! * validity — an accepted value carries the sender's §10.2 signature,
//!   verified before echoing and before counting.
//!
//! Round completeness: `accepted_broadcasts` / `accepted_p2p` block until
//! every committee member has an accepted value for the round (the DKG
//! driver pattern: one message per party per round), up to a generous
//! timeout. On timeout the PARTIAL accepted set is returned and logged;
//! the DKG then fails closed with "incomplete message sets" — a wrong
//! key can never result. Timeout policy is a deployment concern
//! (SPEC §13.1).
//!
//! M1 is the reference-orchestration pattern: one process holds every
//! party's transport key and drives all parties through
//! `drive_dkg_signed` (as the core drives `SimTransport`). P2P messages
//! travel only between dealer and addressee on the wire; the driver sees
//! them because every node's mailbox feeds this one acceptor. Per-party
//! process separation is M2.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use ohm_ecdsa::transport::{DkgMessage, Encode, Envelope, SignedEnvelope, Transport};
use ohm_ecdsa::{PartyId, Phase};

use crate::mesh::Node;
use crate::wire::{Received, WireMessage};

/// Default per-round timeout (localhost rounds complete in milliseconds).
pub const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// `⌈(n+1)/2⌉` — the §4.7 acceptance threshold.
fn majority(n: usize) -> usize {
    (n + 2) / 2
}

/// Broadcast slot key `(sid, phase, round, from)`; for P2P the last
/// component is the addressee instead.
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// One distinct signed broadcast payload and the parties that echoed it.
struct Candidate {
    env: SignedEnvelope<DkgMessage>,
    echoers: BTreeSet<PartyId>,
}

/// The echo-broadcast acceptor: dedups by slot and payload, counts
/// distinct echoers, decides acceptance. Fed by every node's mailbox
/// (orchestrator pattern — one acceptor yields one consistent accepted
/// set, the `SimTransport` analog of §13.2).
struct Acceptor {
    majority: usize,
    /// slot → payload-bytes → candidate (equivocation-safe: payloads are
    /// tracked separately, first to majority wins).
    bcast: BTreeMap<SlotKey, BTreeMap<Vec<u8>, Candidate>>,
    /// (sid, phase, round, to) → sender → message.
    p2p: BTreeMap<SlotKey, BTreeMap<PartyId, SignedEnvelope<DkgMessage>>>,
}

impl Acceptor {
    fn new(n: usize) -> Self {
        Self {
            majority: majority(n),
            bcast: BTreeMap::new(),
            p2p: BTreeMap::new(),
        }
    }

    fn process(&mut self, msg: Received<DkgMessage>) {
        match msg {
            Received::Original(se) => match se.envelope.to {
                None => {
                    let (key, payload) = slot_and_payload(&se);
                    self.bcast
                        .entry(key)
                        .or_default()
                        .entry(payload)
                        .or_insert_with(|| Candidate {
                            env: se,
                            echoers: BTreeSet::new(),
                        });
                }
                Some(to) => {
                    let key = (
                        se.envelope.sid.clone(),
                        se.envelope.phase,
                        se.envelope.round,
                        to,
                    );
                    self.p2p
                        .entry(key)
                        .or_default()
                        .entry(se.envelope.from)
                        .or_insert(se);
                }
            },
            Received::Echo { echoer, original } => {
                let (key, payload) = slot_and_payload(&original);
                let candidate = self
                    .bcast
                    .entry(key)
                    .or_default()
                    .entry(payload)
                    .or_insert_with(|| Candidate {
                        env: original,
                        echoers: BTreeSet::new(),
                    });
                candidate.echoers.insert(echoer);
            }
        }
    }

    /// The accepted broadcast set of one round (only values that reached
    /// the echo majority), plus whether every member has one.
    #[allow(clippy::type_complexity)]
    fn bcast_set(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        ids: &[PartyId],
    ) -> (
        BTreeMap<PartyId, Envelope<SignedEnvelope<DkgMessage>>>,
        bool,
    ) {
        let mut out = BTreeMap::new();
        for &id in ids {
            let key = (sid.to_vec(), phase, round, id);
            let accepted = self
                .bcast
                .get(&key)
                .and_then(|m| m.values().find(|c| c.echoers.len() >= self.majority));
            if let Some(c) = accepted {
                out.insert(
                    id,
                    Envelope::broadcast(sid, phase, round, id, c.env.clone()),
                );
            }
        }
        let complete = out.len() == ids.len();
        (out, complete)
    }

    /// The messages of one round addressed to `to`, plus whether every
    /// member's message arrived.
    #[allow(clippy::type_complexity)]
    fn p2p_set(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
        ids: &[PartyId],
    ) -> (
        BTreeMap<PartyId, Envelope<SignedEnvelope<DkgMessage>>>,
        bool,
    ) {
        let key = (sid.to_vec(), phase, round, to);
        let out: BTreeMap<_, _> = self
            .p2p
            .get(&key)
            .map(|m| {
                m.iter()
                    .map(|(&from, se)| {
                        (from, Envelope::p2p(sid, phase, round, from, to, se.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let complete = ids.iter().all(|id| out.contains_key(id));
        (out, complete)
    }
}

fn slot_and_payload(se: &SignedEnvelope<DkgMessage>) -> (SlotKey, Vec<u8>) {
    let key = (
        se.envelope.sid.clone(),
        se.envelope.phase,
        se.envelope.round,
        se.envelope.from,
    );
    let mut payload = Vec::new();
    se.encode(&mut payload);
    (key, payload)
}

/// The core [`Transport`] over the M1 mesh. Owns the committee's nodes
/// (keeping listeners and reader threads alive), the shared mailbox, and
/// the echo-broadcast acceptor.
pub struct MeshTransport {
    nodes: Vec<Node<DkgMessage>>,
    ids: Vec<PartyId>,
    inbox: Mutex<Receiver<Received<DkgMessage>>>,
    state: Mutex<Acceptor>,
    timeout: Duration,
}

impl MeshTransport {
    /// Bring up the full mesh: bind every node, then connect every pair
    /// (retry/backoff until the mesh is up). `keys` holds each party's
    /// transport keypair — required for echo signing and, in the
    /// orchestrator pattern, handed to the core's `SigningTransport` for
    /// envelope signing.
    pub fn start(
        parties: &[(PartyId, SocketAddr)],
        keys: &[(PartyId, SecretKey)],
        round_timeout: Duration,
    ) -> io::Result<Self> {
        let registry: BTreeMap<PartyId, VerifyingKey> = keys
            .iter()
            .map(|(p, sk)| (*p, *SigningKey::from(sk).verifying_key()))
            .collect();
        let (tx, rx) = mpsc::channel();
        // Phase 1: bind all listeners first so every address is known
        // (supports port 0 — the OS-assigned ports are collected here).
        let mut nodes = Vec::new();
        for &(id, bind) in parties {
            let key = keys
                .iter()
                .find(|(p, _)| p == &id)
                .map(|(_, sk)| sk)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing transport key")
                })?;
            nodes.push(Node::bind(id, bind, key, registry.clone(), tx.clone())?);
        }
        // Phase 2: full-mesh connect with startup retry/backoff.
        let addrs: Vec<(PartyId, SocketAddr)> =
            nodes.iter().map(|n| (n.id(), n.local_addr())).collect();
        for n in &nodes {
            n.connect(&addrs)?;
        }
        let ids: Vec<PartyId> = parties.iter().map(|&(id, _)| id).collect();
        Ok(Self {
            nodes,
            ids,
            inbox: Mutex::new(rx),
            state: Mutex::new(Acceptor::new(parties.len())),
            timeout: round_timeout,
        })
    }

    /// The addresses the nodes actually bound (with port 0 configs: the
    /// OS-assigned ephemeral ports).
    pub fn local_addrs(&self) -> Vec<(PartyId, SocketAddr)> {
        self.nodes
            .iter()
            .map(|n| (n.id(), n.local_addr()))
            .collect()
    }

    fn node(&self, id: PartyId) -> &Node<DkgMessage> {
        self.nodes
            .iter()
            .find(|n| n.id() == id)
            .expect("sender is a committee member")
    }

    /// Pull one mailbox message into the acceptor; `false` on timeout.
    fn pump(&self, deadline: Instant) -> bool {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match self
            .inbox
            .lock()
            .expect("mesh mutex poisoned")
            .recv_timeout(remaining)
        {
            Ok(msg) => {
                self.state.lock().expect("mesh mutex poisoned").process(msg);
                true
            }
            // Disconnection cannot happen: the senders are owned by
            // `self.nodes`. A timeout ends the wait.
            Err(_) => false,
        }
    }
}

impl Transport<SignedEnvelope<DkgMessage>> for MeshTransport {
    fn broadcast(&mut self, env: Envelope<SignedEnvelope<DkgMessage>>) {
        debug_assert!(env.to.is_none(), "broadcast envelope must have to == None");
        // Out over the wire; the value returns as verified echoes from
        // the peers and is accepted on the §4.7 majority.
        self.node(env.from)
            .send_all(&WireMessage::Original(env.payload));
    }

    fn send_p2p(&mut self, env: Envelope<SignedEnvelope<DkgMessage>>) {
        let to = env.to.expect("p2p envelope must have an addressee");
        if to == env.from {
            // The dealer's own share never leaves the node: deliver it
            // straight into the acceptor.
            self.state
                .lock()
                .expect("mesh mutex poisoned")
                .process(Received::Original(env.payload));
            return;
        }
        self.node(env.from)
            .send_to(to, &WireMessage::Original(env.payload));
    }

    fn accepted_broadcasts(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, Envelope<SignedEnvelope<DkgMessage>>> {
        let deadline = Instant::now() + self.timeout;
        loop {
            {
                let acc = self.state.lock().expect("mesh mutex poisoned");
                let (set, complete) = acc.bcast_set(sid, phase, round, &self.ids);
                if complete {
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[mesh] TIMEOUT waiting for {phase} round {round} broadcasts; \
                     returning the partial accepted set (timeout policy is a \
                     deployment concern, SPEC §13.1)"
                );
                let acc = self.state.lock().expect("mesh mutex poisoned");
                return acc.bcast_set(sid, phase, round, &self.ids).0;
            }
        }
    }

    fn accepted_p2p(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
    ) -> BTreeMap<PartyId, Envelope<SignedEnvelope<DkgMessage>>> {
        let deadline = Instant::now() + self.timeout;
        loop {
            {
                let acc = self.state.lock().expect("mesh mutex poisoned");
                let (set, complete) = acc.p2p_set(sid, phase, round, to, &self.ids);
                if complete {
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[mesh] TIMEOUT waiting for {phase} round {round} p2p to {to}; \
                     returning the partial accepted set (timeout policy is a \
                     deployment concern, SPEC §13.1)"
                );
                let acc = self.state.lock().expect("mesh mutex poisoned");
                return acc.p2p_set(sid, phase, round, to, &self.ids).0;
            }
        }
    }
}
