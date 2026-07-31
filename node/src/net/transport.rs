//! [`MeshTransport`]: the core `Transport<SignedEnvelope<DkgMessage>>`
//! trait over the real-TCP mesh, with §4.7 echo-broadcast acceptance.
//!
//! Acceptance rule (SPEC §4.7, signed-echo consistent broadcast): a
//! broadcast value `m` from sender `i` is accepted once
//!
//! 1. the acceptor holds `i`'s valid §10.2 signature on `m` (every
//!    candidate carries the sender's signed envelope, verified on
//!    receipt);
//! 2. `m` was echoed by at least `T−1` DISTINCT parties OTHER than `i`
//!    (the sender's own copy is never counted — an echo of one's own
//!    message is rejected by the mesh);
//! 3. no value `m′ ≠ m` carrying `i`'s signature has been seen: a
//!    second distinct sender-signed payload in the same slot is
//!    EQUIVOCATION — the slot is poisoned (`⊥` for `i`, the value is
//!    never delivered) and logged loudly; the two signed envelopes are
//!    the offline-verifiable blame evidence (§10.1 F8).
//!
//! Together with the mesh's first-echo rule this yields:
//!
//! * consistency — two different values cannot both be accepted: each
//!   would need `i`'s signature (rule 1) and `T−1` echoers, at least
//!   one of them honest (at most `T−2` corrupt parties other than `i`
//!   exist), and an honest echoer echoes to ALL, making the conflict
//!   visible everywhere — rule (3) then forces `⊥`;
//! * validity/totality — an honest sender's value collects its
//!   signature plus the `≥ T−1` honest non-sender echoes.
//!
//! (The superseded `⌈(n+1)/2⌉`-majority-echo rule is inconsistent at
//! `T ≥ 3` — two size-`T` quorums of `n = 2T−1` may intersect only in
//! corrupt parties; see the §4.7 design note.)
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

use crate::mesh::{Node, INBOX_BOUND};
use crate::wire::{FrameBound, Received, WireMessage};

/// H2 per-variant frame bounds for the M1 payload family (see
/// `wire::FrameBound`): same sizes as `party.rs`'s `NodePayload::Dkg` —
/// Commit ≈ 40 B (id + hash), Reveal = `8 + 33n` (Feldman vector,
/// threshold degree bounded by `n` worst case), Share ≈ 48 B — one
/// bound over the largest variant (Reveal), rounded up with slack.
impl FrameBound for DkgMessage {
    fn payload_variant_max(&self, n: usize) -> u64 {
        match self {
            Self::Commit(_) | Self::Share(_) => 64,
            Self::Reveal(_) => Self::family_max(n),
        }
    }

    fn family_max(n: usize) -> u64 {
        64 + 40 * n as u64
    }
}

/// Default per-round timeout (localhost rounds complete in milliseconds).
pub const DEFAULT_ROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Broadcast slot key `(sid, phase, round, from)`; for P2P the last
/// component is the addressee instead.
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// One distinct signed broadcast payload and the parties that echoed it.
struct Candidate {
    env: SignedEnvelope<DkgMessage>,
    echoers: BTreeSet<PartyId>,
}

/// The echo-broadcast acceptor: dedups by slot and payload, counts
/// distinct echoers, decides acceptance per §4.7 rules (1)–(3). Fed by
/// every node's mailbox (orchestrator pattern — one acceptor yields one
/// consistent accepted set, the `SimTransport` analog of §13.2).
struct Acceptor {
    /// §4.7 rule (2): echoes from `T−1` distinct parties other than the
    /// sender.
    echo_quorum: usize,
    /// slot → payload-bytes → candidate. A SECOND distinct payload in a
    /// slot is sender equivocation (every candidate carries the sender's
    /// verified signature) — the slot is poisoned (rule (3)).
    bcast: BTreeMap<SlotKey, BTreeMap<Vec<u8>, Candidate>>,
    /// `(sid, sender)` poisoned by equivocation (§4.7 rule (3)): the
    /// sender's slots in this session never accept (the value is not
    /// delivered, the evidence is the two conflicting signed envelopes).
    equivocated: BTreeSet<(Vec<u8>, PartyId)>,
    /// (sid, phase, round, to) → sender → message.
    p2p: BTreeMap<SlotKey, BTreeMap<PartyId, SignedEnvelope<DkgMessage>>>,
}

impl Acceptor {
    fn new(t: usize) -> Self {
        Self {
            echo_quorum: t.saturating_sub(1),
            bcast: BTreeMap::new(),
            equivocated: BTreeSet::new(),
            p2p: BTreeMap::new(),
        }
    }

    /// Insert one candidate payload into its slot; on the SECOND distinct
    /// payload poison `(sid, from)` and log the equivocation loudly.
    fn insert_candidate(
        &mut self,
        key: &SlotKey,
        payload: Vec<u8>,
        env: SignedEnvelope<DkgMessage>,
    ) -> &mut Candidate {
        let payloads = self.bcast.entry(key.clone()).or_default();
        payloads
            .entry(payload.clone())
            .or_insert_with(|| Candidate {
                env,
                echoers: BTreeSet::new(),
            });
        if payloads.len() == 2 && self.equivocated.insert((key.0.clone(), key.3)) {
            eprintln!(
                "[mesh] EQUIVOCATION: party {} signed two conflicting values for the same \
                 broadcast slot ({}, round {}) — the sender is ⊥ for this session \
                 (SPEC §4.7 rule (3), fault class F8)",
                key.3, key.1, key.2
            );
        }
        payloads.get_mut(&payload).expect("candidate just inserted")
    }

    fn process(&mut self, msg: Received<DkgMessage>) {
        match msg {
            Received::Original(se) => match se.envelope.to {
                None => {
                    let (key, payload) = slot_and_payload(&se);
                    if self.equivocated.contains(&(key.0.clone(), key.3)) {
                        return; // sender already ⊥ in this session
                    }
                    self.insert_candidate(&key, payload, se);
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
                if self.equivocated.contains(&(key.0.clone(), key.3)) {
                    return; // sender already ⊥ in this session
                }
                let candidate = self.insert_candidate(&key, payload, original);
                // §4.7 rule (2): only echoes from parties OTHER than the
                // sender count toward the quorum — the sender's own copy
                // is never counted (its signature already satisfies
                // rule (1); a self-echo adds nothing).
                if echoer != key.3 {
                    candidate.echoers.insert(echoer);
                }
            }
        }
    }

    /// The accepted broadcast set of one round (only values satisfying
    /// §4.7 rules (1)–(3)), plus whether every member has one.
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
            if self.equivocated.contains(&(sid.to_vec(), id)) {
                continue; // rule (3): ⊥ for an equivocating sender
            }
            let key = (sid.to_vec(), phase, round, id);
            let accepted = self
                .bcast
                .get(&key)
                .and_then(|m| m.values().find(|c| c.echoers.len() >= self.echo_quorum));
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
    /// envelope signing. `t` is the signing threshold — the §4.7 echo
    /// quorum is `T−1` echoes from parties other than the sender.
    pub fn start(
        parties: &[(PartyId, SocketAddr)],
        keys: &[(PartyId, SecretKey)],
        t: usize,
        round_timeout: Duration,
    ) -> io::Result<Self> {
        let registry: BTreeMap<PartyId, VerifyingKey> = keys
            .iter()
            .map(|(p, sk)| (*p, *SigningKey::from(sk).verifying_key()))
            .collect();
        let (tx, rx) = mpsc::sync_channel(INBOX_BOUND);
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
            state: Mutex::new(Acceptor::new(t)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ohm_ecdsa::dkg::DkgBcast1;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn signed_commit(seed: u64, from: PartyId, byte: u8) -> SignedEnvelope<DkgMessage> {
        let key = SigningKey::random(&mut StdRng::seed_from_u64(seed));
        SignedEnvelope::sign(
            Envelope::broadcast(
                b"sid/self-echo",
                Phase::KeyGen,
                1,
                from,
                DkgMessage::Commit(DkgBcast1 {
                    from,
                    hash: [byte; 32],
                }),
            ),
            &key,
        )
    }

    /// §4.7 rule (2): a sender's self-echo never counts toward the
    /// `T−1` echo quorum — a malicious sender cannot fill the quorum
    /// with itself plus fewer than `T−1` colluders.
    #[test]
    fn sender_self_echo_does_not_count_toward_quorum() {
        let mut acc = Acceptor::new(3); // quorum = T−1 = 2 non-sender echoers
        let original = signed_commit(900, 1, 0xAA);
        acc.process(Received::Original(original.clone()));

        // Sender 1 self-echoes; one colluder (2) echoes: only {2} can
        // count, so the quorum of 2 is NOT reached.
        acc.process(Received::Echo {
            echoer: 1,
            original: original.clone(),
        });
        acc.process(Received::Echo {
            echoer: 2,
            original: original.clone(),
        });
        let (set, complete) = acc.bcast_set(b"sid/self-echo", Phase::KeyGen, 1, &[1]);
        assert!(
            !complete && !set.contains_key(&1),
            "self-echo + one colluder must not reach the T−1 quorum"
        );

        // A second DISTINCT non-sender echoer reaches the quorum.
        acc.process(Received::Echo {
            echoer: 3,
            original,
        });
        let (set, complete) = acc.bcast_set(b"sid/self-echo", Phase::KeyGen, 1, &[1]);
        assert!(complete && set.contains_key(&1));
    }
}
