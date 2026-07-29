//! M2 per-party node drivers (SPEC §6, §6.1, §9, §10.2, §13.1/§13.2).
//!
//! M2 kills the M1 reference-orchestration pattern: a [`PartyNode`] holds
//! ONLY its own material — its own transport secret key, its own party id,
//! the peers' verifying keys, and its own mesh connections — and runs only
//! its own protocol logic. Key separation is enforced by construction:
//! [`PartyNode::bind`] takes exactly one [`SecretKey`], and no API on
//! [`PartyNode`] accepts another party's secret material.
//!
//! Two drivers:
//!
//! * [`PartyNode::keygen`] — per-node commit-reveal DKG (§6) with the
//!   §6.1 complaint subprotocol carried ON THE WIRE: round 3 broadcasts
//!   signed complaints, round 4 broadcasts signed defenses, and every
//!   node adjudicates `EvalCom(A_d, j)` against the defense over its own
//!   echo-consistent accepted sets — all honest nodes reach the same
//!   blame verdict (false accusation ⇒ accuser blamed; bad or missing
//!   defense ⇒ dealer blamed). The M1 shortcut (defenses read from dealer
//!   state in-process) is gone.
//! * [`PartyNode::sign`] — per-node online signing (§9): each node
//!   broadcasts its `sign_share`, verifies every received share against
//!   `m·A[u] + r·A[z]` by point equality, and interpolates from the first
//!   `t` valid shares (the §10.4 robust path: bad shares are blamed and
//!   excluded, the signature is still delivered).
//!
//! Presignature DISTRIBUTION is the documented M2 shortcut: records come
//! from a prior orchestrated run ([`crate::seed`]); per-node presign
//! through the mesh is M3.
//!
//! Rounds complete when every committee member has an accepted value or
//! the round timeout fires — then the PARTIAL set is returned, logged
//! loudly, and the drivers fail closed ("incomplete message sets"): a
//! wrong key or wrong signature can never result (same policy as M1;
//! timeout values are a deployment concern, SPEC §13.1).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::{Scalar, SecretKey};
use rand::RngCore;

use ohm_ecdsa::dkg::{DkgInstance, DkgP2P};
use ohm_ecdsa::presign::{KeyShare, Presignature};
use ohm_ecdsa::sign::{self, SignShare};
use ohm_ecdsa::transport::{Decode, DkgMessage, Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{hash_commitment, Error, IdentifiableAbort, Params, PartyId, Phase, Result};

use crate::mesh::Node;
use crate::wire::{take_u64, Received};

/// Keygen round numbers (`Envelope::round` within [`Phase::KeyGen`]).
pub const KG_ROUND_COMMIT: u8 = 1;
/// Reveal broadcast + P2P shares ride round 2 (as in M1).
pub const KG_ROUND_REVEAL: u8 = 2;
/// §6.1 complaints ride round 3 (every node broadcasts, possibly empty).
pub const KG_ROUND_COMPLAIN: u8 = 3;
/// §6.1 defenses ride round 4 (every node broadcasts, possibly empty).
pub const KG_ROUND_DEFEND: u8 = 4;

/// Online signing is one broadcast round (SPEC §9).
pub const SIGN_ROUND_SHARE: u8 = 1;

/// The M2 wire payloads: everything a per-node driver sends beyond the
/// core's [`DkgMessage`] rounds. Encoded in the core's canonical
/// [`Encode`]/[`Decode`] format (versioned tag bytes per variant).
#[derive(Clone, Debug)]
pub enum NodePayload {
    /// A core DKG round message (commit / reveal / P2P share).
    Dkg(DkgMessage),
    /// §6.1 complaint round: the dealers this node accuses (empty = no
    /// complaints — the round must still complete for every sender).
    Complaints(Vec<PartyId>),
    /// §6.1 defense round: for each accuser that complained about this
    /// dealer, the share it was dealt — the §10.2 non-repudiation model:
    /// the defense is exactly the dealt value (empty = nobody complained
    /// about this node).
    Defenses(Vec<(PartyId, Scalar)>),
    /// Online signing (SPEC §9): this node's signature share.
    SignShare {
        /// The presignature id the share belongs to.
        presig: u64,
        /// `s_j = m·u_j + r·z_j`.
        s: Scalar,
    },
}

impl Encode for NodePayload {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Dkg(m) => {
                out.push(1);
                m.encode(out);
            }
            Self::Complaints(list) => {
                out.push(2);
                out.extend_from_slice(&(list.len() as u64).to_be_bytes());
                for d in list {
                    out.extend_from_slice(&(*d as u64).to_be_bytes());
                }
            }
            Self::Defenses(defs) => {
                out.push(3);
                out.extend_from_slice(&(defs.len() as u64).to_be_bytes());
                for (accuser, share) in defs {
                    out.extend_from_slice(&(*accuser as u64).to_be_bytes());
                    share.encode(out);
                }
            }
            Self::SignShare { presig, s } => {
                out.push(4);
                out.extend_from_slice(&presig.to_be_bytes());
                s.encode(out);
            }
        }
    }
}

impl Decode for NodePayload {
    fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let tag = *bytes.first()?;
        let mut used = 1;
        match tag {
            1 => {
                let (m, u) = DkgMessage::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::Dkg(m), used))
            }
            2 => {
                let (n, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let mut list = Vec::new();
                for _ in 0..n {
                    let (d, u) = take_u64(bytes.get(used..)?)?;
                    used += u;
                    list.push(usize::try_from(d).ok()?);
                }
                Some((Self::Complaints(list), used))
            }
            3 => {
                let (n, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let mut defs = Vec::new();
                for _ in 0..n {
                    let (a, u) = take_u64(bytes.get(used..)?)?;
                    used += u;
                    let (s, u) = Scalar::decode(bytes.get(used..)?)?;
                    used += u;
                    defs.push((usize::try_from(a).ok()?, s));
                }
                Some((Self::Defenses(defs), used))
            }
            4 => {
                let (presig, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let (s, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::SignShare { presig, s }, used))
            }
            _ => None,
        }
    }
}

/// Fault injection for demos and tests (drives one node into a cheater).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cheat {
    /// Deal a wrong DKG share to `victim` (cheating dealer, fault class
    /// F2 of §10.1): the node's §6.1 defense carries the wrong dealt
    /// value, so every node blames this node as dealer.
    BadDeal {
        /// The party that receives the wrong share.
        victim: PartyId,
    },
    /// Broadcast a §6.1 complaint against `dealer` although the dealt
    /// share verified (false accusation): the dealer's defense verifies,
    /// so every node blames THIS node as accuser.
    FalseAccuse {
        /// The honest dealer falsely accused.
        dealer: PartyId,
    },
    /// Broadcast a wrong signature share (§9): it fails the
    /// `m·A[u] + r·A[z]` point check at every node, so every node blames
    /// this node and still interpolates from the honest shares (§10.4).
    BadSignShare,
}

/// Broadcast slot key `(sid, phase, round, from)`; for P2P the last
/// component is the addressee instead.
type SlotKey = (Vec<u8>, Phase, u8, PartyId);

/// One distinct signed broadcast payload and the parties that echoed it.
struct Candidate {
    env: SignedEnvelope<NodePayload>,
    echoers: BTreeSet<PartyId>,
}

/// The per-node echo-broadcast acceptor: same rule as M1
/// (`⌈(n+1)/2⌉` distinct echoers OTHER than the sender), but fed by this
/// node's mailbox ONLY — including the node's own echo via the mesh's
/// self-echo loopback (M1 counted it through the peers' mailboxes).
struct Acceptor {
    majority: usize,
    bcast: BTreeMap<SlotKey, BTreeMap<Vec<u8>, Candidate>>,
    p2p: BTreeMap<SlotKey, BTreeMap<PartyId, SignedEnvelope<NodePayload>>>,
}

impl Acceptor {
    fn new(n: usize) -> Self {
        Self {
            majority: (n + 2) / 2,
            bcast: BTreeMap::new(),
            p2p: BTreeMap::new(),
        }
    }

    fn process(&mut self, msg: Received<NodePayload>) {
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

    /// The accepted broadcast set of one round: values that reached the
    /// echo majority, keyed by sender.
    fn bcast_set(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        ids: &[PartyId],
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        let mut out = BTreeMap::new();
        for &id in ids {
            let key = (sid.to_vec(), phase, round, id);
            let accepted = self
                .bcast
                .get(&key)
                .and_then(|m| m.values().find(|c| c.echoers.len() >= self.majority));
            if let Some(c) = accepted {
                out.insert(id, c.env.clone());
            }
        }
        out
    }

    /// The round's P2P messages addressed to `to`, keyed by sender.
    fn p2p_set(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        self.p2p
            .get(&(sid.to_vec(), phase, round, to))
            .cloned()
            .unwrap_or_default()
    }
}

fn slot_and_payload(se: &SignedEnvelope<NodePayload>) -> (SlotKey, Vec<u8>) {
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

fn abort(phase: Phase, blamed: Vec<PartyId>, detail: String) -> Error {
    Error::Abort {
        abort: IdentifiableAbort {
            phase,
            blamed,
            detail,
        },
    }
}

/// A per-party M2 node: exactly its own transport key, id, and mesh.
pub struct PartyNode {
    me: PartyId,
    params: Params,
    key: SigningKey,
    node: Node<NodePayload>,
    inbox: Mutex<Receiver<Received<NodePayload>>>,
    state: Mutex<Acceptor>,
    timeout: Duration,
}

impl PartyNode {
    /// Bind this node's listener. `registry` is the PUBLIC party key
    /// registry (every committee member's verifying key, including this
    /// node's); `transport_key` is THIS node's secret key — the only
    /// secret this node ever holds besides its protocol shares.
    pub fn bind(
        me: PartyId,
        params: Params,
        transport_key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        bind: SocketAddr,
        round_timeout: Duration,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let node = Node::bind(me, bind, transport_key, registry, tx)?;
        // The per-node acceptor counts this node's own echo through its
        // own mailbox (M1's orchestrator counted it globally).
        node.set_self_echo_loopback(true);
        Ok(Self {
            me,
            params,
            key: SigningKey::from(transport_key),
            node,
            inbox: Mutex::new(rx),
            state: Mutex::new(Acceptor::new(params.n)),
            timeout: round_timeout,
        })
    }

    /// This node's party id.
    pub fn id(&self) -> PartyId {
        self.me
    }

    /// The address this node's listener bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.node.local_addr()
    }

    /// Artificial per-link send delay (benchmarks; simulated WAN).
    pub fn set_send_delay(&self, delay: Duration) {
        self.node.set_send_delay(delay);
    }

    /// Connect to every peer (startup retry/backoff until the mesh is up).
    pub fn connect(&self, addrs: &[(PartyId, SocketAddr)]) -> io::Result<()> {
        self.node.connect(addrs)
    }

    /// Broadcast one signed payload (echo-broadcast, SPEC §4.7/§10.2).
    pub fn broadcast(&self, sid: &[u8], phase: Phase, round: u8, payload: NodePayload) {
        let signed = SignedEnvelope::sign(
            Envelope::broadcast(sid, phase, round, self.me, payload),
            &self.key,
        );
        self.node
            .send_all(&crate::wire::WireMessage::Original(signed));
    }

    /// Send one signed P2P payload. This node's own copy never leaves the
    /// node: it is delivered straight into the local acceptor.
    pub fn send_p2p(&self, sid: &[u8], phase: Phase, round: u8, to: PartyId, payload: NodePayload) {
        let signed = SignedEnvelope::sign(
            Envelope::p2p(sid, phase, round, self.me, to, payload),
            &self.key,
        );
        if to == self.me {
            self.state
                .lock()
                .expect("mesh mutex poisoned")
                .process(Received::Original(signed));
            return;
        }
        self.node
            .send_to(to, &crate::wire::WireMessage::Original(signed));
    }

    /// The accepted broadcast set of one round (blocks until every
    /// committee member has an accepted value or the round timeout fires;
    /// on timeout the PARTIAL set is returned and logged — the drivers
    /// fail closed on it).
    pub fn accepted_broadcasts(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        let ids = self.params.parties();
        let deadline = Instant::now() + self.timeout;
        loop {
            {
                let set = self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .bcast_set(sid, phase, round, &ids);
                if set.len() == ids.len() {
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} broadcasts; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                return self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .bcast_set(sid, phase, round, &ids);
            }
        }
    }

    /// The round's accepted P2P messages addressed to this node (same
    /// completeness/timeout policy as [`Self::accepted_broadcasts`]).
    pub fn accepted_p2p(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        let ids = self.params.parties();
        let deadline = Instant::now() + self.timeout;
        loop {
            {
                let set = self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .p2p_set(sid, phase, round, self.me);
                if set.len() == ids.len() {
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} p2p; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                return self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .p2p_set(sid, phase, round, self.me);
            }
        }
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
            Err(_) => false,
        }
    }

    /// Per-node keygen (SPEC §6, §6.1): commit → reveal+shares →
    /// complaints → defenses → adjudicate. Every verdict is computed over
    /// this node's own echo-consistent accepted sets, so all honest nodes
    /// reach the SAME blame. Returns this node's [`KeyShare`] — it never
    /// leaves the node.
    pub fn keygen(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KeyShare> {
        let me = self.me;
        let n = self.params.n;
        let t = self.params.t;
        let phase = Phase::KeyGen;

        // Round 1: commit; round 2: reveal + P2P shares.
        let (inst, b1) = DkgInstance::start(self.params, sid, tag, me, rng);
        self.broadcast(
            sid,
            phase,
            KG_ROUND_COMMIT,
            NodePayload::Dkg(DkgMessage::Commit(b1)),
        );
        let (b2, mut shares) = inst.reveal();
        if let Some(Cheat::BadDeal { victim }) = cheat {
            // Cheating dealer: the wrong share is what goes on the wire —
            // and (§10.2 non-repudiation) it is also what the defense
            // below carries.
            for s in shares.iter_mut() {
                if s.to == victim {
                    s.share += Scalar::ONE;
                }
            }
        }
        self.broadcast(
            sid,
            phase,
            KG_ROUND_REVEAL,
            NodePayload::Dkg(DkgMessage::Reveal(b2)),
        );
        for s in shares {
            self.send_p2p(
                sid,
                phase,
                KG_ROUND_REVEAL,
                s.to,
                NodePayload::Dkg(DkgMessage::Share(s)),
            );
        }

        // Collect this node's own accepted sets.
        let r1_envs = self.accepted_broadcasts(sid, phase, KG_ROUND_COMMIT);
        let r2_envs = self.accepted_broadcasts(sid, phase, KG_ROUND_REVEAL);
        let share_envs = self.accepted_p2p(sid, phase, KG_ROUND_REVEAL);
        if r1_envs.len() != n || r2_envs.len() != n || share_envs.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut r1 = BTreeMap::new();
        let mut r2 = BTreeMap::new();
        let mut mine: BTreeMap<PartyId, Scalar> = BTreeMap::new();
        for (f, se) in r1_envs {
            match se.envelope.payload {
                NodePayload::Dkg(DkgMessage::Commit(b)) if b.from == f => {
                    r1.insert(f, b);
                }
                _ => return Err(abort(phase, vec![f], "malformed commit broadcast".into())),
            }
        }
        for (f, se) in r2_envs {
            match se.envelope.payload {
                NodePayload::Dkg(DkgMessage::Reveal(b)) if b.from == f => {
                    r2.insert(f, b);
                }
                _ => return Err(abort(phase, vec![f], "malformed reveal broadcast".into())),
            }
        }
        for (f, se) in share_envs {
            match se.envelope.payload {
                NodePayload::Dkg(DkgMessage::Share(DkgP2P { from, to, share }))
                    if from == f && to == me =>
                {
                    mine.insert(f, share);
                }
                _ => return Err(abort(phase, vec![f], "malformed share envelope".into())),
            }
        }

        // F1 (commit-reveal consistency): computable by EVERY node over
        // the echo-consistent sets — all honest nodes abort with the same
        // blame, no complaint round needed.
        for i in 1..=n {
            let b2 = &r2[&i];
            if b2.com.points.len() != t {
                return Err(abort(
                    phase,
                    vec![i],
                    "malformed Feldman commitment vector".into(),
                ));
            }
            if hash_commitment(sid, tag, i, &b2.com) != r1[&i].hash {
                return Err(abort(phase, vec![i], "commit-reveal hash mismatch".into()));
            }
        }

        // Local share checks (F2): this node complains about every dealer
        // whose share fails point equality against the revealed vector.
        let mut complaints: Vec<PartyId> = (1..=n)
            .filter(|&i| !r2[&i].com.verify_share(me, &mine[&i]))
            .collect();
        if let Some(Cheat::FalseAccuse { dealer }) = cheat {
            if !complaints.contains(&dealer) {
                complaints.push(dealer); // malicious: false accusation
            }
        }

        // Round 3 (§6.1): complaints. Every node broadcasts (possibly
        // empty) so the round completes everywhere.
        self.broadcast(
            sid,
            phase,
            KG_ROUND_COMPLAIN,
            NodePayload::Complaints(complaints),
        );
        let complaint_sets = self.accepted_broadcasts(sid, phase, KG_ROUND_COMPLAIN);
        if complaint_sets.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }

        // Round 4 (§6.1): defenses. This dealer answers every complaint
        // naming it with the share it actually dealt the accuser.
        let mut defenses: Vec<(PartyId, Scalar)> = Vec::new();
        for (a, se) in &complaint_sets {
            let NodePayload::Complaints(list) = &se.envelope.payload else {
                return Err(abort(
                    phase,
                    vec![*a],
                    "malformed complaint broadcast".into(),
                ));
            };
            if list.contains(&me) {
                let mut share = inst.defend(*a);
                if let Some(Cheat::BadDeal { victim }) = cheat {
                    if victim == *a {
                        share += Scalar::ONE; // the dealt (wrong) value
                    }
                }
                defenses.push((*a, share));
            }
        }
        self.broadcast(sid, phase, KG_ROUND_DEFEND, NodePayload::Defenses(defenses));
        let defense_sets = self.accepted_broadcasts(sid, phase, KG_ROUND_DEFEND);
        if defense_sets.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }

        // Adjudication (§6.1 step 2): every complaint has a verdict — a
        // verifying defense blames the accuser, a missing or failing
        // defense blames the dealer. Every node evaluates the FIRST
        // complaint (deterministic accuser/dealer order) over the same
        // echo-consistent accepted sets — same verdict everywhere.
        let mut first_complaint: Option<(PartyId, PartyId)> = None;
        for (a, se) in &complaint_sets {
            let NodePayload::Complaints(list) = &se.envelope.payload else {
                return Err(abort(
                    phase,
                    vec![*a],
                    "malformed complaint broadcast".into(),
                ));
            };
            if let Some(d) = list.iter().min() {
                first_complaint = Some((*a, *d));
                break;
            }
        }
        if let Some((a, d)) = first_complaint {
            let NodePayload::Defenses(defs) = &defense_sets[&d].envelope.payload else {
                return Err(abort(phase, vec![d], "malformed defense broadcast".into()));
            };
            match defs.iter().find(|(accuser, _)| accuser == &a) {
                None => {
                    return Err(abort(
                        phase,
                        vec![d],
                        format!("dealer {d} broadcast no defense against {a}'s complaint"),
                    ))
                }
                Some((_, share)) if r2[&d].com.verify_share(a, share) => {
                    return Err(abort(
                        phase,
                        vec![a],
                        format!(
                            "false accusation: dealer {d}'s defense share verifies against its commitment"
                        ),
                    ))
                }
                Some(_) => {
                    return Err(abort(
                        phase,
                        vec![d],
                        format!(
                            "dealer {d}'s defense share fails verification against its commitment"
                        ),
                    ))
                }
            }
        }

        // Output: the key share is computed locally and never leaves the node.
        let mut share_sum = Scalar::ZERO;
        let mut coms = Vec::with_capacity(n);
        for i in 1..=n {
            share_sum += mine[&i];
            coms.push(r2[&i].com.clone());
        }
        Ok(KeyShare {
            index: me,
            share: share_sum,
            com: FeldmanCommitment::sum(coms),
        })
    }

    /// Per-node online signing (SPEC §9, §10.4): broadcast this node's
    /// `sign_share`, verify every received share against
    /// `m·A[u] + r·A[z]` by point equality (bad shares are blamed and
    /// excluded), interpolate from the first `t` valid shares, low-`s`
    /// normalize. Returns the signature and the blamed senders.
    pub fn sign(
        &self,
        sid: &[u8],
        presig: &Presignature,
        msg: &[u8],
        cheat: Option<Cheat>,
    ) -> Result<(Signature, Vec<PartyId>)> {
        let phase = Phase::Sign;
        let m = ohm_ecdsa::sim::message_scalar(msg);
        let mut share = sign::sign_share(presig, &m);
        if cheat == Some(Cheat::BadSignShare) {
            share.s += Scalar::ONE; // malicious: wrong signature share
        }
        self.broadcast(
            sid,
            phase,
            SIGN_ROUND_SHARE,
            NodePayload::SignShare {
                presig: presig.id,
                s: share.s,
            },
        );
        let set = self.accepted_broadcasts(sid, phase, SIGN_ROUND_SHARE);
        let mut shares = Vec::with_capacity(set.len());
        for (f, se) in set {
            match se.envelope.payload {
                NodePayload::SignShare { presig: pid, s } if pid == presig.id => {
                    shares.push(SignShare { from: f, s });
                }
                NodePayload::SignShare { .. } => {
                    eprintln!(
                        "[node {}] dropped sign share for the wrong presignature id from {f}",
                        self.me
                    );
                }
                _ => return Err(abort(phase, vec![f], "malformed sign broadcast".into())),
            }
        }
        // §10.4 robust combine: bad shares are blamed and excluded; the
        // signature is interpolated from the first t valid shares.
        let ((r, s), blamed) = sign::combine_robust(&self.params, presig, &m, &shares)?;
        let sig = Signature::from_scalars(r, s)?;
        Ok((sig.normalize_s().unwrap_or(sig), blamed))
    }
}
