//! M2/M3a per-party node drivers (SPEC §6, §6.1, §7.2, §8, §9, §10.2,
//! §13.1/§13.2).
//!
//! M2 kills the M1 reference-orchestration pattern: a [`PartyNode`] holds
//! ONLY its own material — its own transport secret key, its own party id,
//! the peers' verifying keys, and its own mesh connections — and runs only
//! its own protocol logic. Key separation is enforced by construction:
//! [`PartyNode::bind`] takes exactly one [`SecretKey`], and no API on
//! [`PartyNode`] accepts another party's secret material.
//!
//! Four drivers:
//!
//! * [`PartyNode::keygen`] — per-node commit-reveal DKG (§6) with the
//!   §6.1 complaint subprotocol carried ON THE WIRE: round 3 broadcasts
//!   signed complaints, round 4 broadcasts signed defenses, and every
//!   node adjudicates `EvalCom(A_d, j)` against the defense over its own
//!   echo-consistent accepted sets — all honest nodes reach the same
//!   blame verdict (false accusation ⇒ accuser blamed; bad or missing
//!   defense ⇒ dealer blamed). The M1 shortcut (defenses read from dealer
//!   state in-process) is gone. The same machinery is factored out as
//!   [`PartyNode::joint_vss`] — one ephemeral joint random sharing over
//!   the wire — and reused by the offline factory below.
//! * [`PartyNode::triple`] — per-node Beaver triple generation (§7.2,
//!   M3a). T1 runs two [`PartyNode::joint_vss`] instances (⟦α⟧, ⟦β⟧);
//!   T2 broadcasts `FeldCommit(g_j)` + ONE DLEQ product proof and sends
//!   the re-shares `g_j(i)` P2P; T3 verifies every proof (F3 ⇒ blame the
//!   prover, deterministic everywhere) and every received re-share (F2 ⇒
//!   the same wire §6.1 complaint/defense rounds as keygen), then
//!   combines with Lagrange weights.
//! * [`PartyNode::presign`] — per-node presignatures (§8, M3a): two
//!   [`PartyNode::triple`] sessions plus two [`PartyNode::joint_vss`]
//!   instances (⟦u⟧, ⟦a⟧), then the Beaver openings δ/ε, v, δ′/ε′ and the
//!   nonce points `R_j` as broadcast rounds — every share checked against
//!   its public commitment by point equality, every nonce point against
//!   `EvalCom(A[k], j)` (F5 ⇒ blame the sender). Openings are FAIL-FAST
//!   identifiable aborts: the wire driver stays simple and fail-closed —
//!   robust blame-and-continue lives in the core's sim (§10.4) and is
//!   deliberately NOT re-implemented here. `v = 0` / `r = 0` return
//!   [`Error::ZeroValue`]; the caller retries with a fresh presignature
//!   id (the demo treats it as fatal — probability ~2⁻¹²⁸ per session).
//! * [`PartyNode::sign`] — per-node online signing (§9): each node
//!   broadcasts its `sign_share`, verifies every received share against
//!   `m·A[u] + r·A[z]` by point equality, and interpolates from the first
//!   `t` valid shares (the §10.4 robust path: bad shares are blamed and
//!   excluded, the signature is still delivered).
//! * [`PartyNode::presign_ki`] / [`PartyNode::sign_ki`] — the OPTIONAL
//!   key-independent mode (§8.7): pool production is P1–P3 of
//!   [`PartyNode::presign`] verbatim with P4 omitted (the record is
//!   key-free and NOT key-equivalent); signing binds the record to a key
//!   ONLINE in two broadcast rounds — R1 generates a fresh triple and
//!   opens δ = ⟦u⟧−⟦α⟧, ε = ⟦x⟧−⟦β⟧ (fail-fast point-equality checks),
//!   R2 broadcasts `s_j = m·u_j + r·z_j` verified against
//!   `m·A[u] + r·A[z]`. Pool records live in a per-node IN-MEMORY
//!   key-free pool (§8.7 storage relaxation; the M3b durable store stays
//!   per-key — a durable key-free pool file is follow-up).
//!
//! With M3a the demo's full arc — keygen → presign → sign — runs under
//! the key the node's OWN keygen produced; the ceremony-seeded
//! presignature distribution ([`crate::seed`]) remains as a fallback
//! (`--seeded`). With M3b ([`crate::persist`]) a node configured with
//! [`PartyNode::set_store`] persists every produced record and consumes
//! durably (§8.6), and [`PartyNode::set_archive`] archives the accepted
//! envelopes and blame tokens (§4.7, §10.2).
//!
//! Rounds complete when every committee member has an accepted value or
//! the round timeout fires — then the PARTIAL set is returned, logged
//! loudly, and the drivers fail closed ("incomplete message sets"): a
//! wrong key or wrong signature can never result (same policy as M1;
//! timeout values are a deployment concern, SPEC §13.1).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, SecretKey};
use rand::RngCore;

use ohm_ecdsa::dkg::{DkgBcast2, DkgInstance, DkgP2P};
use ohm_ecdsa::dleq::{self, DleqProof};
use ohm_ecdsa::open::open;
use ohm_ecdsa::presign::{KeyShare, KiPresignature, Presignature};
use ohm_ecdsa::shamir::{lagrange_coeffs, ShamirPoly};
use ohm_ecdsa::sign::{self, SignShare};
use ohm_ecdsa::store::KiPool;
use ohm_ecdsa::transport::{Decode, DkgMessage, Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::triples::{TriplePublic, TripleShare};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{
    hash_commitment, scalar_from_digest, tags, Error, IdentifiableAbort, Params, PartyId, Phase,
    Result,
};

use crate::mesh::Node;
use crate::persist::{Archive, BlameEvidence, DiskPresigStore, PersistError};
use crate::tls::CommitteeTls;
use crate::wire::{take_u64, Received};

/// Commit-reveal VSS round numbers (`Envelope::round` within one instance's
/// sid): used by keygen (§6) and by every ephemeral joint random sharing
/// the offline factory runs (§7.2 T1, §8 P1).
pub const VSS_ROUND_COMMIT: u8 = 1;
/// Reveal broadcast + P2P shares ride round 2 (as in M1).
pub const VSS_ROUND_REVEAL: u8 = 2;
/// §6.1 complaints ride round 3 (every node broadcasts, possibly empty).
pub const VSS_ROUND_COMPLAIN: u8 = 3;
/// §6.1 defenses ride round 4 (every node broadcasts, possibly empty).
pub const VSS_ROUND_DEFEND: u8 = 4;

/// Triple round numbers (§7.2, within `Phase::Triples`, one sid per
/// triple session): the deal round carries the `FeldCommit(g_j)` + DLEQ
/// product proof broadcast and the `g_j(i)` P2P re-shares.
pub const TR_ROUND_DEAL: u8 = 1;
/// §6.1 complaints on the re-shared shares ride round 2.
pub const TR_ROUND_COMPLAIN: u8 = 2;
/// §6.1 defenses ride round 3.
pub const TR_ROUND_DEFEND: u8 = 3;

/// Presign round numbers (§8, within `Phase::Presign`, one sid per
/// presignature): the δ/ε opening shares (P2) ride round 1.
pub const PS_ROUND_DELTA_EPS: u8 = 1;
/// The v opening shares (P2) ride round 2.
pub const PS_ROUND_V: u8 = 2;
/// The nonce points `R_j` (P3) ride round 3.
pub const PS_ROUND_NONCE: u8 = 3;
/// The δ′/ε′ opening shares (P4) ride round 4.
pub const PS_ROUND_Z: u8 = 4;

/// Online signing is one broadcast round (SPEC §9).
pub const SIGN_ROUND_SHARE: u8 = 1;

/// KI online signing (SPEC §8.7, within `Phase::Sign`, one sid per
/// signature): the R1 δ/ε opening shares ride round 1.
pub const KI_ROUND_OPEN: u8 = 1;
/// The R2 signature shares ride round 2.
pub const KI_ROUND_SHARE: u8 = 2;

/// A triple T2 deal broadcast (§7.2): the sender's re-sharing commitment
/// and its ONE DLEQ product proof binding `g_j(0)` to `α_j·β_j`.
#[derive(Clone, Debug)]
pub struct TripleDealMsg {
    /// `FeldCommit(g_j)`.
    pub com: FeldmanCommitment,
    /// `x1 = α_j·G` (first DLEQ statement point).
    pub x1: ProjectivePoint,
    /// `x2 = g_j(0)·G = c_j.points[0]` (second DLEQ statement point).
    pub x2: ProjectivePoint,
    /// The Chaum–Pedersen product proof (§4.4).
    pub proof: DleqProof,
}

/// The M2/M3a wire payloads: everything a per-node driver sends beyond
/// the core's [`DkgMessage`] rounds. Encoded in the core's canonical
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
    /// Triple T2 (§7.2): this node's re-sharing commitment and DLEQ
    /// product proof (boxed — much larger than the other variants).
    TripleDeal(Box<TripleDealMsg>),
    /// Triple T2 P2P: the re-shared share `g_j(i)` for the addressee.
    Reshare(Scalar),
    /// A pair of Beaver opening shares in one broadcast round (§8 P2:
    /// `(δ_j, ε_j)`; §8 P4: `(δ′_j, ε′_j)`).
    BeaverOpen {
        /// The first opening share (δ / δ′).
        first: Scalar,
        /// The second opening share (ε / ε′).
        second: Scalar,
    },
    /// A single opening share (§8 P2: the `v` opening).
    OpenShare(Scalar),
    /// Presign P3 (§8): this node's nonce point `R_j = k_j·G`, checked
    /// against `EvalCom(A[k], j)` by every node (F5).
    NoncePoint(ProjectivePoint),
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
            Self::TripleDeal(d) => {
                out.push(5);
                d.com.encode(out);
                d.x1.encode(out);
                d.x2.encode(out);
                d.proof.t1.encode(out);
                d.proof.t2.encode(out);
                d.proof.z.encode(out);
            }
            Self::Reshare(s) => {
                out.push(6);
                s.encode(out);
            }
            Self::BeaverOpen { first, second } => {
                out.push(7);
                first.encode(out);
                second.encode(out);
            }
            Self::OpenShare(s) => {
                out.push(8);
                s.encode(out);
            }
            Self::NoncePoint(p) => {
                out.push(9);
                p.encode(out);
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
            5 => {
                let (com, u) = FeldmanCommitment::decode(bytes.get(used..)?)?;
                used += u;
                let (x1, u) = ProjectivePoint::decode(bytes.get(used..)?)?;
                used += u;
                let (x2, u) = ProjectivePoint::decode(bytes.get(used..)?)?;
                used += u;
                let (t1, u) = ProjectivePoint::decode(bytes.get(used..)?)?;
                used += u;
                let (t2, u) = ProjectivePoint::decode(bytes.get(used..)?)?;
                used += u;
                let (z, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                Some((
                    Self::TripleDeal(Box::new(TripleDealMsg {
                        com,
                        x1,
                        x2,
                        proof: DleqProof { t1, t2, z },
                    })),
                    used,
                ))
            }
            6 => {
                let (s, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::Reshare(s), used))
            }
            7 => {
                let (first, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                let (second, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::BeaverOpen { first, second }, used))
            }
            8 => {
                let (s, u) = Scalar::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::OpenShare(s), used))
            }
            9 => {
                let (p, u) = ProjectivePoint::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::NoncePoint(p), used))
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
    /// Triples T2 (§7.2): broadcast an invalid DLEQ product proof (fault
    /// class F3 of §10.1): the proof check fails identically at every
    /// node, so every node blames this node as prover.
    BadProductProof,
    /// Triples T2 (§7.2): send a wrong re-shared share `g_j(i)` to
    /// `victim` (fault class F2): the victim's §6.1 complaint and this
    /// node's defense (carrying the dealt — wrong — value, §10.2
    /// non-repudiation) go over the wire, so every node blames this node
    /// as dealer.
    BadReshare {
        /// The party that receives the wrong re-shared share.
        victim: PartyId,
    },
    /// Presign P3 (§8): broadcast a wrong nonce point `R_j` (fault class
    /// F5): it fails the `EvalCom(A[k], j)` check at every node, so every
    /// node blames this node.
    BadNoncePoint,
    /// Presign P2 (§8): broadcast a wrong `v` opening share: it fails the
    /// point-equality check against the Beaver-derived commitment at
    /// every node, so every node blames this node.
    BadOpenShare,
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
    /// M3b: the durable presignature store (§8.6), configured per key.
    store: Mutex<Option<DiskPresigStore>>,
    /// M3b: the transcript + blame-token archive (§4.7, §10.2, §A.4).
    archive: Mutex<Option<Archive>>,
    /// §8.7: the IN-MEMORY key-free KI pool. Pool records carry no
    /// key-equivalent material (§8.7 storage relaxation), so an in-memory
    /// pool suffices — single-use stays mandatory and is enforced by the
    /// core [`KiPool`]'s atomic consume. The durable M3b store above is
    /// per-key and does NOT hold pool records (a durable key-free pool
    /// file is follow-up; a restart simply loses unspent records).
    ki_pool: Mutex<KiPool>,
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
        Self::bind_with_tls(
            me,
            params,
            transport_key,
            registry,
            bind,
            round_timeout,
            None,
        )
    }

    /// [`PartyNode::bind`] with OPTIONAL M3c mTLS (SPEC §13.1): with
    /// `tls`, every mesh connection is mutually authenticated with
    /// committee-pinned certificates ([`crate::tls`]); the TLS peer
    /// identity matches the expected [`PartyId`] on every link. The
    /// §10.2 envelope signatures stay on regardless (defense in depth).
    #[allow(clippy::too_many_arguments)] // bind + the optional TLS layer
    pub fn bind_with_tls(
        me: PartyId,
        params: Params,
        transport_key: &SecretKey,
        registry: BTreeMap<PartyId, VerifyingKey>,
        bind: SocketAddr,
        round_timeout: Duration,
        tls: Option<Arc<CommitteeTls>>,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let node = match tls {
            Some(tls) => Node::bind_tls(me, bind, transport_key, registry, tx, tls)?,
            None => Node::bind(me, bind, transport_key, registry, tx)?,
        };
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
            store: Mutex::new(None),
            archive: Mutex::new(None),
            ki_pool: Mutex::new(KiPool::new()),
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

    /// M3b: open (or create) the durable presignature store at `dir`,
    /// bound to `public_key` (§8.6 — one store per long-term key;
    /// reopening under a different key is rejected). From then on
    /// [`Self::presign_stored`] persists every record it produces and
    /// [`Self::sign_stored`] consumes durably.
    pub fn set_store(
        &self,
        dir: &Path,
        public_key: &AffinePoint,
    ) -> std::result::Result<(), PersistError> {
        let store = DiskPresigStore::open(dir, public_key)?;
        *self.store.lock().expect("mesh mutex poisoned") = Some(store);
        Ok(())
    }

    /// M3b: open (or create) the evidence archive at `dir`: every
    /// accepted signed envelope is appended to `transcript.log` (§4.7),
    /// and identifiable aborts are recorded in `aborts.log` with a
    /// blame-token file where cryptographic evidence exists (§10.2/§A.4).
    pub fn set_archive(&self, dir: &Path) -> io::Result<()> {
        let archive = Archive::create(dir)?;
        *self.archive.lock().expect("mesh mutex poisoned") = Some(archive);
        Ok(())
    }

    /// Append the accepted envelopes of a round to the transcript
    /// (archive failures are logged, not fatal: the transcript is
    /// auxiliary evidence, not protocol state).
    fn log_accepted(&self, set: &BTreeMap<PartyId, SignedEnvelope<NodePayload>>) {
        let mut guard = self.archive.lock().expect("mesh mutex poisoned");
        if let Some(archive) = guard.as_mut() {
            for se in set.values() {
                if let Err(e) = archive.log_accepted(se) {
                    eprintln!("[node {}] transcript archive failed: {e}", self.me);
                }
            }
        }
    }

    /// Record an identifiable abort in the archive, with blame-token
    /// evidence where it exists (F2 dealt shares, F6 sign shares; other
    /// classes log `token: none`). Non-fatal on I/O failure.
    fn note(&self, abort: &IdentifiableAbort, evidence: Option<BlameEvidence>) {
        let mut guard = self.archive.lock().expect("mesh mutex poisoned");
        if let Some(archive) = guard.as_mut() {
            if let Err(e) = archive.record_abort(abort, evidence.as_ref()) {
                eprintln!("[node {}] blame archive failed: {e}", self.me);
            }
        }
    }

    /// [`Self::note`] for an abort carried by an [`Error`].
    fn record_abort(&self, e: &Error, evidence: Option<BlameEvidence>) {
        if let Error::Abort { abort } = e {
            self.note(abort, evidence);
        }
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
                    self.log_accepted(&set);
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} broadcasts; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                let set = self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .bcast_set(sid, phase, round, &ids);
                self.log_accepted(&set);
                return set;
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
                    self.log_accepted(&set);
                    return set;
                }
            }
            if !self.pump(deadline) {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} p2p; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                let set = self
                    .state
                    .lock()
                    .expect("mesh mutex poisoned")
                    .p2p_set(sid, phase, round, self.me);
                self.log_accepted(&set);
                return set;
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

    /// Per-node keygen (SPEC §6, §6.1): the commit-reveal VSS driver
    /// ([`Self::joint_vss`]) under [`Phase::KeyGen`]. Returns this node's
    /// [`KeyShare`] — it never leaves the node.
    pub fn keygen(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KeyShare> {
        self.joint_vss(sid, tag, Phase::KeyGen, rng, cheat)
    }

    /// One commit-reveal joint random sharing over the wire (SPEC §6,
    /// §6.1): commit → reveal+shares → complaints → defenses →
    /// adjudicate. This is the M2 per-node DKG driver factored out — the
    /// M3a offline factory (§7.2 T1, §8 P1) reuses it for every ephemeral
    /// joint random sharing. Every verdict is computed over this node's
    /// own echo-consistent accepted sets, so all honest nodes reach the
    /// SAME blame. Returns this node's share and the joint commitment —
    /// the share never leaves the node.
    pub fn joint_vss(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        phase: Phase,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KeyShare> {
        let me = self.me;
        let n = self.params.n;
        let t = self.params.t;

        // Round 1: commit; round 2: reveal + P2P shares.
        let (inst, b1) = DkgInstance::start(self.params, sid, tag, me, rng);
        self.broadcast(
            sid,
            phase,
            VSS_ROUND_COMMIT,
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
            VSS_ROUND_REVEAL,
            NodePayload::Dkg(DkgMessage::Reveal(b2)),
        );
        for s in shares {
            self.send_p2p(
                sid,
                phase,
                VSS_ROUND_REVEAL,
                s.to,
                NodePayload::Dkg(DkgMessage::Share(s)),
            );
        }

        // Collect this node's own accepted sets.
        let r1_envs = self.accepted_broadcasts(sid, phase, VSS_ROUND_COMMIT);
        let r2_envs = self.accepted_broadcasts(sid, phase, VSS_ROUND_REVEAL);
        let share_envs = self.accepted_p2p(sid, phase, VSS_ROUND_REVEAL);
        if r1_envs.len() != n || r2_envs.len() != n || share_envs.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut r1 = BTreeMap::new();
        let mut r2 = BTreeMap::new();
        let mut mine: BTreeMap<PartyId, Scalar> = BTreeMap::new();
        // The signed P2P share envelopes, kept for the §10.2/§A.4
        // dealt-share blame evidence (M3b).
        let mut share_env_of: BTreeMap<PartyId, SignedEnvelope<NodePayload>> = BTreeMap::new();
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
            match &se.envelope.payload {
                NodePayload::Dkg(DkgMessage::Share(DkgP2P { from, to, share }))
                    if *from == f && *to == me =>
                {
                    mine.insert(f, *share);
                    share_env_of.insert(f, se);
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

        // §6.1 complaint/defense/adjudication rounds on the wire. The
        // defense is the share this dealer actually dealt the accuser
        // (§10.2 non-repudiation) — for a cheating dealer, the dealt
        // (wrong) value.
        let defense_for = |a: PartyId| {
            let mut share = inst.defend(a);
            if let Some(Cheat::BadDeal { victim }) = cheat {
                if victim == a {
                    share += Scalar::ONE; // the dealt (wrong) value
                }
            }
            share
        };
        let defense_verifies = |d: PartyId, a: PartyId, s: &Scalar| r2[&d].com.verify_share(a, s);
        if let Err(e) = self.complaint_round(
            sid,
            phase,
            (VSS_ROUND_COMPLAIN, VSS_ROUND_DEFEND),
            &complaints,
            defense_for,
            defense_verifies,
        ) {
            // M3b (§10.2/§A.4): archive the abort — with the F2
            // dealt-share token when this node is the accuser holding the
            // dealer's signed P2P share, `token: none` otherwise.
            let evidence = self.dealt_share_evidence(&e, &complaints, &share_env_of, &r2);
            self.record_abort(&e, evidence);
            return Err(e);
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

    /// The §6.1 complaint subprotocol on the wire (shared by the
    /// commit-reveal VSS and the triple factory's T3 re-share checks):
    /// this node broadcasts its complaints, answers every complaint
    /// naming it with the value it actually dealt (`defense_for`), and
    /// adjudicates the FIRST complaint (deterministic accuser/dealer
    /// order) over its own echo-consistent accepted sets — a verifying
    /// defense blames the ACCUSER (false accusation), a missing or
    /// failing defense blames the DEALER. All honest nodes evaluate the
    /// same sets and reach the same verdict. `Ok(())` iff no complaint.
    /// `rounds` is `(complain, defend)`.
    fn complaint_round(
        &self,
        sid: &[u8],
        phase: Phase,
        rounds: (u8, u8),
        complaints: &[PartyId],
        defense_for: impl Fn(PartyId) -> Scalar,
        defense_verifies: impl Fn(PartyId, PartyId, &Scalar) -> bool,
    ) -> Result<()> {
        let n = self.params.n;
        let (complain_round, defend_round) = rounds;

        // Complaints: every node broadcasts (possibly empty) so the round
        // completes everywhere.
        self.broadcast(
            sid,
            phase,
            complain_round,
            NodePayload::Complaints(complaints.to_vec()),
        );
        let complaint_sets = self.accepted_broadcasts(sid, phase, complain_round);
        if complaint_sets.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }

        // Defenses: this dealer answers every complaint naming it with
        // the share it actually dealt the accuser.
        let mut defenses: Vec<(PartyId, Scalar)> = Vec::new();
        for (a, se) in &complaint_sets {
            let NodePayload::Complaints(list) = &se.envelope.payload else {
                return Err(abort(
                    phase,
                    vec![*a],
                    "malformed complaint broadcast".into(),
                ));
            };
            if list.contains(&self.me) {
                defenses.push((*a, defense_for(*a)));
            }
        }
        self.broadcast(sid, phase, defend_round, NodePayload::Defenses(defenses));
        let defense_sets = self.accepted_broadcasts(sid, phase, defend_round);
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
            return match defs.iter().find(|(accuser, _)| accuser == &a) {
                None => Err(abort(
                    phase,
                    vec![d],
                    format!("dealer {d} broadcast no defense against {a}'s complaint"),
                )),
                Some((_, share)) if defense_verifies(d, a, share) => Err(abort(
                    phase,
                    vec![a],
                    format!(
                        "false accusation: dealer {d}'s defense share verifies against its commitment"
                    ),
                )),
                Some(_) => Err(abort(
                    phase,
                    vec![d],
                    format!(
                        "dealer {d}'s defense share fails verification against its commitment"
                    ),
                )),
            };
        }
        Ok(())
    }

    /// The §10.2/§A.4 dealt-share evidence for a §6.1 complaint verdict
    /// (M3b): the blamed dealer's signed P2P share envelope plus its
    /// revealed commitment — exactly what the auditor's offline
    /// `EvalCom` re-check needs. Only the ACCUSER node holds the P2P
    /// envelope, so only it produces the token (every node reaches the
    /// same verdict; the others archive `token: none`). `None` when the
    /// abort is not a dealer fault this node has evidence for.
    fn dealt_share_evidence(
        &self,
        e: &Error,
        complaints: &[PartyId],
        share_env_of: &BTreeMap<PartyId, SignedEnvelope<NodePayload>>,
        r2: &BTreeMap<PartyId, DkgBcast2>,
    ) -> Option<BlameEvidence> {
        let Error::Abort { abort } = e else {
            return None;
        };
        let [d] = abort.blamed[..] else { return None };
        // This node must have complained about d (the dealer-blame
        // branch) and hold d's signed dealt share.
        if !complaints.contains(&d) {
            return None;
        }
        let se = share_env_of.get(&d)?;
        let NodePayload::Dkg(DkgMessage::Share(share)) = &se.envelope.payload else {
            return None;
        };
        let com = &r2.get(&d)?.com;
        if com.verify_share(share.to, &share.share) {
            return None; // a verifying share is not evidence of a fault
        }
        Some(BlameEvidence::DealtShare {
            abort: abort.clone(),
            envelope: se.clone(),
            com: com.clone(),
        })
    }

    /// Per-node Beaver triple generation (SPEC §7.2, M3a): T1 deals joint
    /// random ⟦α⟧, ⟦β⟧ through two ephemeral commit-reveal VSS instances
    /// ([`Self::joint_vss`]); T2 broadcasts this node's re-sharing
    /// commitment `FeldCommit(g_j)` plus ONE DLEQ product proof and sends
    /// the re-shares `g_j(i)` P2P; T3 verifies every proof (F3 ⇒ blame
    /// the prover — the same check everywhere, no complaint round) and
    /// every received re-share (F2 ⇒ the wire §6.1 complaint/defense
    /// rounds), then combines with Lagrange weights (GJKR96-style degree
    /// reduction). Returns this node's [`TripleShare`] and the
    /// [`TriplePublic`] commitments; the share never leaves the node.
    pub fn triple(
        &self,
        sid: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(TripleShare, TriplePublic)> {
        let me = self.me;
        let n = self.params.n;
        let t = self.params.t;
        let phase = Phase::Triples;
        let ids = self.params.parties();

        // T1: joint random [α], [β] — two ephemeral commit-reveal VSS
        // instances over the wire.
        let alpha = self.joint_vss(
            &[sid, b"/alpha"].concat(),
            tags::DKG_COMMIT,
            phase,
            &mut *rng,
            None,
        )?;
        let beta = self.joint_vss(
            &[sid, b"/beta"].concat(),
            tags::DKG_COMMIT,
            phase,
            &mut *rng,
            None,
        )?;
        let (ca, cb) = (alpha.com.clone(), beta.com.clone());

        // T2: local product γ_j = α_j·β_j, re-shared with a fresh
        // degree-(t−1) polynomial g_j; ONE DLEQ product proof binds
        // g_j(0) to α_j·β_j w.r.t. the public commitments. The §6.1
        // defense below is exactly the dealt value (§10.2
        // non-repudiation), so the sent shares are kept.
        let gamma_j = alpha.share * beta.share;
        let g = ShamirPoly::random(gamma_j, t, &mut *rng);
        let c_j = FeldmanCommitment::from_poly(&g);
        let (x1, x2, mut proof) = dleq::prove(
            sid,
            tags::TRIPLE_PRODUCT,
            &alpha.share,
            &ProjectivePoint::GENERATOR,
            &cb.eval_at(me), // β_j·G
            &mut *rng,
        );
        if cheat == Some(Cheat::BadProductProof) {
            proof.z += Scalar::ONE; // malicious: invalid DLEQ product proof (F3)
        }
        self.broadcast(
            sid,
            phase,
            TR_ROUND_DEAL,
            NodePayload::TripleDeal(Box::new(TripleDealMsg {
                com: c_j,
                x1,
                x2,
                proof,
            })),
        );
        let mut sent: BTreeMap<PartyId, Scalar> = BTreeMap::new();
        for &i in &ids {
            let mut s = g.eval(i);
            if let Some(Cheat::BadReshare { victim }) = cheat {
                if victim == i {
                    s += Scalar::ONE; // malicious: wrong re-shared share (F2)
                }
            }
            sent.insert(i, s);
            self.send_p2p(sid, phase, TR_ROUND_DEAL, i, NodePayload::Reshare(s));
        }

        // Collect this node's accepted sets.
        let deal_envs = self.accepted_broadcasts(sid, phase, TR_ROUND_DEAL);
        let resh_envs = self.accepted_p2p(sid, phase, TR_ROUND_DEAL);
        if deal_envs.len() != n || resh_envs.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut deals: BTreeMap<PartyId, TripleDealMsg> = BTreeMap::new();
        for (f, se) in deal_envs {
            match se.envelope.payload {
                NodePayload::TripleDeal(d) => {
                    deals.insert(f, *d);
                }
                _ => {
                    return Err(abort(
                        phase,
                        vec![f],
                        "malformed triple deal broadcast".into(),
                    ))
                }
            }
        }
        let mut mine: BTreeMap<PartyId, Scalar> = BTreeMap::new();
        for (f, se) in resh_envs {
            match se.envelope.payload {
                NodePayload::Reshare(s) => {
                    mine.insert(f, s);
                }
                _ => return Err(abort(phase, vec![f], "malformed re-share envelope".into())),
            }
        }

        // T3a: verify every product proof (F3) — computable identically
        // by every node over the echo-consistent sets; no complaint round.
        for &i in &ids {
            let d = &deals[&i];
            if d.x1 != ca.eval_at(i) // α_i·G
                || d.x2 != d.com.points[0]
                || !dleq::verify(
                    sid,
                    tags::TRIPLE_PRODUCT,
                    &ProjectivePoint::GENERATOR,
                    &d.x1,
                    &cb.eval_at(i), // β_i·G
                    &d.x2,
                    &d.proof,
                )
            {
                // F3 — a signed deal broadcast with an invalid proof is
                // logged (`token: none`; no token shape for proofs, M3b).
                let e = abort(phase, vec![i], "invalid DLEQ product proof".into());
                self.record_abort(&e, None);
                return Err(e);
            }
        }

        // T3b: local re-share checks (F2) → §6.1 complaints/defenses on
        // the wire (the same subprotocol as the commit-reveal VSS).
        let mut complaints: Vec<PartyId> = ids
            .iter()
            .copied()
            .filter(|&i| !deals[&i].com.verify_share(me, &mine[&i]))
            .collect();
        if let Some(Cheat::FalseAccuse { dealer }) = cheat {
            if !complaints.contains(&dealer) {
                complaints.push(dealer); // malicious: false accusation
            }
        }
        if let Err(e) = self.complaint_round(
            sid,
            phase,
            (TR_ROUND_COMPLAIN, TR_ROUND_DEFEND),
            &complaints,
            |a| sent[&a],
            |d, a, s| deals[&d].com.verify_share(a, s),
        ) {
            // M3b: the re-share evidence (a `Reshare` envelope) has no
            // token shape — logged with `token: none` (see
            // `persist::BlameEvidence`).
            self.record_abort(&e, None);
            return Err(e);
        }

        // T3c: combine with Lagrange weights — [γ] = Σ_j λ_j·[g_j]
        // (GJKR96-style degree reduction).
        let lambdas = lagrange_coeffs(&ids);
        let mut cc: Option<FeldmanCommitment> = None;
        for (k, &i) in ids.iter().enumerate() {
            let scaled = deals[&i].com.scale(&lambdas[k]);
            cc = Some(match cc {
                None => scaled,
                Some(acc) => acc.add(&scaled),
            });
        }
        let c_share = ids
            .iter()
            .enumerate()
            .map(|(k, &d)| lambdas[k] * mine[&d])
            .fold(Scalar::ZERO, |acc, x| acc + x);
        Ok((
            TripleShare {
                index: me,
                a: alpha.share,
                b: beta.share,
                c: c_share,
            },
            TriplePublic {
                ca,
                cb,
                cc: cc.expect("n >= 1"),
            },
        ))
    }

    /// Per-node presignature (SPEC §8, P1–P4, M3a): two fresh triples
    /// ([`Self::triple`]) and two ephemeral joint random sharings ⟦u⟧
    /// (:= k⁻¹), ⟦a⟧ ([`Self::joint_vss`]), then the Beaver openings and
    /// nonce points as broadcast rounds. Every broadcast share is checked
    /// against its public commitment by point equality (§4.6 openings are
    /// FAIL-FAST identifiable aborts) and every nonce point against
    /// `EvalCom(A[k], j)` (F5 ⇒ blame the sender). Robust blame-and-
    /// continue (§10.4) is deliberately NOT re-implemented at the wire
    /// level — the core's sim owns it; this driver fails closed.
    /// `v = 0` / `r = 0` return [`Error::ZeroValue`]: the caller retries
    /// with a fresh presignature id. Returns this node's [`Presignature`]
    /// record — it never leaves the node.
    pub fn presign(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Presignature> {
        let t = self.params.t;
        let phase = Phase::Presign;

        // P1–P3 (shared verbatim with the §8.7 KI pool production,
        // [`Self::presign_ki`]): ⟦u⟧ (:= k⁻¹), ⟦a⟧, the Beaver openings
        // and the nonce-point round.
        let (u_j, u_com, r_scalar, big_r) = self.presign_p1_p3(sid, &mut *rng, cheat)?;

        // P4's Beaver triple — the §8.7 KI mode moves exactly this
        // triple session online (K1).
        let (t2, pub2) = self.triple(&[sid, b"/t2"].concat(), &mut *rng, None)?;
        let neg = -Scalar::ONE;

        // P4: z = u·x via triple 2 — ε′ masks this node's OWN long-term
        // key share (the output of its own keygen), binding the
        // presignature to the key; ⟦z⟧ assembled from the openings.
        let d2_com = u_com.add(&pub2.ca.scale(&neg));
        let e2_com = key.com.add(&pub2.cb.scale(&neg));
        self.broadcast(
            sid,
            phase,
            PS_ROUND_Z,
            NodePayload::BeaverOpen {
                first: u_j - t2.a,
                second: key.share - t2.b,
            },
        );
        let (d2s, e2s) = self.collect_beaver_opens(sid, phase, PS_ROUND_Z)?;
        let d2v = self.open_noted(t, &d2_com, &d2s, phase)?;
        let e2v = self.open_noted(t, &e2_com, &e2s, phase)?;
        let z_com = pub2
            .cc
            .clone()
            .add(&pub2.cb.scale(&d2v))
            .add(&pub2.ca.scale(&e2v))
            .add_const(&(d2v * e2v));
        let z_j = t2.c + d2v * t2.b + e2v * t2.a + d2v * e2v;

        Ok(Presignature {
            id,
            index: self.me,
            r: r_scalar,
            big_r,
            u_share: u_j,
            z_share: z_j,
            u_com,
            z_com,
        })
    }

    /// §8 P1–P3 over the wire, verbatim (SPEC §8), shared by
    /// [`Self::presign`] and the §8.7 KI pool production
    /// ([`Self::presign_ki`]): ONE Beaver triple session, the ⟦u⟧
    /// (:= k⁻¹) and ⟦a⟧ joint random sharings, the δ/ε and `v = a·u`
    /// openings, and the nonce-point round (`R_j` checked against
    /// `EvalCom(A[k], j)` — F5 ⇒ blame the sender). Returns this node's
    /// `u`-share and commitment plus the public nonce `(r, R)`.
    fn presign_p1_p3(
        &self,
        sid: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Scalar, FeldmanCommitment, Scalar, AffinePoint)> {
        let n = self.params.n;
        let t = self.params.t;
        let phase = Phase::Presign;

        // One fresh triple (SPEC §7) for the `v = a·u` opening. The
        // dealing cheats (BadProductProof / BadReshare / FalseAccuse)
        // target this session, as in the core's `PresignTamper`.
        let triple_cheat = cheat.filter(|c| {
            matches!(
                c,
                Cheat::BadProductProof | Cheat::BadReshare { .. } | Cheat::FalseAccuse { .. }
            )
        });
        let (t1, pub1) = self.triple(&[sid, b"/t1"].concat(), &mut *rng, triple_cheat)?;

        // P1: ephemeral joint randomness [u] (:= k⁻¹) and [a].
        let u_out = self.joint_vss(
            &[sid, b"/u"].concat(),
            tags::DKG_COMMIT,
            phase,
            &mut *rng,
            None,
        )?;
        let a_out = self.joint_vss(
            &[sid, b"/a"].concat(),
            tags::DKG_COMMIT,
            phase,
            &mut *rng,
            None,
        )?;
        let (u_com, a_com) = (u_out.com.clone(), a_out.com.clone());
        let (u_j, a_j) = (u_out.share, a_out.share);
        let neg = -Scalar::ONE;

        // P2: open δ = u − α, ε = a − β (one broadcast round carries both
        // shares), then form and open v = a·u via triple 1 (Beaver).
        let delta_com = u_com.add(&pub1.ca.scale(&neg));
        let eps_com = a_com.add(&pub1.cb.scale(&neg));
        self.broadcast(
            sid,
            phase,
            PS_ROUND_DELTA_EPS,
            NodePayload::BeaverOpen {
                first: u_j - t1.a,
                second: a_j - t1.b,
            },
        );
        let (deltas, epsilons) = self.collect_beaver_opens(sid, phase, PS_ROUND_DELTA_EPS)?;
        let delta = self.open_noted(t, &delta_com, &deltas, phase)?;
        let eps = self.open_noted(t, &eps_com, &epsilons, phase)?;

        let v_com = pub1
            .cc
            .clone()
            .add(&pub1.cb.scale(&delta))
            .add(&pub1.ca.scale(&eps))
            .add_const(&(delta * eps));
        let mut v_j = t1.c + delta * t1.b + eps * t1.a + delta * eps;
        if cheat == Some(Cheat::BadOpenShare) {
            v_j += Scalar::ONE; // malicious: wrong opening share
        }
        self.broadcast(sid, phase, PS_ROUND_V, NodePayload::OpenShare(v_j));
        let v_shares = self.collect_open_shares(sid, phase, PS_ROUND_V)?;
        let v = self.open_noted(t, &v_com, &v_shares, phase)?;
        if v == Scalar::ZERO {
            // Retry with a fresh presignature id (caller policy).
            return Err(Error::ZeroValue("v = 0".into()));
        }
        let v_inv =
            Option::<Scalar>::from(v.invert()).ok_or_else(|| Error::ZeroValue("v = 0".into()))?;

        // P3: [k] = v⁻¹·[a]; broadcast the nonce point R_j — checked
        // against EvalCom(A[k], j) by every node (F5 ⇒ blame the sender),
        // R = Σ λ_j·R_j, r = F(R).
        let k_com = a_com.scale(&v_inv);
        let mut r_j = ProjectivePoint::GENERATOR * (v_inv * a_j);
        if cheat == Some(Cheat::BadNoncePoint) {
            r_j += ProjectivePoint::GENERATOR; // malicious: wrong nonce point
        }
        self.broadcast(sid, phase, PS_ROUND_NONCE, NodePayload::NoncePoint(r_j));
        let nonce_envs = self.accepted_broadcasts(sid, phase, PS_ROUND_NONCE);
        if nonce_envs.len() != n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut r_points = Vec::with_capacity(n);
        for (f, se) in nonce_envs {
            match se.envelope.payload {
                NodePayload::NoncePoint(p) => {
                    if p != k_com.eval_at(f) {
                        // F5 — logged with `token: none` (M3b; the nonce
                        // evidence has no token shape).
                        let e = abort(phase, vec![f], "invalid nonce point R_j".into());
                        self.record_abort(&e, None);
                        return Err(e);
                    }
                    r_points.push(p);
                }
                _ => return Err(abort(phase, vec![f], "malformed nonce broadcast".into())),
            }
        }
        let lambdas = lagrange_coeffs(&self.params.parties());
        let mut big_r_proj = ProjectivePoint::IDENTITY;
        for (l, rp) in lambdas.iter().zip(r_points.iter()) {
            big_r_proj += *rp * l;
        }
        let big_r = big_r_proj.to_affine();
        let r_encoded = big_r.to_encoded_point(false);
        let r_scalar = scalar_from_digest(r_encoded.x().expect("uncompressed point has x"));
        if r_scalar == Scalar::ZERO {
            // Retry with a fresh presignature id (caller policy).
            return Err(Error::ZeroValue("r = 0".into()));
        }
        Ok((u_j, u_com, r_scalar, big_r))
    }

    /// Per-node KEY-INDEPENDENT pool production (SPEC §8.7 — optional
    /// mode): P1–P3 of [`Self::presign`] verbatim (⟦u⟧ := k⁻¹,
    /// Beaver-derived ⟦k⟧, the nonce-point round with F5 blame) with P4
    /// OMITTED — no key is involved at generation time, and the record
    /// consumes ONE triple (P4's triple moves online, [`Self::sign_ki`]).
    /// The record is key-free and NOT key-equivalent (`t` pool shares
    /// reveal nothing about any long-term key); it binds to a key only at
    /// signing time. Still strictly SINGLE-USE (§8.6(1) — nonce reuse is
    /// fatal under ANY key). `v = 0` / `r = 0` return
    /// [`Error::ZeroValue`]: retry with a fresh id. Returns this node's
    /// [`KiPresignature`] — it never leaves the node.
    pub fn presign_ki(
        &self,
        sid: &[u8],
        id: u64,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KiPresignature> {
        let (u_j, u_com, r, big_r) = self.presign_p1_p3(sid, rng, cheat)?;
        Ok(KiPresignature {
            id,
            index: self.me,
            r,
            big_r,
            u_share: u_j,
            u_com,
        })
    }

    /// [`Self::presign_ki`] plus insertion into this node's in-memory
    /// key-free pool (§8.7; duplicate ids rejected, §8.6(1)). Returns the
    /// record's public nonce `r` — the shares stay inside the pool.
    pub fn presign_ki_pooled(
        &self,
        sid: &[u8],
        id: u64,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Scalar> {
        let record = self.presign_ki(sid, id, rng, cheat)?;
        let r = record.r;
        self.ki_pool
            .lock()
            .expect("mesh mutex poisoned")
            .insert(record)?;
        Ok(r)
    }

    /// Per-node KI online signing (SPEC §8.7, Protocol 8.7.1): TWO
    /// broadcast rounds binding the pool record to `key` online. R1
    /// generates a FRESH triple ([`Self::triple`]) and opens δ = ⟦u⟧−⟦α⟧,
    /// ε = ⟦x⟧−⟦β⟧ — exactly the §8 P4 masking, run online; every share
    /// is point-checked against `A[u]−A[α]` / `A[x]−A[β]` (fail-fast
    /// identifiable abort). R2 computes ⟦z⟧ locally
    /// ([`sign::ki_z_share`]) and broadcasts `s_j = m·u_j + r·z_j`,
    /// verified against `m·A[u] + r·A[z]` by [`sign::combine_ki`]
    /// (fail-fast — the §10.4 robust continuation stays in the core's
    /// sim), low-`s` normalized. Cheats: `BadOpenShare` corrupts this
    /// node's R1 δ-share, `BadSignShare` its R2 share; the dealing cheats
    /// forward to the R1 triple session.
    pub fn sign_ki(
        &self,
        sid: &[u8],
        presig: &KiPresignature,
        key: &KeyShare,
        msg: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Signature> {
        let t = self.params.t;
        let phase = Phase::Sign;
        let m = ohm_ecdsa::sim::message_scalar(msg);

        // R1 (SPEC §8.7 K1): a fresh Beaver triple, then the verified δ/ε
        // openings. The dealing cheats target the triple session (same
        // filter as the presign driver).
        let triple_cheat = cheat.filter(|c| {
            matches!(
                c,
                Cheat::BadProductProof | Cheat::BadReshare { .. } | Cheat::FalseAccuse { .. }
            )
        });
        let (t_share, t_pub) = self.triple(&[sid, b"/triple"].concat(), &mut *rng, triple_cheat)?;
        let neg = -Scalar::ONE;
        let delta_com = presig.u_com.add(&t_pub.ca.scale(&neg));
        let eps_com = key.com.add(&t_pub.cb.scale(&neg));
        let mut delta_j = presig.u_share - t_share.a;
        if cheat == Some(Cheat::BadOpenShare) {
            delta_j += Scalar::ONE; // malicious: wrong R1 opening share
        }
        self.broadcast(
            sid,
            phase,
            KI_ROUND_OPEN,
            NodePayload::BeaverOpen {
                first: delta_j,
                second: key.share - t_share.b,
            },
        );
        let (deltas, epsilons) = self.collect_beaver_opens(sid, phase, KI_ROUND_OPEN)?;
        let delta = self.open_noted(t, &delta_com, &deltas, phase)?;
        let eps = self.open_noted(t, &eps_com, &epsilons, phase)?;

        // R2 (SPEC §8.7 K2): local z-share + sign share, verified
        // combine against m·A[u] + r·A[z].
        let z_com = sign::ki_z_com(&t_pub, &delta, &eps);
        let z_j = sign::ki_z_share(&t_share, &delta, &eps);
        let mut share = sign::sign_share_ki(presig, &z_j, &m);
        if cheat == Some(Cheat::BadSignShare) {
            share.s += Scalar::ONE; // malicious: wrong R2 signature share
        }
        self.broadcast(
            sid,
            phase,
            KI_ROUND_SHARE,
            NodePayload::SignShare {
                presig: presig.id,
                s: share.s,
            },
        );
        let set = self.accepted_broadcasts(sid, phase, KI_ROUND_SHARE);
        let mut shares = Vec::with_capacity(set.len());
        // The signed share envelopes, kept for the §10.2/§A.4 sign-share
        // blame evidence (M3b) — same token shape as the §9 driver.
        let mut share_env_of: BTreeMap<PartyId, SignedEnvelope<NodePayload>> = BTreeMap::new();
        for (f, se) in set {
            match &se.envelope.payload {
                NodePayload::SignShare { presig: pid, s } if *pid == presig.id => {
                    shares.push(SignShare { from: f, s: *s });
                    share_env_of.insert(f, se);
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
        // Fail-fast verified combine (§8.7): a bad share aborts blaming
        // its sender — with the F6 sign-share token archived per blamed
        // sender (M3b), exactly as in the §9 driver.
        let (r, s) = match sign::combine_ki(&self.params, presig, &z_com, &m, &shares) {
            Ok(rs) => rs,
            Err(e) => {
                if let Error::Abort { abort } = &e {
                    for &f in &abort.blamed {
                        if let Some(se) = share_env_of.get(&f) {
                            let single = IdentifiableAbort {
                                phase,
                                blamed: vec![f],
                                detail: abort.detail.clone(),
                            };
                            self.note(
                                &single,
                                Some(BlameEvidence::SignShare {
                                    abort: single.clone(),
                                    envelope: se.clone(),
                                    message: msg.to_vec(),
                                    r: presig.r,
                                    u_com: presig.u_com.clone(),
                                    z_com: z_com.clone(),
                                }),
                            );
                        }
                    }
                }
                return Err(e);
            }
        };
        let sig = Signature::from_scalars(r, s)?;
        Ok(sig.normalize_s().unwrap_or(sig))
    }

    /// [`Self::sign_ki`] with the pool record ATOMICALLY CONSUMED from
    /// this node's in-memory key-free pool first (§8.6(1) transactional
    /// delete): an unknown or consumed id surfaces the core pool's error
    /// and no share is broadcast.
    pub fn sign_ki_pooled(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        msg: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Signature> {
        let record = self
            .ki_pool
            .lock()
            .expect("mesh mutex poisoned")
            .consume(id)?;
        self.sign_ki(sid, &record, key, msg, rng, cheat)
    }

    /// Core `open` with M3b abort archiving (`token: none` — the
    /// opening-share evidence has no token shape, see
    /// `persist::BlameEvidence`).
    fn open_noted(
        &self,
        t: usize,
        com: &FeldmanCommitment,
        shares: &BTreeMap<PartyId, Scalar>,
        phase: Phase,
    ) -> Result<Scalar> {
        let out = open(t, com, shares, phase);
        if let Err(e) = &out {
            self.record_abort(e, None);
        }
        out
    }

    /// Collect a round of single-scalar opening shares (fail-closed on an
    /// incomplete accepted set; malformed payloads blame the sender).
    fn collect_open_shares(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> Result<BTreeMap<PartyId, Scalar>> {
        let envs = self.accepted_broadcasts(sid, phase, round);
        if envs.len() != self.params.n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut out = BTreeMap::new();
        for (f, se) in envs {
            match se.envelope.payload {
                NodePayload::OpenShare(s) => {
                    out.insert(f, s);
                }
                _ => return Err(abort(phase, vec![f], "malformed opening broadcast".into())),
            }
        }
        Ok(out)
    }

    /// Collect a round of paired Beaver opening shares (δ/ε or δ′/ε′).
    #[allow(clippy::type_complexity)] // (δ-shares, ε-shares) — the round's two artifacts
    fn collect_beaver_opens(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> Result<(BTreeMap<PartyId, Scalar>, BTreeMap<PartyId, Scalar>)> {
        let envs = self.accepted_broadcasts(sid, phase, round);
        if envs.len() != self.params.n {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut first = BTreeMap::new();
        let mut second = BTreeMap::new();
        for (f, se) in envs {
            match se.envelope.payload {
                NodePayload::BeaverOpen {
                    first: a,
                    second: b,
                } => {
                    first.insert(f, a);
                    second.insert(f, b);
                }
                _ => return Err(abort(phase, vec![f], "malformed opening broadcast".into())),
            }
        }
        Ok((first, second))
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
        // The signed share envelopes, kept for the §10.2/§A.4 sign-share
        // blame evidence (M3b).
        let mut share_env_of: BTreeMap<PartyId, SignedEnvelope<NodePayload>> = BTreeMap::new();
        for (f, se) in set {
            match &se.envelope.payload {
                NodePayload::SignShare { presig: pid, s } if *pid == presig.id => {
                    shares.push(SignShare { from: f, s: *s });
                    share_env_of.insert(f, se);
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
        // M3b (§10.2/§A.4): archive the F6 sign-share token for every
        // blamed sender — the signed share envelope plus the public data
        // the auditor recomputes the failed check from.
        for &f in &blamed {
            if let Some(se) = share_env_of.get(&f) {
                let abort = IdentifiableAbort {
                    phase,
                    blamed: vec![f],
                    detail: "signature share failed commitment check".into(),
                };
                self.note(
                    &abort.clone(),
                    Some(BlameEvidence::SignShare {
                        abort,
                        envelope: se.clone(),
                        message: msg.to_vec(),
                        r: presig.r,
                        u_com: presig.u_com.clone(),
                        z_com: presig.z_com.clone(),
                    }),
                );
            }
        }
        let sig = Signature::from_scalars(r, s)?;
        Ok((sig.normalize_s().unwrap_or(sig), blamed))
    }

    /// M3b (§8.6): [`Self::presign`] plus durable persistence — the
    /// produced record is written to the configured store
    /// ([`Self::set_store`], write-tmp-rename + fsync) before returning.
    /// Without a configured store this behaves exactly like
    /// [`Self::presign`].
    pub fn presign_stored(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> std::result::Result<Presignature, PersistError> {
        let presig = self.presign(sid, id, key, rng, cheat)?;
        let mut guard = self.store.lock().expect("mesh mutex poisoned");
        if let Some(store) = guard.as_mut() {
            store.insert(&presig)?;
        }
        Ok(presig)
    }

    /// M3b (§8.6): persist an EXTERNALLY produced presignature record
    /// into the configured store (the `--seeded` ceremony fallback seeds
    /// its records this way). An id that is already persisted — live or
    /// consumed — is a no-op (`Ok(false)`), so re-seeding after a
    /// restart is safe; I/O failures propagate.
    pub fn store_offer(&self, presig: &Presignature) -> std::result::Result<bool, PersistError> {
        let mut guard = self.store.lock().expect("mesh mutex poisoned");
        let Some(store) = guard.as_mut() else {
            return Ok(false);
        };
        match store.insert(presig) {
            Ok(()) => Ok(true),
            Err(PersistError::Protocol(Error::PresigStore(_))) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// M3b (§8.6): [`Self::sign`] with the presignature consumed from
    /// the configured durable store ([`Self::set_store`]): the consume
    /// tombstone is fsync'd BEFORE the share is broadcast, so a
    /// kill/restart can never sign twice with the same presignature
    /// (§8.6(1) atomic consume across a crash). Unknown or consumed ids
    /// surface the core store's error.
    pub fn sign_stored(
        &self,
        sid: &[u8],
        presig_id: u64,
        msg: &[u8],
        cheat: Option<Cheat>,
    ) -> std::result::Result<(Signature, Vec<PartyId>), PersistError> {
        let presig = {
            let mut guard = self.store.lock().expect("mesh mutex poisoned");
            guard
                .as_mut()
                .ok_or(Error::PresigStore("no store configured"))?
                .consume(presig_id)?
        };
        Ok(self.sign(sid, &presig, msg, cheat)?)
    }
}
