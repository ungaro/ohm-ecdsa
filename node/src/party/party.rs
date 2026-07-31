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
//!   identifiable aborts (the default posture — some deployments prefer
//!   loud aborts; the §10.4 robust continuation is the OPT-IN
//!   [`PartyNode::presign_robust`] below). `v = 0` / `r = 0` return
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
//! H4 (§10.4 robust continuation + §10.3 expel-and-restart — OPT-IN):
//!
//! * [`PartyNode::presign_robust`] — the §10.4 blame-and-continue
//!   presign: every opening (δ/ε, v, δ′/ε′) goes through the core's
//!   `open_robust` (bad shares filtered, senders blamed — identical
//!   verdicts at every node, since the checks are point equality on
//!   public data over echo-consistent sets), nonce points are filtered
//!   individually and `R` interpolates over the valid senders, and the
//!   blamed are expelled from subsequent rounds' share sets. Returns the
//!   record plus the accumulated blame.
//! * [`PartyNode::triple_robust`] — the §10.4 triple: T3 re-share faults
//!   are recovered by PUBLIC RECONSTRUCTION over two added broadcast
//!   rounds — `ReshareRequests` (a victim broadcasts the dealer's own
//!   signed `Reshare` envelope as self-authenticating evidence; every
//!   node re-verifies signature + failing `EvalCom`, so a fabricated
//!   request blames the requester) and `ReshareSupply` (every node
//!   broadcasts the re-share it received from each dealer in the
//!   reconstruction set; the first `t` supplies verifying against the
//!   dealer's commitment interpolate the cheater's committed
//!   polynomial). Cost: +1 round per triple session honestly, +2 on a
//!   re-share fault. Dealing-phase faults (F1/F2-on-wire/F3) stay
//!   fail-fast everywhere — §10.3 owns them.
//! * [`PartyNode::sign_ki_robust`] — the §10.4 KI sign: robust R1
//!   openings + `sign::combine_ki_robust` in R2; F6 blame tokens still
//!   archived per blamed sender. ([`PartyNode::sign`] was already robust
//!   by construction.)
//! * [`PartyNode::keygen_with_restart`] /
//!   [`PartyNode::presign_with_restart`] — the §10.3 expel-and-restart
//!   policy at the driver level: on a dealing-phase abort every node
//!   deterministically computes the SAME surviving committee (the core's
//!   `policy::restart_committee` — never lowering `t`; zero-slack
//!   refusal propagates the abort with the refusal noted), poisons the
//!   sid (§10.3(2)) — and the presignature id per restarted attempt —
//!   and re-runs over the survivors with ORIGINAL ids preserved (their
//!   key shares stay valid; unlike the sim's keygen restart, the wire
//!   restart never renumbers — the transport registry pins the ids).
//!   The presign wrapper COMPOSES the two layers exactly like the sim's
//!   `run_presign_with_restart`: robust continuation in-attempt, restart
//!   only for dealing-phase aborts. Retries are inherently bounded
//!   (every restart expels ≥ 1 party; the policy refuses below
//!   `n′ < 2t−1`). [`PartyNode::sign_over`] / [`PartyNode::sign_stored_over`]
//!   sign over the post-restart committee.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, SecretKey};
use rand::RngCore;

use ohm_ecdsa::dkg::{DkgBcast2, DkgInstance, DkgP2P};
use ohm_ecdsa::dleq::{self, DleqProof};
use ohm_ecdsa::open::{open, open_robust};
use ohm_ecdsa::presign::{KeyShare, KiPresignature, Presignature};
use ohm_ecdsa::shamir::{lagrange_coeffs, ShamirPoly};
use ohm_ecdsa::sign::{self, SignShare};
use ohm_ecdsa::store::KiPool;
use ohm_ecdsa::transport::{Decode, DkgMessage, Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::triples::{TriplePublic, TripleShare};
use ohm_ecdsa::vss::FeldmanCommitment;
use ohm_ecdsa::{
    hash_commitment, scalar_from_digest, tags, Committee, Error, IdentifiableAbort, Params,
    PartyId, Phase, Result,
};

use crate::mesh::{MeshMetrics, Node, INBOX_BOUND};
use crate::persist::{Archive, BlameEvidence, DiskPresigStore, PersistError};
use crate::tls::CommitteeTls;
use crate::wire::{take_u64, FrameBound, Received, MAX_SID};

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
/// H4 §10.4 reconstruction requests ride round 4 (every node broadcasts,
/// possibly empty — the round must complete everywhere for the verdict
/// to be consistent).
pub const TR_ROUND_RECON_REQ: u8 = 4;
/// H4 §10.4 reconstruction supplies ride round 5 (only when the request
/// union is non-empty — a deterministic, publicly-computable condition).
pub const TR_ROUND_RECON_SUPPLY: u8 = 5;

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

/// The collector thread's mailbox poll interval in milliseconds (H2):
/// how quickly the collector notices shutdown. NOT a liveness timeout —
/// round liveness is bounded by the drivers' round timeout.
const READ_POLL_MS: u64 = 250;

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
    /// H4 §10.4 triple reconstruction, request round: for each dealer
    /// whose T2 re-shared share failed the commitment check AT THIS NODE,
    /// the dealer's id plus the dealer's own signed `Reshare` envelope —
    /// self-authenticating evidence: the share inside fails `EvalCom`
    /// against the dealer's public commitment (dealer blamed) or it does
    /// not (the requester is fabricating and is blamed instead). Empty =
    /// no faults seen here — the round must still complete for every
    /// sender, exactly like the §6.1 complaint round.
    ReshareRequests(Vec<(PartyId, SignedEnvelope<NodePayload>)>),
    /// H4 §10.4 triple reconstruction, supply round: this node's received
    /// re-shared share `g_d(me)` for every dealer `d` in the
    /// reconstruction set (the sorted union of the verified requests),
    /// in dealer order. Every node interpolates the cheater's committed
    /// re-sharing polynomial from the first `t` supplies that verify
    /// against the dealer's public commitment.
    ReshareSupply(Vec<(PartyId, Scalar)>),
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
            Self::ReshareRequests(reqs) => {
                out.push(10);
                out.extend_from_slice(&(reqs.len() as u64).to_be_bytes());
                for (dealer, se) in reqs {
                    out.extend_from_slice(&(*dealer as u64).to_be_bytes());
                    se.encode(out);
                }
            }
            Self::ReshareSupply(supplies) => {
                out.push(11);
                out.extend_from_slice(&(supplies.len() as u64).to_be_bytes());
                for (dealer, share) in supplies {
                    out.extend_from_slice(&(*dealer as u64).to_be_bytes());
                    share.encode(out);
                }
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
            10 => {
                let (n, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let mut reqs = Vec::new();
                for _ in 0..n {
                    let (d, u) = take_u64(bytes.get(used..)?)?;
                    used += u;
                    let (se, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                    used += u;
                    reqs.push((usize::try_from(d).ok()?, se));
                }
                Some((Self::ReshareRequests(reqs), used))
            }
            11 => {
                let (n, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let mut supplies = Vec::new();
                for _ in 0..n {
                    let (d, u) = take_u64(bytes.get(used..)?)?;
                    used += u;
                    let (s, u) = Scalar::decode(bytes.get(used..)?)?;
                    used += u;
                    supplies.push((usize::try_from(d).ok()?, s));
                }
                Some((Self::ReshareSupply(supplies), used))
            }
            _ => None,
        }
    }
}

/// H2 per-variant frame bounds (see `wire::FrameBound`): derived from
/// the exact canonical sizes below (points 33 B compressed, scalars
/// 32 B, ids/`u64` prefixes 8 B; threshold-degree commitment vectors
/// bounded by `n`, the worst case for `t`), rounded up with slack.
impl FrameBound for NodePayload {
    fn payload_variant_max(&self, n: usize) -> u64 {
        let n = n as u64;
        match self {
            // Commit: 1+1+8+40 = 50; Reveal: 1+1+8+(8+33n); Share: 50.
            Self::Dkg(_) => 64 + 40 * n,
            // 1 + 8 + 8n ids.
            Self::Complaints(_) => 16 + 8 * n,
            // 1 + 8 + 40n (id + scalar per defense).
            Self::Defenses(_) => 16 + 40 * n,
            // 1 + 8 + 32.
            Self::SignShare { .. } => 64,
            // 1 + (8+33n) commitment + 2×33 statement points
            // + (2×33 + 32) proof = 173 + 33n.
            Self::TripleDeal(_) => 256 + 40 * n,
            // 1 + 32.
            Self::Reshare(_) => 48,
            // 1 + 2×32.
            Self::BeaverOpen { .. } => 96,
            // 1 + 32.
            Self::OpenShare(_) => 48,
            // 1 + 33.
            Self::NoncePoint(_) => 48,
            // 1 + 8 + per request (8 id + a full signed envelope:
            // ~100 + sid envelope overhead + 33 Reshare payload + 64
            // signature) = 16 + ~270n; 400n is generous slack.
            Self::ReshareRequests(_) => 16 + 400 * n,
            // 1 + 8 + 40n (id + scalar per supply).
            Self::ReshareSupply(_) => 16 + 48 * n,
        }
    }

    fn family_max(n: usize) -> u64 {
        // The ReshareRequests bound (the largest variant).
        16 + 400 * n as u64
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

/// The T2 artifacts shared by the fail-fast and §10.4-robust T3 paths
/// of the triple driver: every dealer's deal broadcast, this node's
/// received re-shares (with the signed envelopes — the H4 reconstruction
/// requests carry them as evidence), and the shares this node sent.
struct TripleT2 {
    deals: BTreeMap<PartyId, TripleDealMsg>,
    mine: BTreeMap<PartyId, Scalar>,
    sent: BTreeMap<PartyId, Scalar>,
    resh_envs: BTreeMap<PartyId, SignedEnvelope<NodePayload>>,
}

/// One distinct signed broadcast payload and the parties that echoed it.
struct Candidate {
    env: SignedEnvelope<NodePayload>,
    echoers: BTreeSet<PartyId>,
}

/// Acceptor-level memory caps (H2): only verified, registered senders
/// reach the acceptor, but a committee member can still flood distinct
/// session ids or equivocate with many payloads per broadcast slot —
/// bound both. A dropped frame increments `dropped` (see
/// [`PartyNode::acceptor_drops`]); a silent drop is a bug.
const MAX_TRACKED_SIDS: usize = 4096;
const MAX_CANDIDATES_PER_SLOT: usize = 8;

/// The per-node echo-broadcast acceptor: same rule as M1
/// (`⌈(n+1)/2⌉` distinct echoers OTHER than the sender), but fed by this
/// node's mailbox ONLY — including the node's own echo via the mesh's
/// self-echo loopback (M1 counted it through the peers' mailboxes).
struct Acceptor {
    majority: usize,
    bcast: BTreeMap<SlotKey, BTreeMap<Vec<u8>, Candidate>>,
    p2p: BTreeMap<SlotKey, BTreeMap<PartyId, SignedEnvelope<NodePayload>>>,
    /// Distinct session ids admitted so far (H2 cap).
    sids: BTreeSet<Vec<u8>>,
    /// Frames dropped by the H2 caps.
    dropped: u64,
}

impl Acceptor {
    fn new(n: usize) -> Self {
        Self {
            majority: (n + 2) / 2,
            bcast: BTreeMap::new(),
            p2p: BTreeMap::new(),
            sids: BTreeSet::new(),
            dropped: 0,
        }
    }

    /// H2 admission control for session ids: a sid longer than
    /// [`MAX_SID`] or beyond the distinct-sid cap is dropped + counted
    /// (the "unknown-sid / wrong-phase" early filter — a frame for a
    /// session this node never runs lands in a slot nothing queries,
    /// and the cap keeps such slots bounded).
    fn admit_sid(&mut self, sid: &[u8]) -> bool {
        if self.sids.contains(sid) {
            return true;
        }
        if sid.len() as u64 > MAX_SID || self.sids.len() >= MAX_TRACKED_SIDS {
            self.dropped += 1;
            return false;
        }
        self.sids.insert(sid.to_vec());
        true
    }

    fn process(&mut self, msg: Received<NodePayload>) {
        match msg {
            Received::Original(se) => {
                if !self.admit_sid(&se.envelope.sid) {
                    return;
                }
                match se.envelope.to {
                    None => {
                        let (key, payload) = slot_and_payload(&se);
                        let payloads = self.bcast.entry(key).or_default();
                        // H2: an equivocating sender can mint unbounded
                        // distinct payloads per slot — cap the candidates.
                        if payloads.len() >= MAX_CANDIDATES_PER_SLOT
                            && !payloads.contains_key(&payload)
                        {
                            self.dropped += 1;
                            return;
                        }
                        payloads.entry(payload).or_insert_with(|| Candidate {
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
                }
            }
            Received::Echo { echoer, original } => {
                if !self.admit_sid(&original.envelope.sid) {
                    return;
                }
                let (key, payload) = slot_and_payload(&original);
                let payloads = self.bcast.entry(key).or_default();
                if payloads.len() >= MAX_CANDIDATES_PER_SLOT && !payloads.contains_key(&payload) {
                    self.dropped += 1;
                    return;
                }
                let candidate = payloads.entry(payload).or_insert_with(|| Candidate {
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

/// §10.4 expulsion bookkeeping (mirrors the core's `presign_robust`
/// discipline): blame accumulates (sorted, dedup'd) and the blamed leave
/// the active set — their later shares are ignored everywhere.
fn expel(blamed: &mut Vec<PartyId>, active: &mut Vec<PartyId>, new: Vec<PartyId>) {
    for b in new {
        if !blamed.contains(&b) {
            blamed.push(b);
        }
        active.retain(|p| *p != b);
    }
    blamed.sort_unstable();
}

/// §10.3(2): the sid of a failed attempt is poisoned — never reused
/// (same derivation as the core sim's restart wrappers).
fn poison_sid(sid: &[u8], attempt: u64) -> Vec<u8> {
    if attempt == 0 {
        return sid.to_vec();
    }
    [sid, b"/retry-", &attempt.to_be_bytes()].concat()
}

/// A per-party M2 node: exactly its own transport key, id, and mesh.
///
/// H2 concurrency: a dedicated collector thread drains the mesh mailbox
/// into the shared acceptor and wakes the round waiters via a condvar,
/// so ANY NUMBER of protocol sessions may be in flight concurrently —
/// the acceptor demultiplexes by `(sid, phase, round)` and each driver
/// thread waits only on its own session's slots (sign shares against an
/// existing presignature interleave with the offline factory's
/// keygen/triples/presign sessions). [`PartyNode::shutdown`] (also on
/// `Drop`) stops the mesh and joins the collector.
pub struct PartyNode {
    me: PartyId,
    params: Params,
    key: SigningKey,
    /// The PUBLIC party verifying keys (H4: the §10.4 reconstruction
    /// verdict re-verifies a carried envelope against its claimed
    /// sender's key — public data, no secret material).
    registry: BTreeMap<PartyId, VerifyingKey>,
    node: Node<NodePayload>,
    /// The acceptor plus the condvar waking round waiters (H2).
    state: Arc<(Mutex<Acceptor>, Condvar)>,
    timeout: Duration,
    /// H2: drains the mesh mailbox into `state` (see the struct docs).
    collector: Mutex<Option<JoinHandle<()>>>,
    /// H2: set by [`PartyNode::shutdown`]; the collector exits.
    shutdown_flag: Arc<AtomicBool>,
    /// M3b: the durable presignature store (§8.6), configured per key.
    /// Shared (Arc) with the H5 pool manager ([`crate::pool`]) — the
    /// manager is the only WRITER (insert/expire), signing only
    /// CONSUMES through the same instance.
    store: Arc<Mutex<Option<DiskPresigStore>>>,
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
        let (tx, rx) = mpsc::sync_channel(INBOX_BOUND);
        let node = match tls {
            Some(tls) => Node::bind_tls(me, bind, transport_key, registry.clone(), tx, tls)?,
            None => Node::bind(me, bind, transport_key, registry.clone(), tx)?,
        };
        // The per-node acceptor counts this node's own echo through its
        // own mailbox (M1's orchestrator counted it globally).
        node.set_self_echo_loopback(true);
        let state = Arc::new((Mutex::new(Acceptor::new(params.n)), Condvar::new()));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        // H2: the collector thread — the ONLY receiver of the mesh
        // mailbox — so concurrent session drivers never serialize on a
        // blocking receive. It polls so shutdown is responsive.
        let collector = {
            let state = Arc::clone(&state);
            let flag = Arc::clone(&shutdown_flag);
            thread::spawn(move || loop {
                match rx.recv_timeout(Duration::from_millis(READ_POLL_MS)) {
                    Ok(msg) => {
                        let (lock, cvar) = &*state;
                        lock.lock().expect("mesh mutex poisoned").process(msg);
                        cvar.notify_all();
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if flag.load(Ordering::SeqCst) {
                            return;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            })
        };
        Ok(Self {
            me,
            params,
            key: SigningKey::from(transport_key),
            registry,
            node,
            state,
            timeout: round_timeout,
            collector: Mutex::new(Some(collector)),
            shutdown_flag,
            store: Arc::new(Mutex::new(None)),
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

    /// The reconnection policy for dropped peer connections (H2; see
    /// [`crate::mesh::ReconnectConfig`]).
    pub fn set_reconnect(&self, cfg: crate::mesh::ReconnectConfig) {
        self.node.set_reconnect(cfg);
    }

    /// The mesh's drop/reject/reconnect counters (H2).
    pub fn metrics(&self) -> MeshMetrics {
        self.node.metrics()
    }

    /// Frames dropped by the acceptor-level H2 caps (distinct-sid and
    /// per-slot candidate bounds).
    pub fn acceptor_drops(&self) -> u64 {
        self.state.0.lock().expect("mesh mutex poisoned").dropped
    }

    /// Clean shutdown (H2): stops the mesh (listeners, readers,
    /// reconnection, outgoing connections — see [`Node::shutdown`]) and
    /// joins the collector thread. Idempotent; also run on `Drop`.
    /// In-flight sessions fail closed on their next round timeout.
    pub fn shutdown(&self) {
        self.node.shutdown();
        self.shutdown_flag.store(true, Ordering::SeqCst);
        // Wake any round waiters so they can observe their deadlines.
        self.state.1.notify_all();
        if let Some(h) = self.collector.lock().expect("mesh mutex poisoned").take() {
            let _ = h.join();
        }
    }

    /// TEST HOOK (H2): drop the outgoing connection to `peer` and start
    /// the reconnector (journal re-sync re-delivers in-flight messages).
    #[doc(hidden)]
    pub fn debug_drop_outgoing(&self, peer: PartyId) {
        self.node.debug_drop_outgoing(peer);
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
        let storage_key = crate::seal::StorageKey::resolve_or_generate(dir)?;
        let store = DiskPresigStore::open(dir, public_key, &storage_key)?;
        *self.store.lock().expect("mesh mutex poisoned") = Some(store);
        Ok(())
    }

    /// H5: the shared store handle for the pool manager
    /// ([`crate::pool::PoolManager`]) — the SAME instance
    /// [`Self::sign_stored`] consumes from, so pool maintenance (the
    /// single writer: insert/expire) and signing (atomic consume) share
    /// one view of the directory. `None` until [`Self::set_store`] runs.
    pub fn store_handle(&self) -> Arc<Mutex<Option<DiskPresigStore>>> {
        Arc::clone(&self.store)
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

    /// M3b archiving for §10.4-robust blame (H4): one `aborts.log` entry
    /// per blamed party (`token: none` — the opening/re-share evidence
    /// has no token shape, see `persist::BlameEvidence`; the sign
    /// drivers archive F6 `SignShare` tokens separately). Non-fatal on
    /// I/O failure.
    fn note_blamed(&self, phase: Phase, blamed: &[PartyId], detail: &str) {
        for &f in blamed {
            self.note(
                &IdentifiableAbort {
                    phase,
                    blamed: vec![f],
                    detail: detail.to_string(),
                },
                None,
            );
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
            let (lock, cvar) = &*self.state;
            lock.lock()
                .expect("mesh mutex poisoned")
                .process(Received::Original(signed));
            cvar.notify_all();
            return;
        }
        self.node
            .send_to(to, &crate::wire::WireMessage::Original(signed));
    }

    /// The accepted broadcast set of one round (blocks until every
    /// committee member has an accepted value or the round timeout fires;
    /// on timeout the PARTIAL set is returned and logged — the drivers
    /// fail closed on it). H2: waits on the acceptor condvar, so any
    /// number of concurrent sessions (distinct sids) progress together.
    pub fn accepted_broadcasts(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        self.accepted_broadcasts_over(sid, phase, round, &self.params.parties())
    }

    /// [`Self::accepted_broadcasts`] over an explicit id set (H4 §10.3:
    /// restart sessions run over the surviving committee with ORIGINAL
    /// ids — rounds complete on the survivors' values only). The
    /// echo-acceptance quorum is unchanged (`⌈(n+1)/2⌉` over the full
    /// registry: echoes come from every live mesh, including expelled
    /// parties' — safety follows from the first-echo-per-slot rule;
    /// liveness holds while expelled parties' meshes keep echoing, the
    /// same assumption as the rest of the active-cheater model — a
    /// crash-stop is the separate H2 crash-recovery gap).
    pub fn accepted_broadcasts_over(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        ids: &[PartyId],
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        let deadline = Instant::now() + self.timeout;
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().expect("mesh mutex poisoned");
        loop {
            let set = guard.bcast_set(sid, phase, round, ids);
            if set.len() == ids.len() {
                drop(guard);
                self.log_accepted(&set);
                return set;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} broadcasts; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                drop(guard);
                self.log_accepted(&set);
                return set;
            }
            guard = cvar
                .wait_timeout(guard, remaining)
                .expect("mesh mutex poisoned")
                .0;
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
        self.accepted_p2p_over(sid, phase, round, &self.params.parties())
    }

    /// [`Self::accepted_p2p`] over an explicit id set (H4 §10.3 — see
    /// [`Self::accepted_broadcasts_over`]).
    pub fn accepted_p2p_over(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        ids: &[PartyId],
    ) -> BTreeMap<PartyId, SignedEnvelope<NodePayload>> {
        let deadline = Instant::now() + self.timeout;
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().expect("mesh mutex poisoned");
        loop {
            let set = guard.p2p_set(sid, phase, round, self.me);
            let set: BTreeMap<PartyId, _> =
                set.into_iter().filter(|(f, _)| ids.contains(f)).collect();
            if set.len() == ids.len() {
                drop(guard);
                self.log_accepted(&set);
                return set;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                eprintln!(
                    "[node {}] TIMEOUT waiting for {phase} round {round} p2p; \
                     failing closed on the partial accepted set (SPEC §13.1)",
                    self.me
                );
                drop(guard);
                self.log_accepted(&set);
                return set;
            }
            guard = cvar
                .wait_timeout(guard, remaining)
                .expect("mesh mutex poisoned")
                .0;
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
        self.joint_vss_over(sid, tag, phase, &self.params.parties(), rng, cheat)
    }

    /// [`Self::joint_vss`] over an explicit committee (H4 §10.3 restart
    /// sessions run over the surviving ORIGINAL ids).
    pub fn joint_vss_over(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        phase: Phase,
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KeyShare> {
        let out = self.joint_vss_run(sid, tag, phase, ids, rng, cheat);
        // H2: the session is over — drop its reconnect journal entries
        // (prefix match covers any derived sub-session sids).
        self.node.retire_session(sid);
        out
    }

    fn joint_vss_run(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        phase: Phase,
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KeyShare> {
        let me = self.me;
        let n = ids.len();
        let t = self.params.t;
        let committee = Committee::new(ids.to_vec(), t)?;

        // Round 1: commit; round 2: reveal + P2P shares.
        let (inst, b1) = DkgInstance::start_committee(&committee, sid, tag, me, rng);
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
        let r1_envs = self.accepted_broadcasts_over(sid, phase, VSS_ROUND_COMMIT, ids);
        let r2_envs = self.accepted_broadcasts_over(sid, phase, VSS_ROUND_REVEAL, ids);
        let share_envs = self.accepted_p2p_over(sid, phase, VSS_ROUND_REVEAL, ids);
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
        for &i in ids {
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
        let mut complaints: Vec<PartyId> = ids
            .iter()
            .copied()
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
            ids,
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
        for &i in ids {
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
    #[allow(clippy::too_many_arguments)] // the subprotocol's full context (H4: + the committee)
    fn complaint_round(
        &self,
        sid: &[u8],
        phase: Phase,
        rounds: (u8, u8),
        ids: &[PartyId],
        complaints: &[PartyId],
        defense_for: impl Fn(PartyId) -> Scalar,
        defense_verifies: impl Fn(PartyId, PartyId, &Scalar) -> bool,
    ) -> Result<()> {
        let n = ids.len();
        let (complain_round, defend_round) = rounds;

        // Complaints: every node broadcasts (possibly empty) so the round
        // completes everywhere.
        self.broadcast(
            sid,
            phase,
            complain_round,
            NodePayload::Complaints(complaints.to_vec()),
        );
        let complaint_sets = self.accepted_broadcasts_over(sid, phase, complain_round, ids);
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
        let defense_sets = self.accepted_broadcasts_over(sid, phase, defend_round, ids);
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
        self.triple_over(sid, &self.params.parties(), rng, cheat)
    }

    /// [`Self::triple`] over an explicit committee (H4 §10.3 restart
    /// sessions run over the surviving ORIGINAL ids).
    pub fn triple_over(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(TripleShare, TriplePublic)> {
        let out = self.triple_run(sid, ids, rng, cheat);
        self.node.retire_session(sid);
        out
    }

    /// T1 + T2 of the per-node triple driver (SPEC §7.2), shared by
    /// [`Self::triple_run`] and [`Self::triple_robust_run`]: two ephemeral
    /// joint random sharings over the wire, then this node's re-sharing
    /// deal broadcast and P2P re-shares, and the collected accepted sets.
    fn triple_t1_t2(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(KeyShare, KeyShare, TripleT2)> {
        let me = self.me;
        let n = ids.len();
        let t = self.params.t;
        let phase = Phase::Triples;

        // T1: joint random [α], [β] — two ephemeral commit-reveal VSS
        // instances over the wire.
        let alpha = self.joint_vss_over(
            &[sid, b"/alpha"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
            &mut *rng,
            None,
        )?;
        let beta = self.joint_vss_over(
            &[sid, b"/beta"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
            &mut *rng,
            None,
        )?;
        let cb = beta.com.clone();

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
        for &i in ids {
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
        let deal_envs = self.accepted_broadcasts_over(sid, phase, TR_ROUND_DEAL, ids);
        let resh_envs = self.accepted_p2p_over(sid, phase, TR_ROUND_DEAL, ids);
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
        let mut kept_envs: BTreeMap<PartyId, SignedEnvelope<NodePayload>> = BTreeMap::new();
        for (f, se) in resh_envs {
            match &se.envelope.payload {
                NodePayload::Reshare(s) => {
                    mine.insert(f, *s);
                    kept_envs.insert(f, se);
                }
                _ => return Err(abort(phase, vec![f], "malformed re-share envelope".into())),
            }
        }
        Ok((
            alpha,
            beta,
            TripleT2 {
                deals,
                mine,
                sent,
                resh_envs: kept_envs,
            },
        ))
    }

    /// T3a: verify every product proof (F3) — computable identically by
    /// every node over the echo-consistent sets; no complaint round. An
    /// invalid proof aborts (continuation is impossible: the dealer's
    /// commitment binds a wrong product, SPEC §10.4 C6) and is logged
    /// (`token: none`; no token shape for proofs, M3b).
    fn triple_check_proofs(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        deals: &BTreeMap<PartyId, TripleDealMsg>,
        ca: &FeldmanCommitment,
        cb: &FeldmanCommitment,
    ) -> Result<()> {
        let phase = Phase::Triples;
        for &i in ids {
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
                let e = abort(phase, vec![i], "invalid DLEQ product proof".into());
                self.record_abort(&e, None);
                return Err(e);
            }
        }
        Ok(())
    }

    /// T3c: combine with Lagrange weights — [γ] = Σ_j λ_j·[g_j]
    /// (GJKR96-style degree reduction). Shared by the fail-fast and
    /// §10.4-robust paths (the robust path passes the RECONSTRUCTED
    /// shares for blamed dealers).
    fn triple_combine(
        &self,
        ids: &[PartyId],
        alpha: &KeyShare,
        beta: &KeyShare,
        deals: &BTreeMap<PartyId, TripleDealMsg>,
        mine: &BTreeMap<PartyId, Scalar>,
    ) -> (TripleShare, TriplePublic) {
        let lambdas = lagrange_coeffs(ids);
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
        (
            TripleShare {
                index: self.me,
                a: alpha.share,
                b: beta.share,
                c: c_share,
            },
            TriplePublic {
                ca: alpha.com.clone(),
                cb: beta.com.clone(),
                cc: cc.expect("n >= 1"),
            },
        )
    }

    fn triple_run(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(TripleShare, TriplePublic)> {
        let me = self.me;
        let phase = Phase::Triples;

        let (alpha, beta, t2) = self.triple_t1_t2(sid, ids, rng, cheat)?;
        let (ca, cb) = (alpha.com.clone(), beta.com.clone());
        let TripleT2 {
            deals,
            mine,
            sent,
            resh_envs: _,
        } = &t2;

        // T3a: product proofs (F3 — fail-fast, identical everywhere).
        self.triple_check_proofs(sid, ids, deals, &ca, &cb)?;

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
            ids,
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

        // T3c: combine with Lagrange weights.
        Ok(self.triple_combine(ids, &alpha, &beta, deals, mine))
    }

    /// H4 §10.4 robust triple generation (SPEC §7.2 + §10.4 C6): the
    /// blame-and-continue variant of [`Self::triple`]. T1/T2/T3a are
    /// unchanged (dealing-phase faults F1/F2-on-wire/F3 still abort — the
    /// §10.3 restart policy owns those). T3b replaces the complaint/abort
    /// with PUBLIC RECONSTRUCTION:
    ///
    /// * **Request round** (always runs, like §6.1 complaints): every
    ///   node broadcasts `ReshareRequests` — for each dealer whose
    ///   re-share failed the commitment check HERE, the dealer's own
    ///   signed `Reshare` envelope as self-authenticating evidence.
    ///   Every node re-verifies the envelope signature (registry) and the
    ///   failing `EvalCom`: a genuine failure blames the DEALER and puts
    ///   it in the reconstruction set; a fabricated or actually-verifying
    ///   "request" blames the REQUESTER (abort — a false accusation
    ///   contaminates no value but is not continuable either; §10.3
    ///   restarts without the accuser).
    /// * **Supply round** (only when the reconstruction set is non-empty
    ///   — a deterministic, publicly-computable condition): every node
    ///   broadcasts `ReshareSupply` with the re-share it RECEIVED from
    ///   each dealer in the set. Every node filters supplies by point
    ///   equality against the dealer's public commitment (deterministic
    ///   BTreeMap order) and interpolates the dealer's committed
    ///   re-sharing polynomial from the first `t` valid supplies,
    ///   recomputing its own contaminated share. Fewer than `t` valid
    ///   supplies (the dealer validly shared with too few parties)
    ///   aborts blaming the dealer — the committed polynomial is
    ///   unrecoverable (same rule as the core's `generate_robust`).
    ///
    /// Round cost: +1 broadcast round per triple session in the honest
    /// case (the request round), +2 on a re-share fault. Returns this
    /// node's share, the public commitments, and the blamed dealers
    /// (identical at every node; a blamed dealer's `C_j` still enters
    /// `A[γ]` — its DLEQ proof already bound `g_j(0) = α_j·β_j`).
    pub fn triple_robust(
        &self,
        sid: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(TripleShare, TriplePublic, Vec<PartyId>)> {
        let out = self.triple_robust_run(sid, &self.params.parties(), rng, cheat);
        self.node.retire_session(sid);
        out
    }

    fn triple_robust_run(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(TripleShare, TriplePublic, Vec<PartyId>)> {
        let me = self.me;
        let t = self.params.t;
        let phase = Phase::Triples;

        let (alpha, beta, t2) = self.triple_t1_t2(sid, ids, rng, cheat)?;
        let (ca, cb) = (alpha.com.clone(), beta.com.clone());
        let TripleT2 {
            deals,
            mut mine,
            sent: _,
            resh_envs,
        } = t2;

        // T3a: product proofs (F3 — fail-fast, identical everywhere).
        self.triple_check_proofs(sid, ids, &deals, &ca, &cb)?;

        // T3b (§10.4): local re-share checks → the reconstruction
        // REQUEST round. This node's evidence is the dealer's own signed
        // `Reshare` envelope; an empty list still broadcasts so the
        // round completes everywhere.
        let mut requests: Vec<(PartyId, SignedEnvelope<NodePayload>)> = ids
            .iter()
            .copied()
            .filter(|&i| !deals[&i].com.verify_share(me, &mine[&i]))
            .map(|i| (i, resh_envs[&i].clone()))
            .collect();
        if let Some(Cheat::FalseAccuse { dealer }) = cheat {
            // Malicious: accuse an honest dealer — the carried envelope's
            // share VERIFIES, so every node blames this node instead.
            if !requests.iter().any(|(d, _)| *d == dealer) {
                requests.push((dealer, resh_envs[&dealer].clone()));
            }
        }
        self.broadcast(
            sid,
            phase,
            TR_ROUND_RECON_REQ,
            NodePayload::ReshareRequests(requests),
        );
        let req_sets = self.accepted_broadcasts_over(sid, phase, TR_ROUND_RECON_REQ, ids);
        if req_sets.len() != ids.len() {
            return Err(Error::InvalidParams("incomplete message sets"));
        }

        // Verdict (deterministic, public data): for every request,
        // re-verify the carried envelope against the claimed dealer's
        // registry key and re-run the failing check. The envelope must
        // belong to THIS session and round — a stale `Reshare` envelope
        // from an earlier triple session would fail this session's
        // commitment check and frame an honest dealer (replay). Genuine
        // → the dealer enters the reconstruction set (sorted union).
        let mut reconstruct: BTreeSet<PartyId> = BTreeSet::new();
        for (v, se) in &req_sets {
            let NodePayload::ReshareRequests(reqs) = &se.envelope.payload else {
                return Err(abort(
                    phase,
                    vec![*v],
                    "malformed reconstruction request broadcast".into(),
                ));
            };
            for (d, evidence) in reqs {
                let genuine = evidence.envelope.from == *d
                    && evidence.envelope.to == Some(*v)
                    && evidence.envelope.sid == sid
                    && evidence.envelope.phase == phase
                    && evidence.envelope.round == TR_ROUND_DEAL
                    && matches!(
                        &evidence.envelope.payload,
                        NodePayload::Reshare(s)
                            if evidence.verify_signature(&self.registry[d])
                                && !deals[d].com.verify_share(*v, s)
                    );
                if genuine {
                    reconstruct.insert(*d);
                } else {
                    // Fabricated evidence or an actually-verifying share:
                    // the REQUESTER is at fault (false accusation).
                    let e = abort(
                        phase,
                        vec![*v],
                        format!("false accusation: {v}'s reconstruction request against dealer {d} does not hold up"),
                    );
                    self.record_abort(&e, None);
                    return Err(e);
                }
            }
        }
        let blamed: Vec<PartyId> = reconstruct.iter().copied().collect();

        // Supply round (deterministic condition): every node broadcasts
        // the re-share it RECEIVED from each dealer in the set.
        if !reconstruct.is_empty() {
            let supplies: Vec<(PartyId, Scalar)> =
                reconstruct.iter().map(|&d| (d, mine[&d])).collect();
            self.broadcast(
                sid,
                phase,
                TR_ROUND_RECON_SUPPLY,
                NodePayload::ReshareSupply(supplies),
            );
            let sup_sets = self.accepted_broadcasts_over(sid, phase, TR_ROUND_RECON_SUPPLY, ids);
            if sup_sets.len() != ids.len() {
                return Err(Error::InvalidParams("incomplete message sets"));
            }
            let mut supplied: BTreeMap<PartyId, BTreeMap<PartyId, Scalar>> = BTreeMap::new();
            for (f, se) in &sup_sets {
                let NodePayload::ReshareSupply(list) = &se.envelope.payload else {
                    return Err(abort(
                        phase,
                        vec![*f],
                        "malformed reconstruction supply broadcast".into(),
                    ));
                };
                for (d, s) in list {
                    supplied.entry(*d).or_default().insert(*f, *s);
                }
            }
            for &d in &reconstruct {
                // Filter supplies by point equality against the dealer's
                // public commitment (BTreeMap order — deterministic),
                // interpolate the committed polynomial, and recompute
                // this node's contaminated share (§10.4 C6).
                let (mut valid_parties, mut valid_shares): (Vec<PartyId>, Vec<Scalar>) = supplied
                    [&d]
                    .iter()
                    .filter(|(&i, s)| deals[&d].com.verify_share(i, s))
                    .map(|(&i, &s)| (i, s))
                    .unzip();
                if valid_parties.len() < t {
                    let e = abort(
                        phase,
                        vec![d],
                        "fewer than t valid re-shared shares; committed re-sharing \
                         polynomial unrecoverable"
                            .into(),
                    );
                    self.record_abort(&e, None);
                    return Err(e);
                }
                valid_parties.truncate(t);
                valid_shares.truncate(t);
                mine.insert(
                    d,
                    ohm_ecdsa::shamir::interpolate_at(
                        &Scalar::from(me as u64),
                        &valid_parties,
                        &valid_shares,
                    ),
                );
            }
            // M3b: log the blamed dealers (`token: none` — the `Reshare`
            // envelope has no token shape, see `persist::BlameEvidence`;
            // the carried evidence rides in the transcript).
            self.note_blamed(
                phase,
                &blamed,
                "re-shared share failed commitment check; committed polynomial \
                 publicly reconstructed (SPEC §10.4)",
            );
        }

        // T3c: combine — the reconstructed shares replace the
        // contaminated ones; the dealer's commitment still enters A[γ].
        let (share, public) = self.triple_combine(ids, &alpha, &beta, &deals, &mine);
        Ok((share, public, blamed))
    }

    /// Per-node presignature (SPEC §8, P1–P4, M3a): two fresh triples
    /// ([`Self::triple`]) and two ephemeral joint random sharings ⟦u⟧
    /// (:= k⁻¹), ⟦a⟧ ([`Self::joint_vss`]), then the Beaver openings and
    /// nonce points as broadcast rounds. Every broadcast share is checked
    /// against its public commitment by point equality (§4.6 openings are
    /// FAIL-FAST identifiable aborts) and every nonce point against
    /// `EvalCom(A[k], j)` (F5 ⇒ blame the sender). Fail-fast is the
    /// DEFAULT posture (some deployments prefer loud aborts); the §10.4
    /// robust blame-and-continue variant is the opt-in
    /// [`Self::presign_robust`] (H4). `v = 0` / `r = 0` return
    /// [`Error::ZeroValue`]: the caller retries with a fresh presignature
    /// id. Returns this node's [`Presignature`] record — it never leaves
    /// the node.
    pub fn presign(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Presignature> {
        let out = self.presign_run(sid, id, key, &self.params.parties(), rng, cheat);
        // H2: the session is over — drop its reconnect journal entries
        // (prefix match covers the sub-session sids not already retired
        // by the triple/joint_vss drivers).
        self.node.retire_session(sid);
        out
    }

    fn presign_run(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<Presignature> {
        let t = self.params.t;
        let phase = Phase::Presign;

        // P1–P3 (shared verbatim with the §8.7 KI pool production,
        // [`Self::presign_ki`]): ⟦u⟧ (:= k⁻¹), ⟦a⟧, the Beaver openings
        // and the nonce-point round.
        let (u_j, u_com, r_scalar, big_r) = self.presign_p1_p3(sid, ids, &mut *rng, cheat)?;

        // P4's Beaver triple — the §8.7 KI mode moves exactly this
        // triple session online (K1).
        let (t2, pub2) = self.triple_over(&[sid, b"/t2"].concat(), ids, &mut *rng, None)?;
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
        let (d2s, e2s) = self.collect_beaver_opens(sid, phase, PS_ROUND_Z, ids)?;
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
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Scalar, FeldmanCommitment, Scalar, AffinePoint)> {
        let n = ids.len();
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
        let (t1, pub1) = self.triple_over(&[sid, b"/t1"].concat(), ids, &mut *rng, triple_cheat)?;

        // P1: ephemeral joint randomness [u] (:= k⁻¹) and [a].
        let u_out = self.joint_vss_over(
            &[sid, b"/u"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
            &mut *rng,
            None,
        )?;
        let a_out = self.joint_vss_over(
            &[sid, b"/a"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
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
        let (deltas, epsilons) = self.collect_beaver_opens(sid, phase, PS_ROUND_DELTA_EPS, ids)?;
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
        let v_shares = self.collect_open_shares(sid, phase, PS_ROUND_V, ids)?;
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
        let nonce_envs = self.accepted_broadcasts_over(sid, phase, PS_ROUND_NONCE, ids);
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
        let lambdas = lagrange_coeffs(ids);
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

    /// H4 §10.4 robust presignature (SPEC §8 + §10.4): the blame-and-
    /// continue variant of [`Self::presign`]. The DEALING phases (the
    /// triple sessions and the ⟦u⟧/⟦a⟧ joint random sharings) stay
    /// fail-fast — the §10.3 restart policy owns them
    /// ([`Self::presign_with_restart`]). Every OPENING (δ/ε, v, δ′/ε′)
    /// goes through the core's [`open_robust`]: bad shares are filtered
    /// and their senders blamed (deterministically identical at every
    /// node — point equality on public data over echo-consistent sets),
    /// and the opening interpolates from the first `t` valid shares.
    /// Nonce points are checked individually; bad `R_j` are filtered and
    /// blamed and `R` is interpolated over the valid senders with
    /// `lagrange_coeffs(&S)` (the core's `presign_robust` semantics).
    /// Blamed parties are expelled from subsequent rounds' share sets
    /// (their broadcasts are ignored; a blamed node's own local values
    /// are unaffected, so every node — including a blamed one — tracks
    /// the same openings and produces its record). Returns this node's
    /// record and the accumulated blame list (identical everywhere).
    /// `v = 0` / `r = 0` handling is unchanged ([`Error::ZeroValue`]).
    pub fn presign_robust(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Presignature, Vec<PartyId>)> {
        let out = self.presign_robust_run(sid, id, key, &self.params.parties(), rng, cheat);
        self.node.retire_session(sid);
        out
    }

    fn presign_robust_run(
        &self,
        sid: &[u8],
        id: u64,
        key: &KeyShare,
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Presignature, Vec<PartyId>)> {
        let t = self.params.t;
        let phase = Phase::Presign;

        // P1–P3 with §10.4-robust openings (⟦u⟧, ⟦a⟧, the δ/ε and v
        // openings, the nonce-point round).
        let (u_j, u_com, r_scalar, big_r, mut blamed, mut active) =
            self.presign_p1_p3_robust(sid, ids, &mut *rng, cheat)?;

        // P4's Beaver triple runs over the ATTEMPT'S committee (the
        // core's `presign_robust` generates both triples over the full
        // committee before any blame; over the wire a blamed party keeps
        // dealing — its later OPENING shares are filtered via the active
        // set). A dealing-phase fault here aborts — §10.3 owns it.
        let (t2, pub2) = self.triple_over(&[sid, b"/t2"].concat(), ids, &mut *rng, None)?;
        let neg = -Scalar::ONE;

        // P4: z = u·x via triple 2 — robust openings over the active set.
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
        let (d2s, e2s) = self.collect_beaver_opens(sid, phase, PS_ROUND_Z, &active)?;
        let (d2v, b_d2) = self.open_robust_noted(t, &d2_com, &d2s, phase)?;
        let (e2v, b_e2) = self.open_robust_noted(t, &e2_com, &e2s, phase)?;
        expel(&mut blamed, &mut active, b_d2);
        expel(&mut blamed, &mut active, b_e2);
        let z_com = pub2
            .cc
            .clone()
            .add(&pub2.cb.scale(&d2v))
            .add(&pub2.ca.scale(&e2v))
            .add_const(&(d2v * e2v));
        let z_j = t2.c + d2v * t2.b + e2v * t2.a + d2v * e2v;

        Ok((
            Presignature {
                id,
                index: self.me,
                r: r_scalar,
                big_r,
                u_share: u_j,
                z_share: z_j,
                u_com,
                z_com,
            },
            blamed,
        ))
    }

    /// H4 §10.4-robust §8 P1–P3 over the wire (the robust counterpart of
    /// [`Self::presign_p1_p3`], mirroring the core's `presign_robust`):
    /// ONE fail-fast triple session and the ⟦u⟧/⟦a⟧ joint sharings
    /// (dealing phases stay fail-fast — §10.3 owns them), then every
    /// opening through [`open_robust`] with expulsion, and the nonce
    /// round filtered to the valid senders (`R` interpolated over the
    /// subset `S` with `lagrange_coeffs(&S)`, `|S| ≥ t` required).
    /// Returns this node's `u`-share and commitment, the public nonce
    /// `(r, R)`, the accumulated blame, and the surviving active set.
    #[allow(clippy::type_complexity)] // (u, A[u], r, R, blame, active) — the phase's full artifacts
    fn presign_p1_p3_robust(
        &self,
        sid: &[u8],
        ids: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(
        Scalar,
        FeldmanCommitment,
        Scalar,
        AffinePoint,
        Vec<PartyId>,
        Vec<PartyId>,
    )> {
        let t = self.params.t;
        let phase = Phase::Presign;

        // One fresh triple (SPEC §7) for the `v = a·u` opening — the
        // dealing phase stays fail-fast (§10.4 C6: not continuable).
        let triple_cheat = cheat.filter(|c| {
            matches!(
                c,
                Cheat::BadProductProof | Cheat::BadReshare { .. } | Cheat::FalseAccuse { .. }
            )
        });
        let (t1, pub1) = self.triple_over(&[sid, b"/t1"].concat(), ids, &mut *rng, triple_cheat)?;

        // P1: ephemeral joint randomness [u] (:= k⁻¹) and [a].
        let u_out = self.joint_vss_over(
            &[sid, b"/u"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
            &mut *rng,
            None,
        )?;
        let a_out = self.joint_vss_over(
            &[sid, b"/a"].concat(),
            tags::DKG_COMMIT,
            phase,
            ids,
            &mut *rng,
            None,
        )?;
        let (u_com, a_com) = (u_out.com.clone(), a_out.com.clone());
        let (u_j, a_j) = (u_out.share, a_out.share);
        let neg = -Scalar::ONE;

        // §10.4 state: blame accumulates; the blamed are expelled from
        // all subsequent share sets.
        let mut blamed: Vec<PartyId> = Vec::new();
        let mut active: Vec<PartyId> = ids.to_vec();

        // P2: open δ = u − α, ε = a − β (one round carries both shares —
        // the blame of both openings is unioned), then v = a·u via
        // triple 1 (Beaver).
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
        let (deltas, epsilons) =
            self.collect_beaver_opens(sid, phase, PS_ROUND_DELTA_EPS, &active)?;
        let (delta, b_d) = self.open_robust_noted(t, &delta_com, &deltas, phase)?;
        let (eps, b_e) = self.open_robust_noted(t, &eps_com, &epsilons, phase)?;
        expel(&mut blamed, &mut active, b_d);
        expel(&mut blamed, &mut active, b_e);

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
        let v_shares = self.collect_open_shares(sid, phase, PS_ROUND_V, &active)?;
        let (v, b_v) = self.open_robust_noted(t, &v_com, &v_shares, phase)?;
        expel(&mut blamed, &mut active, b_v);
        if v == Scalar::ZERO {
            // Retry with a fresh presignature id (caller policy).
            return Err(Error::ZeroValue("v = 0".into()));
        }
        let v_inv =
            Option::<Scalar>::from(v.invert()).ok_or_else(|| Error::ZeroValue("v = 0".into()))?;

        // P3: [k] = v⁻¹·[a]; nonce points checked individually — bad R_j
        // are filtered and blamed, R interpolated over the valid senders.
        let k_com = a_com.scale(&v_inv);
        let mut r_j = ProjectivePoint::GENERATOR * (v_inv * a_j);
        if cheat == Some(Cheat::BadNoncePoint) {
            r_j += ProjectivePoint::GENERATOR; // malicious: wrong nonce point
        }
        self.broadcast(sid, phase, PS_ROUND_NONCE, NodePayload::NoncePoint(r_j));
        let nonce_envs = self.accepted_broadcasts_over(sid, phase, PS_ROUND_NONCE, &active);
        if nonce_envs.len() != active.len() {
            return Err(Error::InvalidParams("incomplete message sets"));
        }
        let mut valid_senders = Vec::new();
        let mut r_points = Vec::new();
        let mut bad_points = Vec::new();
        for (f, se) in nonce_envs {
            match se.envelope.payload {
                NodePayload::NoncePoint(p) => {
                    if p == k_com.eval_at(f) {
                        valid_senders.push(f);
                        r_points.push(p);
                    } else {
                        bad_points.push(f);
                    }
                }
                _ => return Err(abort(phase, vec![f], "malformed nonce broadcast".into())),
            }
        }
        // F5 — logged with `token: none` (M3b), as in the fail-fast driver.
        self.note_blamed(phase, &bad_points, "invalid nonce point R_j");
        expel(&mut blamed, &mut active, bad_points);
        if valid_senders.len() < t {
            return Err(Error::NotEnoughShares {
                got: valid_senders.len(),
                need: t,
            });
        }
        let lambdas = lagrange_coeffs(&valid_senders);
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
        Ok((u_j, u_com, r_scalar, big_r, blamed, active))
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
        let out = self.presign_ki_run(sid, id, rng, cheat);
        // H2: retire the session's reconnect journal entries (see
        // [`Self::presign`]).
        self.node.retire_session(sid);
        out
    }

    fn presign_ki_run(
        &self,
        sid: &[u8],
        id: u64,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<KiPresignature> {
        let (u_j, u_com, r, big_r) = self.presign_p1_p3(sid, &self.params.parties(), rng, cheat)?;
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
    /// identifiable abort — the default posture; the §10.4 robust
    /// continuation is the opt-in [`Self::sign_ki_robust`], H4). R2
    /// computes ⟦z⟧ locally
    /// ([`sign::ki_z_share`]) and broadcasts `s_j = m·u_j + r·z_j`,
    /// verified against `m·A[u] + r·A[z]` by [`sign::combine_ki`]
    /// (fail-fast), low-`s` normalized. Cheats: `BadOpenShare` corrupts this
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
        let out = self.sign_ki_run(sid, presig, key, msg, rng, cheat);
        // H2: retire the session's reconnect journal entries (see
        // [`Self::presign`]).
        self.node.retire_session(sid);
        out
    }

    fn sign_ki_run(
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
        let (deltas, epsilons) =
            self.collect_beaver_opens(sid, phase, KI_ROUND_OPEN, &self.params.parties())?;
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

    /// H4 §10.4 robust variant of [`Self::sign_ki`] (SPEC §8.7 + §10.4):
    /// R1's δ/ε openings go through [`open_robust`] (bad shares filtered,
    /// senders blamed, the blamed expelled from R2's share set — the same
    /// discipline as [`Self::presign_robust`]), and R2 combines via
    /// [`sign::combine_ki_robust`] (bad signature shares filtered and
    /// blamed, `(r, s)` interpolated from the first `t` valid shares).
    /// The R1 triple session stays fail-fast (dealing phase — §10.3 owns
    /// it; KI restart composition is follow-up). F6 sign-share tokens are
    /// archived per R2-blamed sender (M3b), exactly as in the §9 driver.
    /// Returns the signature and the accumulated blame (R1 ∪ R2,
    /// identical at every node).
    pub fn sign_ki_robust(
        &self,
        sid: &[u8],
        presig: &KiPresignature,
        key: &KeyShare,
        msg: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Signature, Vec<PartyId>)> {
        let out = self.sign_ki_robust_run(sid, presig, key, msg, rng, cheat);
        // H2: retire the session's reconnect journal entries (see
        // [`Self::presign`]).
        self.node.retire_session(sid);
        out
    }

    fn sign_ki_robust_run(
        &self,
        sid: &[u8],
        presig: &KiPresignature,
        key: &KeyShare,
        msg: &[u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Signature, Vec<PartyId>)> {
        let t = self.params.t;
        let phase = Phase::Sign;
        let m = ohm_ecdsa::sim::message_scalar(msg);
        let ids = self.params.parties();

        // R1 (SPEC §8.7 K1): a fresh Beaver triple (fail-fast — the
        // dealing phase), then the ROBUST δ/ε openings.
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
        let (deltas, epsilons) = self.collect_beaver_opens(sid, phase, KI_ROUND_OPEN, &ids)?;
        let (delta, b_d) = self.open_robust_noted(t, &delta_com, &deltas, phase)?;
        let (eps, b_e) = self.open_robust_noted(t, &eps_com, &epsilons, phase)?;
        let mut blamed: Vec<PartyId> = Vec::new();
        let mut active: Vec<PartyId> = ids;
        expel(&mut blamed, &mut active, b_d);
        expel(&mut blamed, &mut active, b_e);

        // R2 (SPEC §8.7 K2): local z-share + sign share, ROBUST combine
        // against m·A[u] + r·A[z] over the active set.
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
        let set = self.accepted_broadcasts_over(sid, phase, KI_ROUND_SHARE, &active);
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
        let ((r, s), b2) = sign::combine_ki_robust(&self.params, presig, &z_com, &m, &shares)?;
        // M3b (§10.2/§A.4): archive the F6 sign-share token for every
        // R2-blamed sender (R1 blame is logged via `open_robust_noted`).
        for &f in &b2 {
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
                        z_com: z_com.clone(),
                    }),
                );
            }
        }
        expel(&mut blamed, &mut active, b2);
        let sig = Signature::from_scalars(r, s)?;
        Ok((sig.normalize_s().unwrap_or(sig), blamed))
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

    /// Core `open_robust` (SPEC §10.4) with M3b blame archiving
    /// (`token: none`, same as [`Self::open_noted`]): bad shares are
    /// filtered and their senders blamed; the opening interpolates from
    /// the first `t` valid shares.
    fn open_robust_noted(
        &self,
        t: usize,
        com: &FeldmanCommitment,
        shares: &BTreeMap<PartyId, Scalar>,
        phase: Phase,
    ) -> Result<(Scalar, Vec<PartyId>)> {
        let (opened, blamed) = open_robust(t, com, shares, phase)?;
        self.note_blamed(
            phase,
            &blamed,
            "share failed commitment check during opening (SPEC §10.4: filtered, opening continued)",
        );
        Ok((opened, blamed))
    }

    /// Collect a round of single-scalar opening shares (fail-closed on an
    /// incomplete accepted set; malformed payloads blame the sender).
    fn collect_open_shares(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        ids: &[PartyId],
    ) -> Result<BTreeMap<PartyId, Scalar>> {
        let envs = self.accepted_broadcasts_over(sid, phase, round, ids);
        if envs.len() != ids.len() {
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
        ids: &[PartyId],
    ) -> Result<(BTreeMap<PartyId, Scalar>, BTreeMap<PartyId, Scalar>)> {
        let envs = self.accepted_broadcasts_over(sid, phase, round, ids);
        if envs.len() != ids.len() {
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
        self.sign_over(sid, presig, msg, &self.params.parties(), cheat)
    }

    /// [`Self::sign`] over an explicit committee (H4 §10.3): after an
    /// expel-and-restart the survivors sign with their ORIGINAL ids —
    /// the round waits only for the committee's shares (an expelled
    /// party's silence must not stall the round into the timeout). The
    /// verified-combine semantics are unchanged (`t` valid shares
    /// interpolate at the survivors' original evaluation points).
    pub fn sign_over(
        &self,
        sid: &[u8],
        presig: &Presignature,
        msg: &[u8],
        ids: &[PartyId],
        cheat: Option<Cheat>,
    ) -> Result<(Signature, Vec<PartyId>)> {
        if !ids.contains(&self.me) {
            return Err(Error::InvalidParams(
                "this node is not a member of the signing committee",
            ));
        }
        let out = self.sign_run(sid, presig, msg, ids, cheat);
        // H2: retire the session's reconnect journal entries (see
        // [`Self::presign`]).
        self.node.retire_session(sid);
        out
    }

    fn sign_run(
        &self,
        sid: &[u8],
        presig: &Presignature,
        msg: &[u8],
        ids: &[PartyId],
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
        let set = self.accepted_broadcasts_over(sid, phase, SIGN_ROUND_SHARE, ids);
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
        self.sign_stored_over(sid, presig_id, msg, &self.params.parties(), cheat)
    }

    /// [`Self::sign_stored`] over an explicit committee (H4 §10.3 — the
    /// durable-consume counterpart of [`Self::sign_over`]): the consume
    /// tombstone is fsync'd BEFORE the share is broadcast; the round
    /// waits only for the committee's shares.
    pub fn sign_stored_over(
        &self,
        sid: &[u8],
        presig_id: u64,
        msg: &[u8],
        ids: &[PartyId],
        cheat: Option<Cheat>,
    ) -> std::result::Result<(Signature, Vec<PartyId>), PersistError> {
        let presig = {
            let mut guard = self.store.lock().expect("mesh mutex poisoned");
            guard
                .as_mut()
                .ok_or(Error::PresigStore("no store configured"))?
                .consume(presig_id)?
        };
        Ok(self.sign_over(sid, &presig, msg, ids, cheat)?)
    }

    // --- H4: expel-and-restart at the driver level (SPEC §10.3) -----------

    /// §10.3 restart step shared by the `*_with_restart` drivers:
    /// accumulate the blame and compute the surviving committee —
    /// deterministically, via the core's [`ohm_ecdsa::policy::restart_committee`]
    /// over the current ids minus the blamed (the blame verdicts are
    /// already consistent at every honest node: point-equality checks on
    /// public data over echo-consistent sets). `Ok(Some(survivors))` =
    /// restart over these (original ids preserved — the survivors'
    /// long-term shares live at those evaluation points); `Ok(None)` =
    /// THIS node is expelled (its session is over — its mesh keeps
    /// echoing, so the survivors' rounds still meet the echo quorum);
    /// `Err` = zero-slack refusal (`n′ < 2t−1` — `t` is NEVER lowered;
    /// §13.4 re-sharing is the correct move there): the abort propagates
    /// with the refusal noted. Retries are inherently bounded: every
    /// restart expels at least one party and the policy refuses once the
    /// remainder would drop below `2t − 1`.
    fn restart_step(
        &self,
        current: &[PartyId],
        blamed_all: &mut Vec<PartyId>,
        abort: &IdentifiableAbort,
        attempt: u64,
    ) -> Result<Option<Vec<PartyId>>> {
        for &b in &abort.blamed {
            if !blamed_all.contains(&b) {
                blamed_all.push(b);
            }
        }
        blamed_all.sort_unstable();
        let survivors = ohm_ecdsa::policy::restart_committee(current, &abort.blamed, self.params.t)
            .map_err(|policy| abort_with(abort, format!("expel-and-restart refused: {policy}")))?;
        if !survivors.contains(&self.me) {
            return Ok(None);
        }
        eprintln!(
            "[node {}] §10.3 restart over {:?} (blamed {:?}, attempt {})",
            self.me,
            survivors,
            abort.blamed,
            attempt + 1
        );
        Ok(Some(survivors))
    }

    /// H4 §10.3 keygen with the expel-and-restart policy: the first
    /// attempt runs over the full committee; on `Error::Abort` every node
    /// deterministically computes the SAME restart committee
    /// ([`Self::restart_step`]), poisons the sid (§10.3(2)), and re-runs
    /// over the survivors with ORIGINAL ids preserved. (The core sim's
    /// keygen restart renumbers freely because no long-term shares exist
    /// yet; the wire committee's ids are pinned by the transport
    /// registry, and original ids are strictly better — the survivors'
    /// fresh shares live at their final evaluation points from the
    /// start.) A node expelled mid-way returns the abort. Returns this
    /// node's key share, the FINAL committee, and the cumulative blame
    /// (original ids).
    pub fn keygen_with_restart(
        &self,
        sid: &[u8],
        tag: &'static [u8],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(KeyShare, Vec<PartyId>, Vec<PartyId>)> {
        let mut current = self.params.parties();
        let mut blamed_all: Vec<PartyId> = Vec::new();
        let mut attempt = 0u64;
        let out = loop {
            let attempt_sid = poison_sid(sid, attempt);
            // Fault injection applies to the FIRST attempt only (the
            // core sim's convention): retries run clean.
            let tamp = if attempt == 0 { cheat } else { None };
            match self.joint_vss_run(&attempt_sid, tag, Phase::KeyGen, &current, &mut *rng, tamp) {
                Ok(share) => break Ok((share, current, blamed_all)),
                Err(Error::Abort { abort }) => {
                    match self.restart_step(&current, &mut blamed_all, &abort, attempt) {
                        Ok(Some(survivors)) => current = survivors,
                        Ok(None) => {
                            break Err(abort_with(
                                &abort,
                                "this node is expelled — the session continues over \
                                 the surviving committee"
                                    .into(),
                            ))
                        }
                        Err(e) => break Err(e),
                    }
                }
                Err(e) => break Err(e),
            }
            attempt += 1;
        };
        self.node.retire_session(sid);
        out
    }

    /// H4 §10.3 + §10.4 composition at the driver level (mirrors the core
    /// sim's `run_presign_with_restart`): every attempt drives the §10.4
    /// ROBUST presign ([`Self::presign_robust_run`]), so continuable
    /// faults (bad opening shares, bad nonce points) are filtered
    /// IN-ATTEMPT — the attempt completes, its id is NOT poisoned (the
    /// records are valid), and the in-attempt blame accumulates. Only
    /// DEALING-phase aborts (F1/F2/F3 — inside the commit-reveal VSS and
    /// triple sessions) expel-and-restart ([`Self::restart_step`]). The
    /// presignature id is poisoned per RESTARTED attempt (§10.3(2)):
    /// attempt `k` uses `first_id + k`. The survivors keep their ORIGINAL
    /// ids (their key shares live at those evaluation points). Zero-slack
    /// refusal and the retry bound are as in
    /// [`Self::keygen_with_restart`]. Returns this node's record, the id
    /// actually used, the final committee, and the cumulative blame.
    #[allow(clippy::type_complexity)] // (record, id used, committee, blame) — the session outcome
    pub fn presign_with_restart(
        &self,
        sid: &[u8],
        first_id: u64,
        key: &KeyShare,
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Presignature, u64, Vec<PartyId>, Vec<PartyId>)> {
        self.presign_with_restart_over(sid, first_id, key, &self.params.parties(), rng, cheat)
    }

    /// [`Self::presign_with_restart`] starting from an explicit committee
    /// (H4: a committee already shrunk by an EARLIER session's restart —
    /// e.g. a keygen expulsion before the offline factory runs).
    #[allow(clippy::type_complexity)] // (record, id used, committee, blame) — the session outcome
    pub fn presign_with_restart_over(
        &self,
        sid: &[u8],
        first_id: u64,
        key: &KeyShare,
        start: &[PartyId],
        rng: &mut impl RngCore,
        cheat: Option<Cheat>,
    ) -> Result<(Presignature, u64, Vec<PartyId>, Vec<PartyId>)> {
        let mut current: Vec<PartyId> = start.to_vec();
        let mut blamed_all: Vec<PartyId> = Vec::new();
        let mut attempt = 0u64;
        let out = loop {
            let id = first_id + attempt; // §10.3(2): a poisoned id is never reused
            let attempt_sid = poison_sid(sid, attempt);
            let tamp = if attempt == 0 { cheat } else { None };
            match self.presign_robust_run(&attempt_sid, id, key, &current, &mut *rng, tamp) {
                Ok((record, in_attempt_blamed)) => {
                    // The attempt COMPLETED via §10.4 continuation — no
                    // restart, the id is not poisoned; accumulate the
                    // in-attempt blame.
                    for &b in &in_attempt_blamed {
                        if !blamed_all.contains(&b) {
                            blamed_all.push(b);
                        }
                    }
                    blamed_all.sort_unstable();
                    break Ok((record, id, current, blamed_all));
                }
                Err(Error::Abort { abort }) => {
                    match self.restart_step(&current, &mut blamed_all, &abort, attempt) {
                        Ok(Some(survivors)) => current = survivors,
                        Ok(None) => {
                            break Err(abort_with(
                                &abort,
                                "this node is expelled — the session continues over \
                                 the surviving committee"
                                    .into(),
                            ))
                        }
                        Err(e) => break Err(e),
                    }
                }
                Err(e) => break Err(e),
            }
            attempt += 1;
        };
        self.node.retire_session(sid);
        out
    }
}

/// Clone an abort with extra context appended to the detail (the blame
/// verdict itself is untouched — it is the consistent public outcome).
fn abort_with(abort: &IdentifiableAbort, extra: String) -> Error {
    Error::Abort {
        abort: IdentifiableAbort {
            phase: abort.phase,
            blamed: abort.blamed.clone(),
            detail: format!("{}; {extra}", abort.detail),
        },
    }
}
