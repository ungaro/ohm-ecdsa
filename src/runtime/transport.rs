//! The explicit transport seam (SPEC §13.1/§13.2).
//!
//! The per-party protocol logic in this crate is message-oriented; this
//! module pins down the contract that logic is driven through, so a
//! production deployment can replace the in-process reference transport
//! with a real one (mTLS + echo broadcast + per-message signatures,
//! §13.1) WITHOUT touching per-party logic. The seam is the message
//! contract, not the runtime: the crate stays synchronous, and an async
//! production node implements this same [`Transport`] trait by bridging
//! its runtime — rounds are LOGICAL (SPEC §2.2), so a sync trait models
//! them.
//!
//! * [`Envelope`] — the per-message contract.
//! * [`Transport`] — the minimal synchronous contract a protocol driver
//!   needs: hand the transport one message, later collect a round's
//!   accepted set.
//! * [`SimTransport`] — the reference in-process implementation: delivers
//!   identical accepted message sets to every party, modeling
//!   echo-broadcast consistency (§4.7) exactly as [`crate::sim`] does.
//! * [`drive_dkg`] — the reference transport-driven driver: runs
//!   [`DkgInstance`] commit → reveal → finalize for all parties over any
//!   [`Transport`]. `sim::run_keygen` routes through it.
//!
//! ## Applying the pattern to triples and presign (incremental)
//!
//! The DKG is the reference pattern; triples and presign are deliberately
//! NOT re-architected here. Their orchestrators (`triples::generate*`,
//! `presign::presign*`) still run as monolithic functions that drive
//! `DkgInstance`/`DkgBatchInstance` internally for the dealing phases and
//! hand-deliver the rest (re-sharing vectors, DLEQ proofs, opening
//! shares, nonce points). All of it is already message-shaped
//! (`from`-keyed structs), so the same pattern applies incrementally:
//! wrap each payload in an [`Envelope`] at the orchestration site and
//! collect per-round accepted sets from a [`Transport`] — no verification
//! logic changes.

use std::collections::BTreeMap;

use k256::Scalar;
use rand::RngCore;

use crate::dkg::{DkgBcast1, DkgBcast2, DkgInstance, DkgOutput, DkgP2P, DkgTamper};
use crate::{Params, PartyId, Phase, Result};

/// DKG round numbers carried on the wire (`Envelope::round`).
pub const DKG_ROUND_COMMIT: u8 = 1;
/// Round 2 carries the reveal broadcast AND the P2P shares.
pub const DKG_ROUND_REVEAL: u8 = 2;

/// The per-message contract: every protocol message on the wire.
///
/// These are exactly the fields a production transport signs per message
/// (SPEC §10.2/§13.1): `(sid, phase, round, from, to, payload)`. Signing
/// itself, mTLS, echo-broadcast acceptance, and persistence of
/// accepted-message sets (blame evidence) are the transport
/// implementation's job, not this crate's. `to == None` is a broadcast.
///
/// The payload structs keep their own `from`/`to` fields (the per-party
/// logic predates the seam); the envelope's fields are authoritative for
/// routing and signing.
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope<M> {
    /// Session id (see [`crate::session_id`], SPEC §13.1).
    pub sid: Vec<u8>,
    /// Protocol phase this message belongs to.
    pub phase: Phase,
    /// Logical round within the phase (SPEC §2.2).
    pub round: u8,
    /// Sender.
    pub from: PartyId,
    /// Addressee; `None` = broadcast to all parties.
    pub to: Option<PartyId>,
    /// The protocol message.
    pub payload: M,
}

impl<M> Envelope<M> {
    /// A broadcast envelope (`to == None`).
    pub fn broadcast(sid: &[u8], phase: Phase, round: u8, from: PartyId, payload: M) -> Self {
        Self {
            sid: sid.to_vec(),
            phase,
            round,
            from,
            to: None,
            payload,
        }
    }

    /// A point-to-point envelope.
    pub fn p2p(
        sid: &[u8],
        phase: Phase,
        round: u8,
        from: PartyId,
        to: PartyId,
        payload: M,
    ) -> Self {
        Self {
            sid: sid.to_vec(),
            phase,
            round,
            from,
            to: Some(to),
            payload,
        }
    }
}

/// The minimal synchronous contract a protocol driver needs from a
/// transport. Object-safe (`dyn Transport<M>`) and runtime-agnostic: it
/// models the LOGICAL round structure (SPEC §2.2), not a wire or a
/// scheduler — an async production node implements this same trait by
/// bridging its runtime; the seam is the message contract, not the
/// runtime.
///
/// Contract (echo broadcast, SPEC §4.7): after the senders of a round
/// have handed their messages over, `accepted_broadcasts` returns the
/// SAME set to every party (consistency), and only messages the sender
/// actually sent (non-forgeability). `accepted_p2p` returns to each party
/// exactly the messages addressed to it.
pub trait Transport<M: Clone> {
    /// Hand one broadcast message to the transport (`env.to == None`).
    fn broadcast(&mut self, env: Envelope<M>);
    /// Hand one point-to-point message to the transport (`env.to ==
    /// Some(_)`).
    fn send_p2p(&mut self, env: Envelope<M>);
    /// The accepted broadcast set of one round, keyed by sender. A
    /// consistent transport returns the same set to every caller.
    fn accepted_broadcasts(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, Envelope<M>>;
    /// The accepted messages of one round addressed to `to`, keyed by
    /// sender.
    fn accepted_p2p(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
    ) -> BTreeMap<PartyId, Envelope<M>>;
}

/// The reference in-process [`Transport`] (SPEC §4.7, §13.2): a
/// synchronizing queue that delivers identical accepted message sets to
/// all parties, modeling echo-broadcast consistency exactly as
/// [`crate::sim`] does. Deterministic and single-threaded; a production
/// deployment replaces this with the §13.1 transport.
pub struct SimTransport<M: Clone> {
    bcast: Vec<Envelope<M>>,
    p2p: Vec<Envelope<M>>,
}

impl<M: Clone> SimTransport<M> {
    /// An empty transport.
    pub fn new() -> Self {
        Self {
            bcast: Vec::new(),
            p2p: Vec::new(),
        }
    }
}

impl<M: Clone> Default for SimTransport<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: Clone> Transport<M> for SimTransport<M> {
    fn broadcast(&mut self, env: Envelope<M>) {
        debug_assert!(env.to.is_none(), "broadcast envelope must have to == None");
        self.bcast.push(env);
    }

    fn send_p2p(&mut self, env: Envelope<M>) {
        debug_assert!(env.to.is_some(), "p2p envelope must have an addressee");
        self.p2p.push(env);
    }

    fn accepted_broadcasts(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> BTreeMap<PartyId, Envelope<M>> {
        self.bcast
            .iter()
            .filter(|e| e.sid == sid && e.phase == phase && e.round == round)
            .map(|e| (e.from, e.clone()))
            .collect()
    }

    fn accepted_p2p(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
    ) -> BTreeMap<PartyId, Envelope<M>> {
        self.p2p
            .iter()
            .filter(|e| e.sid == sid && e.phase == phase && e.round == round && e.to == Some(to))
            .map(|e| (e.from, e.clone()))
            .collect()
    }
}

/// DKG payloads carried over the transport seam in one session.
#[derive(Clone, Debug)]
pub enum DkgMessage {
    /// Round 1 ([`DKG_ROUND_COMMIT`]): hash commitment to the dealing.
    Commit(DkgBcast1),
    /// Round 2 ([`DKG_ROUND_REVEAL`]): revealed Feldman vector.
    Reveal(DkgBcast2),
    /// Round 2 (P2P): the dealt share for the addressee.
    Share(DkgP2P),
}

fn commits_of(envs: BTreeMap<PartyId, Envelope<DkgMessage>>) -> BTreeMap<PartyId, DkgBcast1> {
    envs.into_iter()
        .map(|(f, e)| match e.payload {
            DkgMessage::Commit(b) => (f, b),
            _ => unreachable!("round {} carries only commits", DKG_ROUND_COMMIT),
        })
        .collect()
}

fn reveals_of(envs: BTreeMap<PartyId, Envelope<DkgMessage>>) -> BTreeMap<PartyId, DkgBcast2> {
    envs.into_iter()
        .map(|(f, e)| match e.payload {
            DkgMessage::Reveal(b) => (f, b),
            _ => unreachable!("round {} carries only reveals", DKG_ROUND_REVEAL),
        })
        .collect()
}

/// The reference transport-driven driver (SPEC §6, §13.2): run
/// [`DkgInstance`] commit → reveal → finalize for all parties over any
/// [`Transport`]. `rngs[k]` is the RNG of the `k`-th party (position in
/// `1..=n`); per-party arrays are positional as everywhere in this crate.
///
/// This is exactly the delivery behavior of `sim::run_keygen` (which
/// routes through this driver): round 1 broadcasts the hash commitments,
/// round 2 broadcasts the reveals and delivers the P2P shares, then every
/// party finalizes over the accepted sets. The §6.1 defense broadcast is
/// modeled as in `sim.rs`: computed directly from dealer state (the
/// dealt value is non-repudiable, SPEC §10.2) rather than routed through
/// the transport; a production transport would carry defenses as ordinary
/// signed round-3 broadcasts.
///
/// `tamper` is the test fault-injection hook; `corrupt_share` mutates the
/// victim's accepted share (a corruption in transit is observationally
/// identical on the victim's view).
pub fn drive_dkg<R: RngCore>(
    params: &Params,
    sid: &[u8],
    tag: &'static [u8],
    phase: Phase,
    rngs: &mut [R],
    transport: &mut impl Transport<DkgMessage>,
    tamper: Option<&DkgTamper>,
) -> Result<Vec<DkgOutput>> {
    // Round 1: every party samples its dealing and broadcasts the commit.
    let mut insts = Vec::with_capacity(params.n);
    for (k, &i) in params.parties().iter().enumerate() {
        let (mut inst, b1) = DkgInstance::start(*params, sid, tag, i, &mut rngs[k]);
        if let Some((dealer, victim)) = tamper.and_then(|t| t.bad_deal) {
            if dealer == i {
                // Cheating dealer: wrong share *and* wrong §6.1 defense.
                inst.bad_deal = Some(victim);
            }
        }
        transport.broadcast(Envelope::broadcast(
            sid,
            phase,
            DKG_ROUND_COMMIT,
            i,
            DkgMessage::Commit(b1),
        ));
        insts.push(inst);
    }
    // Round 2: reveal broadcasts + P2P shares.
    for inst in &insts {
        let (b2, shares) = inst.reveal();
        transport.broadcast(Envelope::broadcast(
            sid,
            phase,
            DKG_ROUND_REVEAL,
            inst.me,
            DkgMessage::Reveal(b2),
        ));
        for s in shares {
            transport.send_p2p(Envelope::p2p(
                sid,
                phase,
                DKG_ROUND_REVEAL,
                s.from,
                s.to,
                DkgMessage::Share(s),
            ));
        }
    }
    // Round 3 (local): every party finalizes over the accepted sets.
    let r1 = commits_of(transport.accepted_broadcasts(sid, phase, DKG_ROUND_COMMIT));
    let r2 = reveals_of(transport.accepted_broadcasts(sid, phase, DKG_ROUND_REVEAL));
    let mut outs = Vec::with_capacity(params.n);
    for inst in &insts {
        let me = inst.me;
        let mut share_envs = transport.accepted_p2p(sid, phase, DKG_ROUND_REVEAL, me);
        if let Some((dealer, victim)) = tamper.and_then(|t| t.corrupt_share) {
            // Corrupt the share in transit: the dealer's §6.1 defense
            // still verifies, so the victim's complaint is a false
            // accusation.
            if victim == me {
                if let Some(env) = share_envs.get_mut(&dealer) {
                    if let DkgMessage::Share(s) = &mut env.payload {
                        s.share += Scalar::ONE;
                    }
                }
            }
        }
        let mine: BTreeMap<PartyId, Scalar> = share_envs
            .iter()
            .map(|(&f, e)| match &e.payload {
                DkgMessage::Share(s) => (f, s.share),
                _ => unreachable!("p2p carries only shares"),
            })
            .collect();
        let defenses: BTreeMap<PartyId, Scalar> =
            insts.iter().map(|d| (d.me, d.defend(me))).collect();
        outs.push(inst.finalize(phase, &r1, &r2, &mine, &defenses)?);
    }
    Ok(outs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::interpolate_at_zero;
    use k256::ProjectivePoint;

    #[test]
    fn sim_transport_delivers_consistently() {
        let sid = b"sid-1".to_vec();
        let mut t: SimTransport<String> = SimTransport::new();
        for from in 1..=3 {
            t.broadcast(Envelope::broadcast(
                &sid,
                Phase::KeyGen,
                1,
                from,
                format!("b{from}"),
            ));
        }
        // Echo-broadcast consistency (§4.7): one accepted set for the
        // round, the same for every party (the query is not per-party).
        let accepted = t.accepted_broadcasts(&sid, Phase::KeyGen, 1);
        assert_eq!(accepted.len(), 3);
        for from in 1..=3 {
            assert_eq!(accepted[&from].payload, format!("b{from}"));
            assert_eq!(accepted[&from].from, from);
        }
        // Other rounds / sids see nothing (domain separation on the wire).
        assert!(t.accepted_broadcasts(&sid, Phase::KeyGen, 2).is_empty());
        assert!(t.accepted_broadcasts(b"other", Phase::KeyGen, 1).is_empty());

        // P2P: only the addressee receives the message.
        t.send_p2p(Envelope::p2p(&sid, Phase::KeyGen, 2, 1, 2, "s12".into()));
        t.send_p2p(Envelope::p2p(&sid, Phase::KeyGen, 2, 1, 3, "s13".into()));
        let for2 = t.accepted_p2p(&sid, Phase::KeyGen, 2, 2);
        assert_eq!(for2.len(), 1);
        assert_eq!(for2[&1].payload, "s12");
        let for3 = t.accepted_p2p(&sid, Phase::KeyGen, 2, 3);
        assert_eq!(for3.len(), 1);
        assert_eq!(for3[&1].payload, "s13");
        assert!(t.accepted_p2p(&sid, Phase::KeyGen, 2, 1).is_empty());
    }

    #[test]
    fn drive_dkg_reconstructs_joint_key() {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = crate::sim::make_rngs(3, 42);
        let mut t = SimTransport::new();
        let outs = drive_dkg(
            &params,
            b"sid/dkg",
            b"test-tag",
            Phase::KeyGen,
            &mut rngs,
            &mut t,
            None,
        )
        .unwrap();
        // Any t = 2 shares reconstruct the joint secret under the public key.
        let parties = vec![1, 2];
        let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1].share).collect();
        let x = interpolate_at_zero(&parties, &shares);
        assert_eq!(ProjectivePoint::GENERATOR * x, outs[0].com.points[0]);
    }
}
