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
//! * [`SignedEnvelope`] / [`SigningTransport`] — SPEC §10.2/§13.1
//!   per-message ECDSA signatures: every envelope is signed by its sender
//!   over a canonical length-prefixed encoding of
//!   `(sid ‖ phase ‖ round ‖ from ‖ to ‖ payload)` (domain-separated under
//!   `tags::TRANSPORT_SIGN`) and verified against the party key registry
//!   on receipt; a forgery surfaces as an identifiable error.
//! * [`BlameToken`] — the §10.2/§A.4 evidence object: the abort, the
//!   offending signed envelope, and the public commitment reference; any
//!   auditor re-verifies it offline with only the party public keys.
//! * [`drive_dkg_signed`] — [`drive_dkg`] over a [`SigningTransport`];
//!   complaint resolution additionally yields the offending envelope as a
//!   [`BlameToken`].
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

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar, SecretKey};
use rand::RngCore;

use crate::dkg::{DkgBcast1, DkgBcast2, DkgInstance, DkgOutput, DkgP2P, DkgTamper};
use crate::vss::FeldmanCommitment;
use crate::{tags, Error, IdentifiableAbort, Params, PartyId, Phase, Result};

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

// --- §10.2/§13.1 signed envelopes and blame tokens -------------------------

/// Canonical byte encoding for transport signing (SPEC §13.1): no serde —
/// every field is fixed-width or length-prefixed, so the encoding of
/// `(sid ‖ phase ‖ round ‖ from ‖ to ‖ payload)` is unambiguous.
///
/// Implemented for [`DkgMessage`] (the demo/driver path); other message
/// types implement it as their phases migrate to the signed transport.
pub trait Encode {
    /// Append the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u64(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(&s.to_bytes());
}

fn put_point(out: &mut Vec<u8>, p: &ProjectivePoint) {
    out.extend_from_slice(p.to_affine().to_encoded_point(true).as_bytes());
}

fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::KeyGen => 1,
        Phase::Triples => 2,
        Phase::Presign => 3,
        Phase::Sign => 4,
        Phase::Refresh => 5,
    }
}

impl Encode for FeldmanCommitment {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.points.len() as u64);
        for p in &self.points {
            put_point(out, p);
        }
    }
}

impl Encode for DkgBcast1 {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.from as u64);
        put_bytes(out, &self.hash);
    }
}

impl Encode for DkgBcast2 {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.from as u64);
        self.com.encode(out);
    }
}

impl Encode for DkgP2P {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u64(out, self.from as u64);
        put_u64(out, self.to as u64);
        put_scalar(out, &self.share);
    }
}

impl Encode for DkgMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            DkgMessage::Commit(b) => {
                put_u8(out, 1);
                b.encode(out);
            }
            DkgMessage::Reveal(b) => {
                put_u8(out, 2);
                b.encode(out);
            }
            DkgMessage::Share(s) => {
                put_u8(out, 3);
                s.encode(out);
            }
        }
    }
}

/// The canonical signing bytes of an envelope: the domain-separation tag
/// followed by the unambiguous encoding of all six fields.
fn signing_bytes<M: Encode>(env: &Envelope<M>) -> Vec<u8> {
    let mut out = tags::TRANSPORT_SIGN.to_vec();
    put_bytes(&mut out, &env.sid);
    put_u8(&mut out, phase_code(env.phase));
    put_u8(&mut out, env.round);
    put_u64(&mut out, env.from as u64);
    match env.to {
        None => put_u8(&mut out, 0),
        Some(to) => {
            put_u8(&mut out, 1);
            put_u64(&mut out, to as u64);
        }
    }
    let mut payload = Vec::new();
    env.payload.encode(&mut payload);
    put_bytes(&mut out, &payload);
    out
}

/// An [`Envelope`] plus its sender's ECDSA signature (SPEC §10.2/§13.1):
/// the signature covers the canonical encoding of
/// `(sid ‖ phase ‖ round ‖ from ‖ to ‖ payload)` under
/// `tags::TRANSPORT_SIGN`. This is the non-repudiable wire artifact a
/// [`BlameToken`] is built from.
#[derive(Clone, Debug)]
pub struct SignedEnvelope<M> {
    /// The signed message (all six fields are signature-covered).
    pub envelope: Envelope<M>,
    /// Sender's ECDSA signature over [`signing_bytes`].
    pub signature: Signature,
}

impl<M: Encode> SignedEnvelope<M> {
    /// Sign an envelope with the sender's transport key.
    pub fn sign(envelope: Envelope<M>, key: &SigningKey) -> Self {
        let signature: Signature = key.sign(&signing_bytes(&envelope));
        Self {
            envelope,
            signature,
        }
    }

    /// Verify the signature against the claimed sender's transport key.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        key.verify(&signing_bytes(&self.envelope), &self.signature)
            .is_ok()
    }
}

/// A signing/verifying front end over any `Transport<SignedEnvelope<M>>`
/// (SPEC §10.2/§13.1): outgoing envelopes are signed with the sender's
/// key, incoming accepted sets are verified against the registered party
/// keys. A forged or tampered envelope surfaces as [`Error::Abort`]
/// blaming the envelope's claimed sender — on a signed transport, a
/// malformed envelope is itself attributable (§10.2).
///
/// The reference orchestration drives one shared transport for all
/// parties, so every party's signing key is registered here; a production
/// node holds only its own secret key plus the peers' verifying keys.
pub struct SigningTransport<T> {
    inner: T,
    signing_keys: BTreeMap<PartyId, SigningKey>,
    verifying_keys: BTreeMap<PartyId, VerifyingKey>,
}

impl<T> SigningTransport<T> {
    /// Wrap `inner`; `signers` registers each party's transport keypair
    /// (the verifying-key registry is derived from the secret keys).
    pub fn new(inner: T, signers: &[(PartyId, SecretKey)]) -> Self {
        let mut signing_keys = BTreeMap::new();
        let mut verifying_keys = BTreeMap::new();
        for (id, sk) in signers {
            let key = SigningKey::from(sk);
            verifying_keys.insert(*id, *key.verifying_key());
            signing_keys.insert(*id, key);
        }
        Self {
            inner,
            signing_keys,
            verifying_keys,
        }
    }

    /// The party key registry — all an auditor needs to verify blame
    /// tokens offline (SPEC §A.4).
    pub fn verifying_keys(&self) -> Vec<(PartyId, VerifyingKey)> {
        self.verifying_keys.iter().map(|(&p, &k)| (p, k)).collect()
    }

    /// Sign `env` with its sender's key and hand it to the inner
    /// transport as a broadcast.
    pub fn broadcast<M: Clone + Encode>(&mut self, env: Envelope<M>)
    where
        T: Transport<SignedEnvelope<M>>,
    {
        let signed = self.sign_env(env);
        self.inner.broadcast(Envelope::broadcast(
            &signed.envelope.sid.clone(),
            signed.envelope.phase,
            signed.envelope.round,
            signed.envelope.from,
            signed,
        ));
    }

    /// Sign `env` with its sender's key and hand it to the inner
    /// transport as a point-to-point message.
    pub fn send_p2p<M: Clone + Encode>(&mut self, env: Envelope<M>)
    where
        T: Transport<SignedEnvelope<M>>,
    {
        let signed = self.sign_env(env);
        let to = signed.envelope.to.expect("p2p envelope has an addressee");
        self.inner.send_p2p(Envelope::p2p(
            &signed.envelope.sid.clone(),
            signed.envelope.phase,
            signed.envelope.round,
            signed.envelope.from,
            to,
            signed,
        ));
    }

    fn sign_env<M: Encode>(&self, env: Envelope<M>) -> SignedEnvelope<M> {
        let key = self
            .signing_keys
            .get(&env.from)
            .expect("sender has a registered transport key");
        SignedEnvelope::sign(env, key)
    }

    /// The verified accepted broadcast set of one round. Every envelope's
    /// signature must verify under its claimed sender's registered key.
    pub fn accepted_broadcasts<M: Clone + Encode>(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
    ) -> Result<BTreeMap<PartyId, SignedEnvelope<M>>>
    where
        T: Transport<SignedEnvelope<M>>,
    {
        self.verify_all(phase, self.inner.accepted_broadcasts(sid, phase, round))
    }

    /// The verified accepted messages of one round addressed to `to`.
    pub fn accepted_p2p<M: Clone + Encode>(
        &self,
        sid: &[u8],
        phase: Phase,
        round: u8,
        to: PartyId,
    ) -> Result<BTreeMap<PartyId, SignedEnvelope<M>>>
    where
        T: Transport<SignedEnvelope<M>>,
    {
        self.verify_all(phase, self.inner.accepted_p2p(sid, phase, round, to))
    }

    fn verify_all<M: Clone + Encode>(
        &self,
        phase: Phase,
        raw: BTreeMap<PartyId, Envelope<SignedEnvelope<M>>>,
    ) -> Result<BTreeMap<PartyId, SignedEnvelope<M>>> {
        let mut out = BTreeMap::new();
        for (claimed, outer) in raw {
            let signed = outer.payload;
            let from = signed.envelope.from;
            let valid = self
                .verifying_keys
                .get(&from)
                .is_some_and(|key| signed.verify_signature(key));
            if !valid {
                return Err(Error::Abort {
                    abort: IdentifiableAbort {
                        phase,
                        blamed: vec![from],
                        detail: "invalid transport signature (forged or tampered envelope)".into(),
                    },
                });
            }
            out.insert(claimed, signed);
        }
        Ok(out)
    }
}

/// A completed blame event as offline-verifiable evidence (SPEC §10.2):
/// the [`IdentifiableAbort`], the offending signed envelope (e.g. the bad
/// dealt share), and the public reference needed to re-verify (the
/// dealer's Feldman commitment vector; the `sid` travels inside the
/// signature-covered envelope). This is exactly what the §A.4 evidence
/// flow archives — retention is safe (§10.5): the token carries only
/// public commitments, one dealt share, and a signature.
#[derive(Clone, Debug)]
pub struct BlameToken {
    /// The abort the token substantiates.
    pub abort: IdentifiableAbort,
    /// The offending signed message, signed by the blamed party.
    pub envelope: SignedEnvelope<DkgMessage>,
    /// The blamed dealer's revealed commitment vector (the public
    /// reference the failed check is recomputed against).
    pub com: FeldmanCommitment,
}

impl BlameToken {
    /// The auditor's offline check (SPEC §10.2, §A.4 step 3) — no secret
    /// material, only the party transport keys and the token:
    ///
    /// (a) the envelope signature verifies under the blamed party's
    ///     transport key;
    /// (b) recomputing the failed check really fails: the dealt share
    ///     does not satisfy point equality against `EvalCom(com, to)`;
    /// (c) the blame is consistent: the abort names exactly the
    ///     envelope's sender, in the envelope's phase.
    ///
    /// Returns `false` on any mismatch (forgery, wrong key, tampered
    /// payload, mismatched commitment, inconsistent blame).
    pub fn verify(&self, party_keys: &[(PartyId, VerifyingKey)]) -> bool {
        // (c) blame/phase consistency.
        if self.abort.blamed != [self.envelope.envelope.from]
            || self.abort.phase != self.envelope.envelope.phase
        {
            return false;
        }
        // The evidence is a dealt share signed by the blamed dealer.
        let DkgMessage::Share(share) = &self.envelope.envelope.payload else {
            return false;
        };
        if share.from != self.envelope.envelope.from {
            return false;
        }
        // (a) signature under the blamed party's transport key.
        let Some((_, key)) = party_keys.iter().find(|(p, _)| p == &share.from) else {
            return false;
        };
        if !self.envelope.verify_signature(key) {
            return false;
        }
        // (b) the failed check really fails (detection is unconditional,
        // §11 C3: exactly one scalar per position passes EvalCom).
        !self.com.verify_share(share.to, &share.share)
    }
}

/// Failure of [`drive_dkg_signed`]: the protocol error plus, when the
/// failure left cryptographic evidence on the wire (a dealer's bad dealt
/// share, fault class F2 of §10.1), the [`BlameToken`] built from it.
/// Faults without a wire artifact (e.g. a false accusation) carry
/// `token: None`.
#[derive(Debug)]
pub struct SignedDriveError {
    /// The protocol error (usually `Error::Abort` with blame).
    pub error: Error,
    /// The blame token, when the abort is attributable to a signed
    /// message (boxed to keep the `Err` variant small).
    pub token: Option<Box<BlameToken>>,
}

impl core::fmt::Display for SignedDriveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for SignedDriveError {}

/// [`drive_dkg`] over a [`SigningTransport`] (SPEC §6, §10.2): identical
/// rounds and verification, but every envelope is signed and
/// signature-verified, and a dealer fault resolved by the §6.1 complaint
/// subprotocol additionally yields the offending signed share envelope as
/// a [`BlameToken`] inside [`SignedDriveError`]. `drive_dkg` remains the
/// unsigned entry point used by `sim::run_keygen`.
pub fn drive_dkg_signed<R: RngCore>(
    params: &Params,
    sid: &[u8],
    tag: &'static [u8],
    phase: Phase,
    rngs: &mut [R],
    transport: &mut SigningTransport<impl Transport<SignedEnvelope<DkgMessage>>>,
    tamper: Option<&DkgTamper>,
) -> std::result::Result<Vec<DkgOutput>, SignedDriveError> {
    // Round 1: every party samples its dealing and broadcasts the commit.
    let mut insts = Vec::with_capacity(params.n);
    for (k, &i) in params.parties().iter().enumerate() {
        let (mut inst, b1) = DkgInstance::start(*params, sid, tag, i, &mut rngs[k]);
        if let Some((dealer, victim)) = tamper.and_then(|t| t.bad_deal) {
            if dealer == i {
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
    // Round 3 (local): every party finalizes over the verified accepted
    // sets; a signature failure is itself an identifiable abort (§10.2).
    let signed_error = |error| SignedDriveError { error, token: None };
    let unsigned = |envs: BTreeMap<PartyId, SignedEnvelope<DkgMessage>>| {
        envs.into_iter().map(|(f, e)| (f, e.envelope)).collect()
    };
    let r1 = commits_of(unsigned(
        transport
            .accepted_broadcasts(sid, phase, DKG_ROUND_COMMIT)
            .map_err(signed_error)?,
    ));
    let r2 = reveals_of(unsigned(
        transport
            .accepted_broadcasts(sid, phase, DKG_ROUND_REVEAL)
            .map_err(signed_error)?,
    ));
    let mut outs = Vec::with_capacity(params.n);
    for inst in &insts {
        let me = inst.me;
        let mut share_envs = transport
            .accepted_p2p(sid, phase, DKG_ROUND_REVEAL, me)
            .map_err(signed_error)?;
        if let Some((dealer, victim)) = tamper.and_then(|t| t.corrupt_share) {
            // Corrupt the share in transit: the dealer's §6.1 defense
            // still verifies, so the victim's complaint is a false
            // accusation.
            if victim == me {
                if let Some(env) = share_envs.get_mut(&dealer) {
                    if let DkgMessage::Share(s) = &mut env.envelope.payload {
                        s.share += Scalar::ONE;
                    }
                }
            }
        }
        let mine: BTreeMap<PartyId, Scalar> = share_envs
            .iter()
            .map(|(&f, e)| match &e.envelope.payload {
                DkgMessage::Share(s) => (f, s.share),
                _ => unreachable!("p2p carries only shares"),
            })
            .collect();
        let defenses: BTreeMap<PartyId, Scalar> =
            insts.iter().map(|d| (d.me, d.defend(me))).collect();
        match inst.finalize(phase, &r1, &r2, &mine, &defenses) {
            Ok(out) => outs.push(out),
            Err(error) => {
                let token = dealer_blame_token(&error, &share_envs, &r2).map(Box::new);
                return Err(SignedDriveError { error, token });
            }
        }
    }
    Ok(outs)
}

/// Build the §10.2 blame token for a dealer fault (F2): the abort must
/// name a dealer whose signed share envelope really fails the commitment
/// check. Any other abort shape (false accusation, commit-reveal
/// mismatch) leaves no share-envelope evidence and yields `None`.
fn dealer_blame_token(
    error: &Error,
    share_envs: &BTreeMap<PartyId, SignedEnvelope<DkgMessage>>,
    r2: &BTreeMap<PartyId, DkgBcast2>,
) -> Option<BlameToken> {
    let Error::Abort { abort } = error else {
        return None;
    };
    let [dealer] = abort.blamed[..] else {
        return None;
    };
    let envelope = share_envs.get(&dealer)?.clone();
    let com = r2.get(&dealer)?.com.clone();
    let DkgMessage::Share(share) = &envelope.envelope.payload else {
        return None;
    };
    if share.from != dealer || com.verify_share(share.to, &share.share) {
        return None;
    }
    Some(BlameToken {
        abort: abort.clone(),
        envelope,
        com,
    })
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

    // --- §10.2 signed envelopes / blame tokens --------------------------

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_signers(n: usize, seed: u64) -> Vec<(PartyId, SecretKey)> {
        let mut rng = StdRng::seed_from_u64(seed);
        (1..=n).map(|i| (i, SecretKey::random(&mut rng))).collect()
    }

    fn commit_msg(from: PartyId) -> DkgMessage {
        DkgMessage::Commit(DkgBcast1 {
            from,
            hash: [7; 32],
        })
    }

    #[test]
    fn signing_transport_roundtrip() {
        let sid = b"sid-signed".to_vec();
        let signers = make_signers(3, 11);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        for from in 1..=3 {
            st.broadcast(Envelope::broadcast(
                &sid,
                Phase::KeyGen,
                DKG_ROUND_COMMIT,
                from,
                commit_msg(from),
            ));
        }
        let accepted = st
            .accepted_broadcasts(&sid, Phase::KeyGen, DKG_ROUND_COMMIT)
            .unwrap();
        assert_eq!(accepted.len(), 3);
        let registry = st.verifying_keys();
        for from in 1..=3 {
            let signed = &accepted[&from];
            assert_eq!(signed.envelope.from, from);
            // Every accepted envelope verifies under its sender's key.
            let key = registry.iter().find(|(p, _)| *p == from).unwrap().1;
            assert!(signed.verify_signature(&key));
        }
    }

    #[test]
    fn signing_transport_rejects_wrong_key() {
        let sid = b"sid-forge".to_vec();
        let signers = make_signers(3, 12);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        // Forgery: party 2's key signs an envelope claiming to be party 1.
        let forged = SignedEnvelope::sign(
            Envelope::broadcast(&sid, Phase::KeyGen, DKG_ROUND_COMMIT, 1, commit_msg(1)),
            &st.signing_keys[&2],
        );
        st.inner.broadcast(Envelope::broadcast(
            &sid,
            Phase::KeyGen,
            DKG_ROUND_COMMIT,
            1,
            forged,
        ));
        let err = st
            .accepted_broadcasts(&sid, Phase::KeyGen, DKG_ROUND_COMMIT)
            .unwrap_err();
        match err {
            Error::Abort { abort } => {
                assert_eq!(abort.blamed, vec![1]); // the claimed sender
                assert_eq!(abort.phase, Phase::KeyGen);
            }
            other => panic!("expected identifiable abort, got {other:?}"),
        }
    }

    #[test]
    fn signing_transport_rejects_tampered_payload() {
        let sid = b"sid-tamper".to_vec();
        let signers = make_signers(3, 13);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        // Sign honestly, then flip a byte in the payload after signing.
        let mut signed = SignedEnvelope::sign(
            Envelope::broadcast(&sid, Phase::KeyGen, DKG_ROUND_COMMIT, 2, commit_msg(2)),
            &st.signing_keys[&2],
        );
        let DkgMessage::Commit(b) = &mut signed.envelope.payload else {
            unreachable!()
        };
        b.hash[0] ^= 1;
        assert!(!signed.verify_signature(&st.verifying_keys[&2]));
        st.inner.broadcast(Envelope::broadcast(
            &sid,
            Phase::KeyGen,
            DKG_ROUND_COMMIT,
            2,
            signed,
        ));
        let err = st
            .accepted_broadcasts(&sid, Phase::KeyGen, DKG_ROUND_COMMIT)
            .unwrap_err();
        match err {
            Error::Abort { abort } => assert_eq!(abort.blamed, vec![2]),
            other => panic!("expected identifiable abort, got {other:?}"),
        }
    }

    #[test]
    fn drive_dkg_signed_honest_run() {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = crate::sim::make_rngs(3, 21);
        let signers = make_signers(3, 22);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        let outs = drive_dkg_signed(
            &params,
            b"sid/signed-dkg",
            b"test-tag",
            Phase::KeyGen,
            &mut rngs,
            &mut st,
            None,
        )
        .unwrap();
        let parties = vec![1, 2];
        let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1].share).collect();
        let x = interpolate_at_zero(&parties, &shares);
        assert_eq!(ProjectivePoint::GENERATOR * x, outs[0].com.points[0]);
    }

    #[test]
    fn drive_dkg_signed_yields_blame_token() {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = crate::sim::make_rngs(3, 23);
        let signers = make_signers(3, 24);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        let registry = st.verifying_keys();
        let tamper = DkgTamper {
            bad_deal: Some((2, 1)),
            ..Default::default()
        };
        let err = drive_dkg_signed(
            &params,
            b"sid/signed-dkg",
            b"test-tag",
            Phase::KeyGen,
            &mut rngs,
            &mut st,
            Some(&tamper),
        )
        .unwrap_err();
        let Error::Abort { abort } = &err.error else {
            panic!("expected identifiable abort, got {:?}", err.error)
        };
        assert_eq!(abort.blamed, vec![2]);
        let token = err.token.expect("a dealer fault leaves a blame token");
        assert_eq!(token.abort.blamed, vec![2]);
        assert!(token.verify(&registry));
    }

    #[test]
    fn blame_token_rejects_forgery_and_wrong_registry() {
        let params = Params::new(3, 2).unwrap();
        let mut rngs = crate::sim::make_rngs(3, 25);
        let signers = make_signers(3, 26);
        let mut st = SigningTransport::new(SimTransport::new(), &signers);
        let registry = st.verifying_keys();
        let tamper = DkgTamper {
            bad_deal: Some((2, 1)),
            ..Default::default()
        };
        let token = drive_dkg_signed(
            &params,
            b"sid/signed-dkg",
            b"test-tag",
            Phase::KeyGen,
            &mut rngs,
            &mut st,
            Some(&tamper),
        )
        .unwrap_err()
        .token
        .unwrap();
        assert!(token.verify(&registry));

        // Forgery: flip a byte in the signed payload — the signature no
        // longer verifies, so the auditor rejects the token.
        let mut forged = token.clone();
        let DkgMessage::Share(s) = &mut forged.envelope.envelope.payload else {
            unreachable!()
        };
        s.share += Scalar::ONE;
        assert!(!forged.verify(&registry));

        // Wrong registry: keys of an unrelated committee — check (a) fails.
        let other = make_signers(3, 27);
        let wrong_registry: Vec<(PartyId, VerifyingKey)> = other
            .iter()
            .map(|(p, sk)| (*p, *SigningKey::from(sk).verifying_key()))
            .collect();
        assert!(!token.verify(&wrong_registry));
    }
}
