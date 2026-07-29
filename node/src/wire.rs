//! The wire protocol: length-prefixed frames of signed messages
//! (SPEC §4.7, §10.2, §13.1).
//!
//! Every frame is one [`WireMessage`] in the core's canonical
//! [`Encode`]/[`Decode`] format, prefixed by a 4-byte big-endian length.
//! Two message kinds:
//!
//! * [`WireMessage::Original`] — a protocol envelope exactly as its
//!   sender signed it (broadcast or P2P);
//! * [`WireMessage::Echo`] — a §4.7 echo of a broadcast, re-signed by the
//!   ECHOING party so echoes are attributable: a relayed echo cannot be
//!   planted under an honest party's name, and the acceptance count is
//!   per distinct echoer.
//!
//! The payload type `M` is generic: M1 drives the core's
//! [`DkgMessage`] through `drive_dkg_signed`; M2's per-node drivers
//! ([`crate::party`]) use the node crate's own payload enum. The framing,
//! echo, and signature rules are payload-agnostic.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ohm_ecdsa::transport::{Decode, Encode, SignedEnvelope};
use ohm_ecdsa::PartyId;

/// Domain separation for echo signatures (the core's tags are
/// crate-private; this tag is the node crate's own).
const ECHO_TAG: &[u8] = b"OHM-ECDSA-NODE/v0.1/echo";

/// Largest accepted frame: a garbage length prefix must not trigger an
/// unbounded allocation. Protocol frames are a few hundred bytes.
const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// One message on the wire.
#[derive(Clone, Debug)]
pub enum WireMessage<M> {
    /// A protocol envelope as sent by its origin (broadcast or P2P),
    /// signed by the sender under the core's transport-signing tag.
    Original(SignedEnvelope<M>),
    /// A §4.7 echo of a broadcast, signed by the echoing party.
    Echo {
        /// The party emitting this echo.
        echoer: PartyId,
        /// The broadcast being echoed (itself signed by its sender).
        original: SignedEnvelope<M>,
        /// The echoer's signature over `ECHO_TAG ‖ echoer ‖ original`.
        signature: Signature,
    },
}

impl<M: Encode> WireMessage<M> {
    /// Build a signed echo of a broadcast.
    pub fn echo(echoer: PartyId, original: SignedEnvelope<M>, key: &SigningKey) -> Self {
        let signature: Signature = key.sign(&echo_bytes(echoer, &original));
        Self::Echo {
            echoer,
            original,
            signature,
        }
    }

    /// Cryptographic validation: every claimed sender is a registered
    /// party and every signature verifies. Routing rules (P2P addressee,
    /// first-echo-per-slot) are the mesh's job, not this function's.
    pub fn verify(&self, registry: &BTreeMap<PartyId, VerifyingKey>) -> bool {
        match self {
            Self::Original(se) => valid_original(se, registry),
            Self::Echo {
                echoer,
                original,
                signature,
            } => {
                // Only broadcasts are echoed, and a party's echo of its
                // OWN message is meaningless (the sender's copy is never
                // counted toward acceptance) — reject both here.
                if echoer == &original.envelope.from || original.envelope.to.is_some() {
                    return false;
                }
                valid_original(original, registry)
                    && registry.get(echoer).is_some_and(|key| {
                        key.verify(&echo_bytes(*echoer, original), signature)
                            .is_ok()
                    })
            }
        }
    }
}

fn valid_original<M: Encode>(
    se: &SignedEnvelope<M>,
    registry: &BTreeMap<PartyId, VerifyingKey>,
) -> bool {
    registry
        .get(&se.envelope.from)
        .is_some_and(|key| se.verify_signature(key))
}

fn echo_bytes<M: Encode>(echoer: PartyId, original: &SignedEnvelope<M>) -> Vec<u8> {
    let mut out = ECHO_TAG.to_vec();
    out.extend_from_slice(&(echoer as u64).to_be_bytes());
    original.encode(&mut out);
    out
}

/// A wire message that survived signature verification: the reader
/// threads' output, the echo-broadcast acceptor's input.
#[derive(Clone, Debug)]
pub enum Received<M> {
    /// A verified original envelope (broadcast or P2P).
    Original(SignedEnvelope<M>),
    /// A verified echo of a broadcast.
    Echo {
        /// The verified echoing party.
        echoer: PartyId,
        /// The verified broadcast being echoed.
        original: SignedEnvelope<M>,
    },
}

impl<M: Encode> Encode for WireMessage<M> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Original(se) => {
                out.push(1);
                se.encode(out);
            }
            Self::Echo {
                echoer,
                original,
                signature,
            } => {
                out.push(2);
                out.extend_from_slice(&(*echoer as u64).to_be_bytes());
                original.encode(out);
                signature.encode(out);
            }
        }
    }
}

impl<M: Decode> Decode for WireMessage<M> {
    fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let tag = *bytes.first()?;
        let mut used = 1;
        match tag {
            1 => {
                let (se, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                Some((Self::Original(se), used))
            }
            2 => {
                let (echoer, u) = take_u64(bytes.get(used..)?)?;
                used += u;
                let (original, u) = SignedEnvelope::decode(bytes.get(used..)?)?;
                used += u;
                let (signature, u) = Signature::decode(bytes.get(used..)?)?;
                used += u;
                Some((
                    Self::Echo {
                        echoer: usize::try_from(echoer).ok()?,
                        original,
                        signature,
                    },
                    used,
                ))
            }
            _ => None,
        }
    }
}

pub(crate) fn take_u64(b: &[u8]) -> Option<(u64, usize)> {
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some((u64::from_be_bytes(a), 8))
}

/// The canonical bytes of one framed message (`u32` BE length ‖ payload).
pub fn frame_bytes<M: Encode>(msg: &WireMessage<M>) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    let len = u32::try_from(buf.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    let mut out = Vec::with_capacity(4 + buf.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Write one length-prefixed frame (`u32` BE length ‖ canonical bytes).
pub fn write_frame<M: Encode>(w: &mut impl Write, msg: &WireMessage<M>) -> io::Result<()> {
    w.write_all(&frame_bytes(msg)?)
}

/// Read one frame. `Ok(None)` on a clean connection close between frames;
/// `Err` on truncation, oversize, or malformed content (the caller drops
/// the connection).
pub fn read_frame<M: Decode>(r: &mut impl Read) -> io::Result<Option<WireMessage<M>>> {
    let mut hdr = [0u8; 4];
    if !read_exact_or_eof(r, &mut hdr)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(hdr);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    let (msg, used) = WireMessage::decode(&buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed frame"))?;
    if used != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes in frame",
        ));
    }
    Ok(Some(msg))
}

/// `read_exact` that reports a clean EOF (0 bytes read) as `false`.
fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut done = 0;
    while done < buf.len() {
        match r.read(&mut buf[done..]) {
            Ok(0) if done == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ))
            }
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}
