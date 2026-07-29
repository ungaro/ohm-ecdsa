//! Error and identifiable-abort types for OHM-ECDSA.

use crate::PartyId;

/// Which protocol phase an abort occurred in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    KeyGen,
    Triples,
    Presign,
    Sign,
    /// Committee maintenance (SPEC §13.4): proactive refresh / re-sharing.
    Refresh,
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Phase::KeyGen => "keygen",
            Phase::Triples => "triples",
            Phase::Presign => "presign",
            Phase::Sign => "sign",
            Phase::Refresh => "refresh",
        };
        f.write_str(s)
    }
}

/// An abort with public attribution: every listed party produced a value
/// that failed verification against public commitments (SPEC §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiableAbort {
    pub phase: Phase,
    pub blamed: Vec<PartyId>,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(&'static str),

    #[error("commit-reveal mismatch by party {0}")]
    RevealMismatch(PartyId),

    #[error("invalid share dealt by party {dealer} to party {party}")]
    InvalidShare { dealer: PartyId, party: PartyId },

    #[error("invalid product proof from party {0}")]
    InvalidProductProof(PartyId),

    #[error("invalid opening share from party {0}")]
    InvalidOpening(PartyId),

    #[error("invalid nonce point from party {0}")]
    InvalidNoncePoint(PartyId),

    #[error("invalid signature share from party {0}")]
    InvalidSigShare(PartyId),

    #[error("joint value is zero; restart with fresh randomness: {0}")]
    ZeroValue(String),

    #[error("not enough valid shares: got {got}, need {need}")]
    NotEnoughShares { got: usize, need: usize },

    #[error("identifiable abort: {abort:?}")]
    Abort { abort: IdentifiableAbort },

    #[error("presignature store: {0}")]
    PresigStore(&'static str),

    #[error(transparent)]
    Ecdsa(#[from] k256::ecdsa::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
