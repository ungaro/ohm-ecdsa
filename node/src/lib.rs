//! `ohm-ecdsa-node` — the M1 transport companion crate for OHM-ECDSA
//! (SPEC §13.1/§13.2): the core's reference transport seam driven over
//! REAL TCP.
//!
//! M1 scope (deliberately boring):
//!
//! * full-mesh TCP on `std::net` with blocking threads and NO external
//!   async runtime (tokio/rustls are M2);
//! * length-prefixed framing of the core's canonical [`Encode`]/[`Decode`]
//!   wire format;
//! * §10.2 signed envelopes, verified on receipt (unknown sender or bad
//!   signature: drop + log);
//! * §4.7 echo broadcast: a broadcast value is *accepted* for sender `i`
//!   in a round once `⌈(n+1)/2⌉` distinct parties OTHER than `i` echoed
//!   it, with dedup by `(sid, phase, round, from)`;
//! * [`MeshTransport`] implements the core `Transport` trait, so keygen
//!   runs through `drive_dkg_signed` unchanged.
//!
//! M1 is the reference-orchestration pattern: one process holds every
//! party's transport key and drives all parties (exactly as the core
//! drives `SimTransport`); the TCP separation is at the wire level.
//! Per-party process separation, TLS, persistence of accepted-message
//! sets, and any production hardening are M2+ (SPEC §13.1/§13.6 — this is
//! unaudited research code, do not secure real assets with it).
//!
//! [`Encode`]: ohm_ecdsa::transport::Encode
//! [`Decode`]: ohm_ecdsa::transport::Decode

pub mod mesh;
pub mod transport;
pub mod wire;

pub use mesh::Node;
pub use transport::{MeshTransport, DEFAULT_ROUND_TIMEOUT};
pub use wire::{Received, WireMessage};
