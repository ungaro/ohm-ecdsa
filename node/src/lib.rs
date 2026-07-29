//! `ohm-ecdsa-node` — the transport companion crate for OHM-ECDSA
//! (SPEC §13.1/§13.2): the core's reference transport seam driven over
//! REAL TCP.
//!
//! M1 (the orchestrator substrate, unchanged):
//!
//! * full-mesh TCP on `std::net` with blocking threads and NO external
//!   async runtime (tokio/rustls are M3);
//! * length-prefixed framing of the core's canonical
//!   [`Encode`]/[`Decode`] wire format;
//! * §10.2 signed envelopes, verified on receipt (unknown sender or bad
//!   signature: drop + log);
//! * §4.7 echo broadcast: a broadcast value is *accepted* for sender `i`
//!   in a round once `⌈(n+1)/2⌉` distinct parties OTHER than `i` echoed
//!   it, with dedup by `(sid, phase, round, from)`;
//! * [`MeshTransport`] implements the core `Transport` trait, so the M1
//!   reference orchestration (`drive_dkg_signed`, one process holding
//!   every party's key) still runs unchanged.
//!
//! M2 (per-party drivers — [`party`]):
//!
//! * [`PartyNode`] holds ONLY its own material (own transport secret key,
//!   own party id, peer verifying keys, own mesh connections) and runs
//!   only its own protocol logic — key separation by construction;
//! * per-node keygen (§6) with the §6.1 complaint subprotocol carried on
//!   the wire (signed complaint and defense broadcast rounds, every node
//!   adjudicating over its own echo-consistent accepted sets);
//! * per-node online signing (§9): broadcast `sign_share`, per-share
//!   point-equality verification, §10.4 robust combine (bad shares blamed
//!   and excluded, the signature still delivered), low-`s` normalized;
//! * presignature DISTRIBUTION is the documented demo shortcut
//!   ([`seed`]): records come from a prior orchestrated ceremony; the
//!   per-node presign driver is M3;
//! * each party runs as its own OS process (see `src/main.rs`:
//!   `--node-id` / `spawn-demo`).
//!
//! M2 is still NOT: TLS/mTLS (channels are authenticated by per-message
//! ECDSA signatures only), persistence of accepted-message sets, clean
//! thread shutdown, or any production hardening (SPEC §13.1/§13.6 — this
//! is unaudited research code, do not secure real assets with it).
//!
//! [`Encode`]: ohm_ecdsa::transport::Encode
//! [`Decode`]: ohm_ecdsa::transport::Decode

pub mod mesh;
pub mod party;
pub mod seed;
pub mod transport;
pub mod wire;

pub use mesh::Node;
pub use party::{Cheat, NodePayload, PartyNode};
pub use transport::{MeshTransport, DEFAULT_ROUND_TIMEOUT};
pub use wire::{Received, WireMessage};
