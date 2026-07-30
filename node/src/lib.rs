//! `ohm-ecdsa-node` — the transport companion crate for OHM-ECDSA
//! (SPEC §13.1/§13.2): the core's reference transport seam driven over
//! REAL TCP.
//!
//! M1 (the orchestrator substrate, unchanged):
//!
//! * full-mesh TCP on `std::net` with blocking threads and NO external
//!   async runtime (rustls for the optional M3c mTLS layer, [`tls`]);
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
//! * each party runs as its own OS process (see `src/main.rs`:
//!   `--node-id` / `spawn-demo`).
//!
//! M3a (the per-node offline factory — [`party`]):
//!
//! * per-node triple generation (§7.2): T1 deals ⟦α⟧, ⟦β⟧ through two
//!   ephemeral commit-reveal VSS instances (`PartyNode::joint_vss`, the
//!   keygen driver factored out); T2 broadcasts `FeldCommit(g_j)` + ONE
//!   DLEQ product proof with P2P re-shares; T3 verifies proofs (F3 ⇒
//!   blame the prover) and re-shares (F2 ⇒ the same wire §6.1
//!   complaint/defense rounds), then Lagrange-combines;
//! * per-node presign (§8): two triple sessions, ⟦u⟧/⟦a⟧ joint VSS,
//!   Beaver openings and nonce points as broadcast rounds — every share
//!   point-equality-verified (fail-fast identifiable abort; §10.4 robust
//!   continuation stays with the core's sim), `v = 0`/`r = 0` ⇒
//!   `Error::ZeroValue` (retry with a fresh id);
//! * the demo's full arc keygen → presign → sign runs under the key each
//!   node's OWN keygen produced; ceremony-seeded presignatures
//!   ([`seed`]) remain as the `--seeded` fallback.
//!
//! M3b (persistence + evidence — [`persist`]):
//!
//! * [`DiskPresigStore`] — the §8.6 durable single-use presignature
//!   store: write-tmp-rename + fsync per insert, the consume tombstone
//!   fsync'd BEFORE the record is handed out (a kill/restart can never
//!   sign twice with the same presignature); duplicate inserts and
//!   wrong-key reopens rejected with the core store's error semantics.
//!   Wired into the drivers as `PartyNode::presign_stored` /
//!   `sign_stored` / `store_offer`;
//! * [`Archive`] — the §4.7 accepted-message-set transcript (every
//!   accepted signed envelope, fsync'd per entry) plus `aborts.log`;
//! * [`BlameEvidence`] / `audit_token` — the §10.2/§A.4 evidence flow:
//!   blame-token files for the fault classes with wire evidence (F2
//!   dealt shares, F6 sign shares; other classes `token: none`) and an
//!   offline auditor (the `auditor` CLI subcommand).
//!
//! M3c (OPTIONAL transport confidentiality + peer-auth — [`tls`]):
//!
//! * every mesh connection can be wrapped in mutually-authenticated
//!   TLS 1.3 (rustls, blocking streams — still no async runtime) with
//!   certificates PINNED to the committee: no PKI, no system roots,
//!   each node pins the exact cert of every party and the TLS peer
//!   identity matches the expected [`PartyId`] on every link;
//! * the wire format inside the TLS stream is unchanged (canonical
//!   `Encode`/`Decode` frames of signed envelopes); envelope
//!   signatures stay ON regardless — TLS is defense in depth, not a
//!   replacement for the §10.2 message-layer accountability;
//! * plain TCP remains the default for localhost dev; TLS is
//!   configured per node (`--tls CERT KEY --pinned DIR`,
//!   `spawn-demo --tls` generates per-party self-signed certs with
//!   rcgen). Real deployments substitute their own PKI (§13.1).
//!
//! M2/M3a/M3b/M3c are still NOT: robust continuation at the wire
//! level, clean thread shutdown, or any production hardening (SPEC
//! §13.1/§13.6 — this is unaudited research code, do not secure real
//! assets with it).
//!
//! [`Encode`]: ohm_ecdsa::transport::Encode
//! [`Decode`]: ohm_ecdsa::transport::Decode
//! [`PartyId`]: ohm_ecdsa::PartyId

pub mod mesh;
pub mod party;
pub mod persist;
pub mod seed;
pub mod tls;
pub mod transport;
pub mod wire;

pub use mesh::Node;
pub use party::{Cheat, NodePayload, PartyNode};
pub use persist::{Archive, AuditReport, BlameEvidence, DiskPresigStore, PersistError};
pub use tls::CommitteeTls;
pub use transport::{MeshTransport, DEFAULT_ROUND_TIMEOUT};
pub use wire::{Received, WireMessage};
