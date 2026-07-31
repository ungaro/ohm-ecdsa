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
//!   point-equality-verified (fail-fast identifiable abort, the default
//!   posture; the §10.4 robust continuation is the opt-in H4
//!   [`PartyNode::presign_robust`]), `v = 0`/`r = 0` ⇒
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
//! §8.7 KI mode (OPTIONAL key-independent pool — [`party`]):
//!
//! * [`PartyNode::presign_ki`] runs P1–P3 of the per-node presign
//!   verbatim with P4 omitted — a KEY-FREE pool record (`t` shares
//!   reveal no key; still strictly single-use);
//! * [`PartyNode::sign_ki`] binds a pool record to a key ONLINE in two
//!   broadcast rounds (R1 fresh triple + verified δ/ε openings, R2
//!   verified `s_j` shares — fail-fast blame, same posture as the other
//!   wire drivers);
//! * pool records live in a per-node in-memory key-free pool
//!   (`presign_ki_pooled` / `sign_ki_pooled`); the M3b durable store
//!   stays per-key. `node --ki` / `spawn-demo --ki` run the arc.
//!
//! H2 (network resilience — [`mesh`], [`party`]):
//!
//! * reconnection with capped exponential backoff + jitter after the
//!   mesh is up ([`mesh::ReconnectConfig`]): every sent message is
//!   journaled per session BEFORE the write, and a reconnect re-sends
//!   the journal — the resync semantics are "re-deliver every message
//!   of every in-flight session, in original order per session", safe
//!   because the receive path is idempotent (first-echo and acceptor
//!   dedup); finished sessions are retired by the drivers
//!   (`retire_session`) — there is NO crash recovery of finished
//!   rounds by design;
//! * clean shutdown ([`PartyNode::shutdown`] / [`mesh::Node::shutdown`],
//!   also on `Drop`): stop accepting, close outgoing connections,
//!   signal readers/reconnectors, join every thread with a 5 s
//!   deadline;
//! * IO timeouts on all blocking IO: write timeouts on sends, the mTLS
//!   handshake under `tls::HANDSHAKE_TIMEOUT` (socket-timeout strategy,
//!   see [`tls`]), reader threads polling so shutdown stays responsive,
//!   and a stalled peer failing its round loudly via the drivers'
//!   round timeout (partial set, fail closed);
//! * DoS guards that only drop/delay — verification is never weakened:
//!   per-connection frame-rate window (pre-verification), per-variant
//!   frame size bounds derived from protocol message sizes
//!   ([`wire::FrameBound`]), a listener accept-rate window, an mTLS
//!   handshake concurrency cap, a bounded mailbox, and acceptor-level
//!   caps (distinct-sid bound, per-slot equivocation bound) — every
//!   drop increments a [`mesh::MeshMetrics`] counter;
//! * MULTIPLE concurrent protocol sessions: a dedicated collector
//!   thread drains the mesh mailbox into the acceptor and wakes round
//!   waiters via a condvar, so sessions demultiplexed by
//!   `(sid, phase, round)` progress together — the `node --factory N`
//!   demo runs a background presignature factory overlapping online
//!   signing as the proving ground.
//!
//! H3 (distributed committee ceremony — [`ceremony`]):
//!
//! * the DEMO-ONLY one-process ceremony ([`seed`], `setup`) is replaced
//!   as the standard path by a distributed flow: each party runs `init`
//!   on its OWN machine (its transport keypair — and M3c certificate —
//!   are generated locally; only a PUBLIC `party-<id>.pub` bundle
//!   leaves), the bundles travel out of band over an authenticated
//!   channel (short hex fingerprints for second-channel verification),
//!   and a PUBLIC `assemble` step — safe to run anywhere — validates the
//!   bundles and writes the shared `committee.hex` in the exact format
//!   every existing consumer reads. No process ever holds another
//!   party's secret; nodes boot with `--identity` and fail closed when
//!   their own key/cert does not match the assembled registry/pins.
//!
//! H4 (§10.4 robust continuation + §10.3 expel-and-restart — OPT-IN,
//! [`party`]):
//!
//! * [`PartyNode::presign_robust`] — the §10.4 presign: every opening
//!   filtered-and-continued through the core's `open_robust` (blame
//!   identical at every node), nonce points filtered with subset
//!   Lagrange interpolation; dealing phases stay fail-fast;
//! * [`PartyNode::triple_robust`] — the §10.4 triple: a T3 re-share
//!   fault is recovered by PUBLIC RECONSTRUCTION over two added
//!   broadcast rounds (`ReshareRequests` carrying the dealer's own
//!   signed envelope as self-authenticating evidence — a fabricated
//!   request blames the requester — and `ReshareSupply` supplying the
//!   received shares so the first `t` valid ones interpolate the
//!   cheater's committed polynomial; +1 round honestly, +2 on a fault);
//! * [`PartyNode::sign_ki_robust`] — the §10.4 KI sign (robust R1
//!   openings + `sign::combine_ki_robust` in R2; F6 tokens still
//!   archived). [`PartyNode::sign`] was already robust by construction;
//! * [`PartyNode::keygen_with_restart`] / [`PartyNode::presign_with_restart`]
//!   — the §10.3 expel-and-restart policy at the driver level: the same
//!   deterministic restart committee everywhere (the core's
//!   `policy::restart_committee` — `t` never lowered, zero-slack
//!   refusal), poisoned sid (§10.3(2)) and presignature id, survivors'
//!   ORIGINAL ids preserved (the wire never renumbers — the transport
//!   registry pins the ids), retries inherently bounded. The presign
//!   wrapper composes the layers like the sim's
//!   `run_presign_with_restart` (robust in-attempt, restart only for
//!   dealing-phase aborts); `sign_over` / `sign_stored_over` sign over
//!   the post-restart committee. `node --restart` / `spawn-demo
//!   --restart` run the arc; the default stays fail-fast (some
//!   deployments prefer loud aborts).
//!
//! H5 (key-material protection + pool management — [`locked`], [`seal`],
//! [`pool`]):
//!
//! * long-lived secrets at the node boundary (key shares, the transport
//!   signing key, pooled records) are wrapped in page-locked buffers
//!   ([`locked::LockedSecret`], `mlock`/`munlock` — FAIL-OPEN with a loud
//!   warning when the OS refuses, the only fail-open path in H5); the
//!   core's zeroize-on-drop is unchanged;
//! * at-rest: every secret file (presignature records, seed/identity
//!   files) is SEALED — canonical bytes inside a ChaCha20-Poly1305
//!   envelope under a per-node storage key ([`seal::StorageKey`];
//!   resolved from `OHM_STORAGE_KEY` / `OHM_STORAGE_KEY_FILE` / a
//!   generated `0600` dev key file — the KMS/HSM integration point, not
//!   a KMS), written `0600`, legacy cleartext rejected (fail closed);
//! * [`pool::PoolManager`] — the §8.6 pool maintenance layer: keeps the
//!   durable store filled to a target level (single writer; signing
//!   only consumes), enforces a per-record TTL with secure erase
//!   (§8.6(3) — expiry tombstone fsync'd first, id burned forever), and
//!   survives crash/restart without re-issuing ids or over-producing.
//!
//! H2 is still NOT: crash recovery of finished rounds (the journal
//! covers in-flight sessions only), reconnection of INCOMING
//! connections (the dial side reconnects; the accept side just serves
//! whatever arrives — the mesh heals through the dial side), or any
//! kind of production readiness (SPEC §13.1/§13.6 — this is unaudited
//! research code, do not secure real assets with it). There is no
//! SIGINT handler (std has no signal API); a deployment wraps
//! [`PartyNode::shutdown`] in its own signal handling.
//!
//! [`Encode`]: ohm_ecdsa::transport::Encode
//! [`Decode`]: ohm_ecdsa::transport::Decode
//! [`PartyId`]: ohm_ecdsa::PartyId

pub mod net;
pub mod party;
pub mod setup;
pub mod store;

// Flat re-exports: every public module path from before the layering
// (`ohm_ecdsa_node::mesh`, `ohm_ecdsa_node::party::NodePayload`, …) is
// unchanged — internal `crate::…` references resolve through these too.
pub use net::{mesh, tls, transport, wire};
pub use party::pool;
pub use setup::{ceremony, seed};
pub use store::{locked, persist, seal};

pub use mesh::Node;
pub use party::{Cheat, NodePayload, PartyNode};
pub use persist::{Archive, AuditReport, BlameEvidence, DiskPresigStore, PersistError};
pub use pool::{PoolConfig, PoolCounters, PoolManager, PoolStats};
pub use tls::CommitteeTls;
pub use transport::{MeshTransport, DEFAULT_ROUND_TIMEOUT};
pub use wire::{Received, WireMessage};
