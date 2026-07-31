# ohm-ecdsa-node — transport companion (reference code)

**Unaudited research code. Do NOT secure real assets with it.** See
`SPEC.md` §13 (and §13.6) for the full disclaimers; everything the core
crate says about being a reference implementation of an unreviewed
protocol draft applies here doubly — this crate adds a *network* to it.

This crate is the SPEC §13.1/§13.2 path "from the reference orchestrator
to production", driven over **real TCP** on `std::net` with blocking
threads and **no external async runtime** (rustls for the optional M3c
mTLS layer). Milestones:

* **M1** — the orchestrator substrate: full-mesh TCP, length-prefixed
  framing of the core's canonical `Encode`/`Decode` wire format, §10.2
  signed envelopes verified on receipt, §4.7 echo broadcast
  (`MeshTransport` implementing the core `Transport` trait), keygen
  through `drive_dkg_signed`. One process holds every party's key.
  The broadcast primitive is **signed-echo consistent broadcast**: a
  value `m` from sender `i` is *accepted* iff (1) the acceptor holds
  `i`'s valid signature on `m` (echoes carry the sender's signed
  message, so acceptance condition (1) is always checkable and
  equivocation evidence constructible), (2) `m` was echoed by `≥ T−1`
  distinct parties other than `i`, and (3) no conflicting sender-signed
  value was seen — a second distinct payload in one slot poisons the
  sender for the session (`⊥`, the value never delivered) and the two
  signed envelopes are archived as offline-verifiable F8 blame evidence
  (`BlameEvidence::Equivocation`, checked by the `auditor`).
  *Design note:* the superseded textbook rule — accept on
  `⌈(n+1)/2⌉` consistent echoes — is inconsistent at `T ≥ 3`: two
  size-`T` quorums of `n = 2T−1` may intersect only in corrupt parties,
  so a corrupt sender with one colluding echoer could split the honest
  accepted sets (demonstrated at `n = 5, T = 3, f = 2`; the
  `node/tests/echo_consistency.rs` regression test drives exactly this
  attack over the wire).
* **M2** — per-party node drivers (`src/party/party.rs`): the orchestrator
  model is gone. A `PartyNode` holds ONLY its own material — its own
  transport secret key, its own party id, the peers' verifying keys, its
  own mesh connections — and runs only its own protocol logic. Each
  party runs as its own OS process (see the demo below).
* **M3a** — the per-node OFFLINE FACTORY over the wire (`src/party/party.rs`):
  per-node triple generation (SPEC §7.2) and per-node presign (SPEC §8)
  as `PartyNode` drivers, with every share verified and every cheater
  named consistently at every node. The demo's full arc — keygen →
  presign → sign — now runs under the key each process's OWN keygen
  produced; ceremony-seeded presignatures remain as a `--seeded`
  fallback.
* **M3b** — persistence + blame-token archiving (`src/store/persist.rs`): a
  durable, crash-safe single-use presignature store per node per key
  (SPEC §8.6), an append-only transcript of every accepted signed
  envelope (§4.7), blame-token files for the fault classes that leave
  cryptographic evidence on the wire (§10.2), and an offline `auditor`
  subcommand re-verifying a token against the committee's public keys
  (§A.4). Everything on disk is the core's canonical `Encode`/`Decode`
  wire format; std only.
* **M3c** — OPTIONAL mTLS on the mesh (`src/net/tls.rs`): every connection
  wrapped in mutually-authenticated TLS 1.3 (rustls + ring, blocking
  streams) with certificates **pinned to the committee** — no PKI, no
  system roots. Plain TCP remains the default for localhost dev; any
  non-localhost deployment MUST run TLS (see below).
* **H2** — network resilience (still localhost reference scale):
  reconnection with capped exponential backoff + jitter and a
  journal-based re-sync of in-flight sessions, clean shutdown
  (`Node::shutdown` / `PartyNode::shutdown`, also on `Drop`), timeouts
  on all blocking IO, DoS guards that only drop/delay (per-connection
  frame-rate window, per-variant frame size bounds, listener
  accept-rate window, mTLS handshake concurrency cap, bounded mailbox,
  acceptor-level caps — all counted in `MeshMetrics`), and MULTIPLE
  concurrent protocol sessions demultiplexed by sid (the
  `node --factory N` background presignature factory is the proving
  ground). Details below.
* **H3** — the distributed committee ceremony (`src/setup/ceremony.rs`): the
  standard setup path for a real committee. Each party generates its
  OWN transport keypair (and M3c certificate) on its own machine
  (`init`); only PUBLIC `party-<id>.pub` bundles leave, exchanged out
  of band over an authenticated channel (short hex fingerprints for
  second-channel verification); a PUBLIC `assemble` step — safe to run
  anywhere — writes the shared `committee.hex` in the unchanged
  existing format. No process ever holds another party's secret. The
  one-process `setup`/`spawn-demo` ceremony stays as a DEMO-ONLY path.
* **§8.7 KI mode over the wire** — the OPTIONAL key-independent
  presignature pool (`PartyNode::presign_ki` / `sign_ki`): pool
  production is P1–P3 of the per-node presign verbatim with P4 omitted
  (the record is KEY-FREE — not key-equivalent); signing binds the record
  to a key ONLINE in two broadcast rounds (R1 fresh triple + verified
  δ/ε openings, R2 verified `s_j` shares). One pool serves any key the
  committee owns — including keys generated after the pool was filled.
  Records live in a per-node in-memory key-free pool (`KiPool`); the M3b
  durable store stays per-key. `spawn-demo --ki` runs the arc.
* **H5** — key-material protection + pool management (SPEC §8.6, §13.3):
  page-locked secrets at the node boundary (`src/store/locked.rs`, `mlock`,
  fail-open with a loud warning), AEAD encryption at rest for every
  secret file (`src/store/seal.rs`, ChaCha20-Poly1305 under a per-node storage
  key, `0600`, legacy cleartext rejected), and the presignature pool
  manager (`src/party/pool.rs`) keeping the durable store filled to a target
  level with per-record TTL expiry (§8.6(3) secure erase). Details
  below.

## What M2/M3a is

* **Key separation by construction.** `PartyNode::bind` takes exactly
  one `SecretKey` (this node's) plus the public registry; no `PartyNode`
  API accepts another party's secret material. A node process reads
  exactly its own secret file (demo seed or H3 identity) plus the public
  committee file (`src/setup/seed.rs`, `src/setup/ceremony.rs`).
* **Per-node keygen (SPEC §6)** over the mesh: commit → reveal + P2P
  shares → **§6.1 complaint subprotocol on the wire** — round 3 carries
  signed `Complaints` broadcasts, round 4 signed `Defenses` broadcasts,
  and every node adjudicates `EvalCom(A_d, j)` against the defense over
  its own echo-consistent accepted sets, so all honest nodes reach the
  SAME blame verdict: a verifying defense means a false accusation
  (accuser blamed); a failing or missing defense means a cheating
  dealer. The M1 shortcut (defenses read from dealer state in one
  process) is gone. The same machinery is factored out as
  `PartyNode::joint_vss` — one ephemeral joint random sharing over the
  wire — and reused by the offline factory.
* **Per-node triple generation (SPEC §7.2, M3a)**: T1 deals joint random
  ⟦α⟧, ⟦β⟧ through two `joint_vss` instances; T2 broadcasts
  `FeldCommit(g_j)` + ONE DLEQ product proof and sends the re-shares
  `g_j(i)` P2P; T3 verifies every proof (F3 ⇒ blame the prover — the
  same check everywhere, no complaint round) and every received re-share
  (F2 ⇒ the same wire §6.1 complaint/defense rounds as keygen), then
  combines with Lagrange weights. A bad DLEQ proof, a bad re-shared
  share, and a false accusation are each named consistently by every
  node.
* **Per-node presign (SPEC §8, M3a)**: two triple sessions plus two
  `joint_vss` instances (⟦u⟧, ⟦a⟧), then the Beaver openings δ/ε, v,
  δ′/ε′ and the nonce points `R_j` as broadcast rounds — every opening
  share checked against its public commitment by point equality, every
  nonce point against `EvalCom(A[k], j)` (F5 ⇒ blame the sender). ε′
  masks this node's OWN long-term key share. Openings are FAIL-FAST
  identifiable aborts (the default posture; the §10.4 robust
  blame-and-continue variant is the opt-in `presign_robust` — see H4
  below). `v = 0` / `r = 0` return `Error::ZeroValue`;
  the caller retries with a fresh presignature id (the demo treats it as
  fatal — probability ~2⁻¹²⁸ per session). Records are held in memory, or
  persisted by the M3b durable store when the node runs with
  `--data-dir` (below).
* **Per-node online signing (SPEC §9, §10.4)**: each node computes
  `sign_share` locally, broadcasts it (signed + echo), verifies every
  received share against `m·A[u] + r·A[z]` by point equality (bad shares
  are blamed and excluded), interpolates from the first `t` valid
  shares, low-`s` normalizes. A cheating signer is named by every node
  and the signature is still delivered.
* **Presignature distribution: self-produced by default; ceremony
  fallback.** With M3a the default demo presigns through the mesh under
  the key its own keygen produced. The M2 ceremony (`seed::ceremony`)
  remains as a fallback (`--seeded`): a prior orchestrated run writing
  one SECRET seed file per party (its transport key, its key share, its
  presignature records) and one PUBLIC committee file. Note the
  transport keys themselves still come from the seed files in both modes
  (the demo's §13.1 deployment-PKI stand-in). Seed files are secret
  material on disk; retention/zeroization of files is a deployment
  concern (SPEC §13.3).
* **Process separation**: `spawn-demo` launches three child processes,
  each running `node` with only its own seed file; keygen, presign, and
  signing run across real OS processes on localhost TCP.
* **Liveness**: rounds complete when the accepted sets are complete or
  the round timeout fires — then the PARTIAL set is returned, logged
  loudly, and the drivers fail closed ("incomplete message sets"). Same
  policy as M1; timeout values are a deployment concern (SPEC §13.1).

## What the §8.7 KI mode adds (key-independent pool over the wire)

The default presignatures are KEY-DEPENDENT: every long-term key needs
its own factory inventory. The optional §8.7 mode runs a **commodity
pool** over the same mesh:

* **Pool production** (`PartyNode::presign_ki`) is P1–P3 of the per-node
  presign driver verbatim — one triple session, the ⟦u⟧/⟦a⟧ joint
  sharings, the `v = a·u` opening, the nonce-point round with F5 blame —
  with **P4 omitted**: no key is involved at generation time, and the
  record `(id, R, r, [u], A[u])` is NOT key-equivalent (`t` pool shares
  reveal nothing about any key, §8.7 storage relaxation). It is still
  strictly single-use (§8.6(1)).
* **Online binding** (`PartyNode::sign_ki`) is TWO broadcast rounds: R1
  generates a FRESH triple over the wire and opens δ = ⟦u⟧−⟦α⟧,
  ε = ⟦x⟧−⟦β⟧ (β masks the long-term key — exactly the §8 P4 masking,
  moved online; every share point-checked, fail-fast blame); R2 computes
  ⟦z⟧ locally and broadcasts `s_j = m·u_j + r·z_j`, verified against
  `m·A[u] + r·A[z]`, low-`s`. The price vs the default mode: one extra
  online round and one extra triple per signature.
* **Storage**: pool records live in a per-node IN-MEMORY key-free pool
  (the core's `KiPool`, atomic consume) — `presign_ki_pooled` /
  `sign_ki_pooled` mirror the M3b `*_stored` wrappers. The durable M3b
  store is per-key by design (§8.6(4)) and does NOT hold pool records; a
  durable key-free pool file is follow-up (a restart simply loses unspent
  records — safe, not a nonce-reuse risk).
* One pool serves ANY key: `node/tests/party_ki.rs` proves two records
  of one pool signing under two DIFFERENT keys from two independent
  keygens, each signature verifying under its own X.

## What M3b adds (persistence + evidence)

A node run with `--data-dir DIR` (`spawn-demo --persist` gives each
child `DIR/node-i`) gets three artifacts, all in the core's canonical
`Encode`/`Decode` wire format (std only, no serde):

* **Durable presignature store (SPEC §8.6)** at `DIR/store`: one file
  per record (`<id>.presig`), a `key.bin` binding the directory to ONE
  long-term key (§8.6(4) — reopening under a different key is
  rejected). `insert` writes `<id>.tmp`, fsyncs the file, renames,
  fsyncs the directory. `consume(id)` reads the record, renames
  `<id>.presig` → `<id>.consumed`, fsyncs the directory, and only THEN
  returns the record: the tombstone is durable before the nonce can be
  used, so a killed-and-restarted node can never sign twice with the
  same presignature (§8.6(1) atomic consume across a crash). A crash
  between the rename and the return loses the record — the safe
  direction. Duplicate inserts (live, consumed, OR expired ids) are
  rejected with the core store's error semantics; stray `.tmp` files
  (crash mid-insert, never acknowledged) are deleted on open. Records
  are key-equivalent (§8.6(2)), so every file is H5-SEALED
  (ChaCha20-Poly1305 under the node's storage key, `0600`, legacy
  cleartext rejected — see H5 below) and carries a created-at timestamp
  for the pool manager's TTL expiry (`<id>.expired` tombstones, ids
  never re-issued). The presign driver persists every record it
  produces; the sign driver consumes from the store.
* **Transcript archive (SPEC §4.7)** at `DIR/archive/transcript.log`:
  every ACCEPTED signed envelope appended as `u32 BE length ‖ canonical
  SignedEnvelope bytes`, fsync'd per entry. Append-only, deduped per
  `(sid, phase, round, from, to)` slot in memory (at-least-once across
  a restart).
* **Blame tokens (SPEC §10.2, §A.4)** at `DIR/archive/*.tok` +
  `aborts.log`: on an identifiable abort, a token file is written where
  the fault leaves cryptographic evidence on the wire — F2 dealt-share
  faults (the dealer's signed P2P share envelope + its revealed
  commitment; only the ACCUSER holds the P2P envelope, so only it
  produces the token) and F6 sign-share faults (the signed share +
  message, `r`, `A[u]`, `A[z]`). Other classes (false accusations, bad
  DLEQ proofs, bad nonce points, bad opening shares, bad re-shares) are
  logged to `aborts.log` with `token: none` — documented in
  `src/store/persist.rs`. The `auditor` subcommand verifies a token OFFLINE
  against the public committee file (see below).

Durability model, honestly: this survives process kill and — on a
cooperating filesystem/OS — machine crash at exactly the fsync points
above. At-rest confidentiality reduces to the H5 storage key (wire it to
a KMS in real deployments — `src/store/seal.rs` is the interface, not a KMS);
it is not HSM-backed share storage, it does no wear leveling, and it
does not defend against a malicious host rolling back the directory.

## What M3c adds (optional mTLS)

Plain TCP (M1–M3b) authenticates every message with the §10.2 envelope
signatures, but nothing is encrypted in transit and there is no
transport-level peer authentication — anyone can open a TCP connection
to a node (its frames are dropped, but the endpoint is exposed). With
`--tls CERT KEY --pinned DIR` every mesh connection is wrapped in
**mutually-authenticated TLS 1.3** (rustls + ring, blocking streams —
still no async runtime):

* **Committee-pinned certificates, no PKI, no system roots.** Each
  party has a self-signed certificate (rcgen in the demo/tests); every
  node pins the EXACT certificate of every committee member
  (`--pinned DIR` reads the public `party-<id>.crt.pem` set). Outgoing
  connections accept only the pinned certificate of the party they
  connect to — the TLS peer identity IS the expected `PartyId`, so the
  transport-level and message-level (signed-envelope) identities are
  the same party. Incoming connections must present a pinned committee
  certificate; anything else (a stranger's cert, a plaintext peer) is
  rejected during the handshake with a loud log. There is NO fallback
  to plaintext once TLS is configured.
* **Threat-model delta.** TLS adds: confidentiality in transit (the
  protocol messages are commitments, masked openings and public
  points — leaks are not key-compromising per §10.5, but traffic
  analysis and metadata are) and transport-level peer authentication
  (only committee members can even complete a handshake). TLS does NOT
  add end-to-end accountability: that already comes from the §10.2
  per-message ECDSA signatures, which stay ON regardless — envelope
  verification is never weakened (defense in depth).
* **The wire format inside the TLS stream is unchanged** — the same
  length-prefixed canonical `Encode`/`Decode` frames of signed
  envelopes. TLS replaces only the confidentiality/peer-auth layer.
* **Cert guidance.** `setup --tls` / `spawn-demo --tls` generate
  per-party self-signed certs (`party-<id>.crt.pem` public,
  `party-<id>.key.pem` SECRET) — a development ceremony. Real
  deployments substitute their own PKI/certificate issuance and cert
  distribution (SPEC §13.1); the pinning verifiers in `src/net/tls.rs` are
  the reference. TLS is mandatory for any non-localhost deployment;
  plain TCP is for localhost dev and tests only.
* **MSRV note.** The pinned dependency tree (rustls 0.23.43 + ring,
  rcgen 0.14.7) builds with the workspace MSRV 1.75; the transitive
  pins in `node/Cargo.toml` (`time = "=0.3.36"`) and the lockfile
  (`base64ct 1.6.0`, `zeroize 1.8.2`) keep it that way — newer
  releases of those crates need edition2024 toolchains.

## What H2 adds (network resilience)

H2 hardens the mesh and the per-node drivers along three axes —
everything stays localhost reference scale, and every guard only
drops/delays: signature and commitment verification is never weakened.

* **Connection lifecycle.** Every message a node sends is journaled per
  session id BEFORE the write is attempted. When a send fails (or the
  outgoing connection is gone), one reconnect task per peer re-dials
  with capped exponential backoff + up to +100% jitter
  (`ReconnectConfig`: 100 ms initial, ×2, 5 s cap, unlimited attempts
  by default) and on success RE-SENDS the whole journal — the resync
  semantics are **"re-deliver every message of every in-flight session,
  in original order per session"**. Re-delivery is safe because the
  receive path is idempotent (the §4.7 first-echo rule and the acceptor
  dedup per `(sid, phase, round, from)`); messages for rounds that
  already completed are absorbed by the same dedup. Drivers retire a
  session's journal when it finishes (`retire_session`, prefix-matching
  the sub-session sids) — there is deliberately **no crash recovery of
  finished rounds**. The dial side reconnects; the accept side simply
  serves whatever arrives, and the mesh heals through the dial side
  (both directions of a pair reconnect independently).
  `Node::shutdown` (also on `Drop`, and `PartyNode::shutdown`) stops
  the accept loop (a dummy self-connection unblocks it), closes the
  outgoing connections (peer readers see EOF), signals every reader and
  reconnect task, and joins all tracked threads with a 5 s deadline —
  stragglers are logged and detached (std cannot kill threads). There
  is no SIGINT handler: std has no signal API, so a deployment wraps
  `shutdown()` in its own signal handling (adding a ctrlc-style
  dependency was deliberately skipped).
* **Timeouts.** Writes carry a 10 s `WRITE_TIMEOUT` (a dead peer fails
  the send — which triggers the reconnector — instead of parking the
  writer). The blocking rustls handshake runs under a 10 s
  `HANDSHAKE_TIMEOUT` via the simplest strategy compatible with
  blocking rustls: the socket gets short read/write timeouts and the
  `complete_io` loop treats `WouldBlock`/`TimedOut` as a tick until the
  deadline (see `src/net/tls.rs`). Reader threads poll with a 250 ms
  `READ_POLL` — NOT a liveness timeout, just shutdown responsiveness.
  Read stalls are bounded by the drivers' ROUND timeout: a peer that
  accepts but never sends fails its round loudly (partial accepted set,
  fail closed) instead of parking a thread forever.
* **DoS guards** (each increments exactly one `MeshMetrics` counter —
  a silent drop is a bug): a per-connection frame-rate window
  (`1024·n` frames/s, pre-verification, drops the connection —
  protocol-legitimate traffic is ≤ `n` frames per round per connection
  and rounds are sequential, so this is orders of magnitude of
  headroom), per-variant frame size bounds (`wire::FrameBound`, derived
  from the protocol's message sizes — points 33 B, scalars 32 B,
  commitment vectors bounded by `n` worst case — instead of one global
  4 MiB cap), a listener accept-rate window (`32·n` accepts/s), an mTLS
  handshake concurrency cap (`4n`), a bounded mailbox (65536, drops +
  counts when full), and acceptor-level caps (4096 distinct sids, 8
  equivocating candidates per broadcast slot). Unknown-sid/wrong-phase
  frames land in slots nothing queries and are bounded by the sid cap.
* **Concurrent sessions.** A dedicated collector thread drains the mesh
  mailbox into the acceptor and wakes round waiters via a condvar, so
  ANY NUMBER of protocol sessions (distinct sids) may be in flight:
  the acceptor demultiplexes by `(sid, phase, round)` and each driver
  waits only on its own session's slots. Keygen/triples/presign
  sessions overlap freely, and online signing (share exchange against
  an existing presignature) interleaves with the offline factory. One
  discipline: CONCURRENT sessions must not have prefix-related sids
  (journal retirement is a prefix match); the demo's
  `session_id`-derived sids are digests and never prefix-related. The
  proving ground is `node --factory N` / `spawn-demo --factory N`: the
  H5 pool manager keeps N presignatures in the node's durable store
  while the main thread signs 3 messages against consumed records.

## What H4 adds (robust continuation + expel-and-restart, §10.4 + §10.3)

H4 brings the core's §10.4 robust continuation and §10.3 restart policy
to the per-node wire drivers — **opt-in**: the default drivers stay
fail-fast (some deployments prefer loud aborts — a halt is a signal,
robustness masks it), exactly as the core keeps `presign` next to
`presign_robust`. A single cheater causes **blame + continued service**,
not an outage. Every verdict is a point-equality check on public data
over the echo-consistent accepted sets, so blame is deterministic and
identical at every honest node — the same discipline as the existing
drivers; the filter happens only AFTER a check fails, and every
interpolated share is still commitment-checked.

* **Robust online signing** was already the default (`PartyNode::sign`
  filters bad `s_j`, blames, interpolates from the remaining ≥ t valid
  shares, archives the F6 token per blamed party). H4 adds
  `sign_ki_robust` — the §8.7 KI sign with robust R1 openings (bad δ/ε
  shares filtered, senders expelled from R2's share set) and a robust
  R2 combine (the core's new `sign::combine_ki_robust`).
* **Robust presign** (`presign_robust`): every opening (δ/ε, v, δ′/ε′)
  goes through the core's `open_robust` — bad shares filtered and
  blamed, the opening interpolated from the first `t` valid shares; bad
  nonce points are filtered individually and `R` interpolates over the
  valid senders with the subset Lagrange weights (the core's
  `presign_robust` semantics). Blamed parties are expelled from
  subsequent rounds' share sets. Returns the record plus the blame
  list (identical everywhere).
* **Robust triples** (`triple_robust`): a T3 re-share fault no longer
  aborts — the honest majority **publicly reconstructs the cheater's
  committed re-sharing polynomial**. The sim sees every P2P share; a
  per-node driver does not, so H4 adds two broadcast rounds to the
  triple session: `ReshareRequests` (every node broadcasts the dealers
  whose re-share failed HERE, carrying the dealer's OWN signed
  `Reshare` envelope as self-authenticating evidence — every node
  re-verifies the signature against the registry and the failing
  `EvalCom`, so a fabricated or actually-verifying request blames the
  REQUESTER instead of the dealer) and `ReshareSupply` (every node
  broadcasts the re-share it received from each dealer in the verified
  reconstruction set; the first `t` supplies that verify against the
  dealer's public commitment interpolate the committed polynomial, and
  each node recomputes its own contaminated share). Fewer than `t`
  valid supplies aborts blaming the dealer (the committed polynomial is
  unrecoverable — same rule as the core's `generate_robust`). **Round
  cost: +1 broadcast round per triple session in the honest case (the
  request round must complete everywhere for the verdict to be
  consistent), +2 on a re-share fault.** The blamed dealer's commitment
  still enters `A[γ]` — its DLEQ proof already bound `g_j(0) = α_j·β_j`.
* **Expel-and-restart** (`keygen_with_restart`,
  `presign_with_restart`, CLI `node --restart` / `spawn-demo
  --restart`): faults that cannot continue (dealing-phase F1/F2/F3)
  abort the attempt; every node then deterministically computes the
  SAME surviving committee (the core's `policy::restart_committee` over
  the current ids minus the blamed), poisons the sid (§10.3(2)) — and
  the presignature id per restarted attempt — and re-runs over the
  survivors with **original ids preserved** (their key shares stay
  valid; unlike the sim's keygen restart, the wire restart never
  renumbers — the transport registry pins the ids). The presign wrapper
  COMPOSES the two layers exactly like the sim's
  `run_presign_with_restart`: robust continuation in-attempt (id NOT
  poisoned, blame accumulated), restart only for dealing-phase aborts.
  Retries are inherently bounded (every restart expels ≥ 1 party) and
  the policy REFUSES once the remainder would drop below `n′ < 2t−1` —
  `t` is never silently lowered (zero-slack committees like 2-of-3
  refuse every restart; deploy with slack, e.g. 3-of-6, to absorb
  ejections — SPEC §10.3(1)). Signing over the post-restart committee
  uses `sign_over` / `sign_stored_over` (rounds wait only for the
  survivors).

## What H5 adds (key-material protection + pool management, §8.6 + §13.3)

H5 is the node-side hardening of how SECRETS live — in memory, on disk,
and over time. It changes no protocol message and weakens no check.

* **Page-locked secrets in memory (`src/store/locked.rs`).** Long-lived secret
  material at the node boundary — key shares, the transport signing key,
  pooled presignature records — is wrapped in `mlock`'d buffers so the
  kernel cannot swap it to disk while it lives (the core's zeroize-on-drop
  erasure on free is unchanged and applies underneath). Policy:
  **FAIL-OPEN WITH A LOUD WARNING** — when the OS refuses wiring
  (`RLIMIT_MEMLOCK` too small, no `CAP_IPC_LOCK`), the node logs a WARNING
  and continues unlocked; failing closed would make every default dev
  machine unable to run a node at all. This is the ONLY fail-open path in
  H5; deployments that require the guarantee treat the warning as fatal
  at the ops level.
* **AEAD at rest (`src/store/seal.rs`).** Every secret file — presignature
  store records (key-equivalent, §8.6(2)), seed/identity files — is the
  canonical `Encode` bytes inside a ChaCha20-Poly1305 envelope under a
  per-node storage key (derived `SHA-256(tag ‖ secret)`, held
  page-locked, erased on drop). The sealed format is versioned and
  purpose-bound (a renamed or repurposed file fails authentication);
  legacy CLEARTEXT files are rejected, fail closed, no silent downgrade.
  Key resolution, in order: `OHM_STORAGE_KEY` (64 hex chars in the
  environment), `OHM_STORAGE_KEY_FILE` (path of a hex key file), or a
  generated `storage.key` (`0600`) beside the secret material — the DEV
  default, loudly warned about. **This is the KMS/HSM integration
  interface, not a KMS**: real deployments set the env var from their
  secrets agent; key custody, rotation, and rollback defense stay
  deployment concerns.
* **File permissions.** Every secret file the node writes is `0600`
  (enforced even when the file pre-existed looser); readers warn loudly
  on startup when an existing secret file is group/world-accessible
  (fail-open for availability, like `mlock` — the contents stay
  authenticated regardless).
* **The pool manager (`src/party/pool.rs`, SPEC §8.6).** A per-node
  maintenance layer over the durable store and the H2 concurrent-session
  machinery:
  - *Target level*: keeps `target` live records in the store, one
    production session per tick (the `--factory N` demo wires it to
    `PartyNode::presign` over the wire). Signing drains via the store's
    atomic consume — unchanged; the manager only ADDS, never consumes
    (**single-writer invariant: exactly one manager per node**).
  - *Expiry (§8.6(3))*: records carry a created-at timestamp (v2 sealed
    payload, stamped from the manager's injectable clock; legacy v1
    sealed records fall back to the file mtime). With `--pool-ttl SECS`
    (> 0), an aged record is ERASED — the empty `<id>.expired` tombstone
    is fsync'd FIRST (the id is durably burned, never re-issuable — the
    same discipline as the consume tombstone), then the sealed file is
    removed — and never served to sign. `0` = never expire (default).
    Expiry is a LOCAL per-node policy: nothing synchronizes the nodes'
    clocks, so a sign racing expiry fails loudly (unknown id) rather
    than serving a stale record.
  - *Crash/restart*: ids are re-seeded from the persisted
    `max(live ∪ consumed ∪ expired) + 1`, so an id is never re-issued;
    a crash mid-production loses at most the never-persisted in-flight
    session (safe direction), and the retried session's insert dedups
    against the persisted record — a restart never over-produces.
  - *Visibility*: the `--factory N` demo prints produced/stored/expired
    counts per node (`FACTORY target=… produced=… stored=… expired=…
    signed=…`).

## What M3b/M3c/H2/H4/H5 is still NOT

* **Not everything is robust.** TLS handshake faults, connection-level
  misbehavior, and crash-stop are NOT covered by H4's continuation (an
  expelled party's MESH is assumed to keep echoing — alive process,
  dead driver; a crashed process is the separate H2 crash-recovery
  gap). The §8.7 KI arc composes only partially: `sign_ki_robust` is
  robust online, but `presign_ki` pool production stays fail-fast and
  there is no KI restart wrapper. Dealing phases are fail-fast in ALL
  drivers — recovery there is exactly the §10.3 restart, never
  in-attempt continuation. The default drivers remain fail-fast by
  design (see above).
* **No crash recovery of finished rounds**, no reconnection of incoming
  connections (the dial side heals the mesh), no SIGINT handler (std
  has no signal API — a deployment wraps `Node::shutdown`), no
  reconnection of a node that fully RESTARTS (a restarted node re-binds
  and the peers' reconnectors re-dial it only if it keeps its address —
  rejoining a committee after a full restart is out of scope).
* **H5 is an interface, not a vault.** The storage-key resolution is
  where a KMS/HSM plugs in — no KMS is implemented; key custody and
  rotation are ops. `mlock` is fail-open (a warning, not a guarantee).
  There is NO rollback defense (a malicious host restoring deleted
  sealed files or replaying an old store directory), no wear leveling
  (filesystem block reuse is not guaranteed — "secure erase" means
  removed from service), and side channels (timing, cache, swap beyond
  the locked pages) remain out of scope. Pool expiry skew across nodes
  is a documented liveness trade-off, not a safety issue.
* **Not audited, not production anything.** localhost-scale demo and
  test scaffolding only.

## Committee ceremony (H3 — the standard setup path)

The one-process ceremony (`setup`, `spawn-demo`, `src/setup/seed.rs`) generates
**every party's transport keypair in a single process** and distributes
secret files: one machine momentarily holds the whole committee's
transport secrets. That is **DEMO-ONLY** — fine for demos and tests,
unacceptable for a real committee. The standard setup path is the
**distributed ceremony** (`src/setup/ceremony.rs`), where no secret ever
leaves its party's machine:

```sh
# 1. Each party, on its OWN machine (party 1 shown; parties 2, 3 alike):
cargo run -p ohm-ecdsa-node -- init --id 1 --dir ./party1 --addr 10.0.0.1:7700 --tls
#    writes ./party1/party-1.identity (SECRET), ./party1/party-1.key.pem (SECRET, with --tls),
#    ./party1/party-1.crt.pem and ./party1/party-1.pub (PUBLIC); prints:
#      FINGERPRINT <hex>

# 2. Out of band: exchange the .pub bundles over an AUTHENTICATED channel
#    (signed email, verified read-out …) and confirm every party's
#    FINGERPRINT on a second channel (voice, video). See the trust model
#    below — this step is ops, not code.

# 3. Assembly — PUBLIC data only, safe to run anywhere (even untrusted):
cargo run -p ohm-ecdsa-node -- assemble --committee ./committee \
    --inputs party-1.pub,party-2.pub,party-3.pub
#    validates the bundles (ids exactly 1..=n, uniform TLS posture,
#    parseable keys/certs), writes ./committee/committee.hex (the exact
#    format every existing consumer reads) plus the pinned cert set
#    (party-<id>.crt.pem) with TLS, prints ALL fingerprints for
#    cross-checking and a suggested --peers line from the addr hints.

# 4. Each party runs its node with its own dir + the shared committee:
cargo run -p ohm-ecdsa-node -- node --identity ./party1/party-1.identity \
    --committee ./committee/committee.hex --bind 10.0.0.1:7700 \
    --peers 1@10.0.0.1:7700,2@10.0.0.2:7700,3@10.0.0.3:7700 \
    --tls ./party1/party-1.crt.pem ./party1/party-1.key.pem --pinned ./committee
```

Properties and trust model, honestly:

* **Self-sovereign keys.** `init` uses an OS CSPRNG on the party's own
  machine; the transport secret key (and TLS key) never touch another
  machine, a file share, or this repo's demo ceremony.
* **Assembly is public and re-runnable.** `assemble` reads only `.pub`
  bundles; every party can re-run it and compare `committee.hex` byte
  for byte. A corrupt assembly is a liveness issue, not a confidentiality
  one.
* **The out-of-band channel is the trust root — and it is OPS, not
  code.** A swapped `.pub` bundle means the committee bootstraps with an
  attacker's key in the registry. No code can authenticate that channel;
  the per-party **fingerprint** (hex of `H(tag ‖ id ‖ transport key ‖
  cert)`, truncated) exists so the committee confirms every bundle over
  a second channel BEFORE assembling. `init` prints it; `assemble`
  prints all of them.
* **Fail-closed backstops.** Even if a tampered bundle survives the
  out-of-band check, a node refuses to boot when its own transport key
  does not match its registry entry, or when its own certificate does
  not match the pinned set (`node/tests/process_demo.rs` exercises
  both).
* **No ceremony key.** An assembled committee file carries the identity
  point as `x` (an explicit marker): there is no ceremony key share, so
  the M2 `--seeded` fallback is impossible with `--identity` — the full
  arc (fresh keygen → presign → sign under the nodes' own key) is the
  only mode, which is what a real committee wants anyway.
* The `setup`/`spawn-demo` one-process ceremony stays for demos and
  tests and now says DEMO-ONLY in its usage text and output.

## Demo

```sh
cargo run -p ohm-ecdsa-node -- spawn-demo           # 3 child processes: keygen → presign → sign
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-sign-share
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-product-proof
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-reshare:1
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-nonce-point
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-open-share
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-deal:1
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 3 --cheat false-accuse:1
cargo run -p ohm-ecdsa-node -- spawn-demo --seeded  # M2 fallback: sign with ceremony presigs
cargo run -p ohm-ecdsa-node -- spawn-demo --delay-ms 50   # simulated WAN links
cargo run -p ohm-ecdsa-node -- spawn-demo --persist # M3b: durable stores + transcript/blame archive
cargo run -p ohm-ecdsa-node -- spawn-demo --tls     # M3c: the full arc over mTLS (rcgen certs, committee-pinned)
cargo run -p ohm-ecdsa-node -- spawn-demo --ki      # §8.7: keygen → KEY-FREE pool record → 2-round KI sign
cargo run -p ohm-ecdsa-node -- spawn-demo --factory 2  # H2/H5: pool manager (durable store) + 3 concurrent signatures
cargo run -p ohm-ecdsa-node -- spawn-demo --factory 2 --pool-ttl 600   # + §8.6(3) TTL expiry (erased, never served)
cargo run -p ohm-ecdsa-node -- spawn-demo --restart    # H4: §10.4 robust + §10.3 expel-and-restart drivers
cargo run -p ohm-ecdsa-node -- spawn-demo --restart --cheat-node 2 --cheat bad-open-share
#   → the cheater is named by every process AND the presign + signature still complete
cargo run -p ohm-ecdsa-node -- spawn-demo --restart --cheat-node 2 --cheat bad-product-proof
#   → dealing-phase fault: restart REFUSED (2-of-3 is zero-slack) — consistent abort, t never lowered
cargo run -p ohm-ecdsa-node -- spawn-demo --tls --persist --cheat-node 2 --cheat bad-sign-share
cargo run -p ohm-ecdsa-node -- spawn-demo --persist --cheat-node 2 --cheat bad-deal:1 --dir /tmp/ohm-demo
cargo run -p ohm-ecdsa-node -- auditor /tmp/ohm-demo/node-1/archive/blame-keygen-2.tok \
    /tmp/ohm-demo/committee.hex                 # offline §A.4 verification (exit 0 = VALID)
cargo run -p ohm-ecdsa-node -- m1-demo              # the M1 orchestrator demo
```

`spawn-demo` writes a ceremony committee to a temp dir (`--dir` to
override; in the default mode only the transport keys and the public
registry are used — the arc runs under the fresh key), launches the
three child `node` processes, and prints per-process logs with
per-phase timings, the joint key `X` (all three agree), the
self-produced presignature, the final signature (verified under the
FRESH X), and any blame. With `bad-sign-share`, the other two processes
both name the cheater and all three still deliver the signature; with
`bad-deal`/`false-accuse`, keygen aborts consistently naming the cheater
(presign/sign skipped); with `bad-product-proof`/`bad-reshare`, the
triple factory aborts consistently (`BLAME triples K`); with
`bad-nonce-point`/`bad-open-share`, presign aborts consistently
(`BLAME presign K`). With `--persist`, each child runs with a per-node
`--data-dir` (durable presignature store + transcript/blame archive,
M3b) — a cheater run leaves a `blame-*.tok` file in the accuser's
archive, which the `auditor` subcommand verifies offline.

To run parties by hand (separate terminals or machines — TLS mandatory
off localhost), use the distributed ceremony in the previous section.
The one-process demo path stays for local experiments (**DEMO-ONLY** —
one machine holds all keys):

```sh
cargo run -p ohm-ecdsa-node -- setup --dir /tmp/ohm-demo --tls   # DEMO-ONLY: seeds + per-party certs
cargo run -p ohm-ecdsa-node -- node --seed /tmp/ohm-demo/party-1.seed \
    --committee /tmp/ohm-demo/committee.hex --bind 127.0.0.1:7700 \
    --peers 1@127.0.0.1:7700,2@127.0.0.1:7701,3@127.0.0.1:7702 \
    --tls /tmp/ohm-demo/party-1.crt.pem /tmp/ohm-demo/party-1.key.pem \
    --pinned /tmp/ohm-demo
# ... party 2 on :7701, party 3 on :7702 (each with its own cert/key)
```

## Benchmark

```sh
cargo run --release -p ohm-ecdsa-node --example mesh_perf
# [--iters K] [--delays 0,50,100]
```

Wall-clock keygen and online-sign times over the real mesh for 2-of-3
and 3-of-5, on localhost and with a configurable per-link artificial
send delay (send-side delay wrapper in the mesh) simulating a WAN;
reports medians in a small table. Presignatures are ceremony-seeded (the
documented M2 shortcut).

## Tests

```sh
cargo test -p ohm-ecdsa-node
```

* `node/tests/mesh_keygen.rs` (M1, 3 tests): orchestrated keygen over
  `MeshTransport`, a cheating dealer blamed with a verifying
  `BlameToken`, forged/unknown-sender/malformed frames dropped.
* `node/tests/echo_consistency.rs` (§4.7, 2 tests, thread-level):
  the reviewer attack on the superseded majority-echo rule — at 3-of-5
  a corrupt sender signs two conflicting values for one broadcast slot
  and a colluding corrupt echoer echoes each to a different honest
  node; every honest node outputs ⊥ for the sender's slot (accepted
  sets identical, honest values still accepted), holds the two
  conflicting sender-signed envelopes as F8 evidence, and the
  constructed `BlameEvidence::Equivocation` token audits VALID offline;
  plus an echo of a value the sender never signed is dropped + counted
  while the honest keygen completes.
* `node/tests/party_mesh.rs` (M2, 6 tests, thread-level with strict
  per-node key separation): per-node keygen reconstructs the joint key
  (2-of-3 and 3-of-5); a cheating dealer is named by every node via the
  wire complaint/defense rounds; a false accuser is named by every node;
  per-node signing produces a valid low-`s` signature; a wrong signature
  share is blamed by every node and the signature is still delivered.
* `node/tests/party_offline.rs` (M3a, 8 tests, thread-level with strict
  per-node key separation): per-node triples are multiplicative at the
  public commitments (2-of-3 and 3-of-5); a bad DLEQ product proof, a
  bad re-shared share (via the wire §6.1 rounds), and a false accusation
  are each named consistently by every node; a bad nonce point and a bad
  opening share are named in presign; the full arc keygen → presign →
  sign signs under the key the nodes' own keygen produced (valid low-`s`
  signature, all nodes agree).
* `node/tests/party_ki.rs` (§8.7, 3 tests, thread-level with strict
  per-node key separation): the KI full arc signs under the nodes' own
  key (with pool single-use enforced — a consumed id cannot sign twice);
  ONE key-free pool signs for TWO different keys from two independent
  keygens (each signature verifies under its own X and not the other);
  a bad R1 opening share is blamed by every node in `Phase::Sign`.
* `node/tests/party_robust.rs` (H4, 10 tests, thread-level with strict
  per-node key separation): robust sign — a bad `s_j` is filtered,
  blamed `[2]` at every node, the SAME valid low-`s` signature is
  delivered everywhere, and the archived F6 token verifies offline at
  every node; robust presign — a bad `v` opening share and a bad nonce
  point each continue with consistent blame and records that still sign
  and verify; robust triples — a bad re-share to one victim is publicly
  reconstructed via the request/supply rounds (the victim's recovered
  c-share verifies against `A[γ]`, `c == a·b` per the openings, dealer
  blamed consistently) and a fabricated reconstruction request blames
  the requester; §10.3 restart — a 3-of-6 keygen dealing cheater
  restarts over the 5 survivors' ORIGINAL ids and a 3-of-6 presign
  dealing cheater restarts with the id poisoned (`first_id + 1`),
  completes, and signs over the final committee; zero-slack refusal —
  a 2-of-3 dealing cheater fails the session with the policy refusal
  (no silent `t`-lowering); robust KI sign — bad R2 signature share and
  bad R1 opening share each blamed with the KI signature delivered.
* `node/tests/process_demo.rs` (M2/M3a/M3b/M3c/§8.7/H2/H3/H4, 19 tests, REAL
  CHILD PROCESSES): 16 via `spawn-demo` — honest full arc across 3
  processes; the
  `--ki` KI arc (keygen → KEY-FREE pool record → 2-round KI sign, all
  processes agreeing on X and a verifying signature); a
  sign-share cheater named by the other two processes with the signature
  still delivered; a DKG cheater and a false accuser each named by all
  three processes (full arc and `--seeded` fallback); a bad DLEQ proof
  and a bad re-share named as `BLAME triples` by every process; a bad
  nonce point and a bad opening share named as `BLAME presign` by every
  process; the `--persist` full arc leaving fsync'd consume tombstones
  and decodable transcripts; a `bad-deal` token file verified by the
  `auditor` subcommand (exit 0, `VERDICT: VALID`) and a tampered copy
  rejected; the `--tls` full arc over mTLS (M3c); the `--factory 2` H2
  demo (a background presignature factory per process overlapping 3
  online signatures — factory progress asserted, every signature
  verifying under the fresh X); the `--restart` H4 demos — a bad opening
  share named by every process while the presign and signature still
  COMPLETE (blame + continued service), and a dealing-phase cheat
  refused at zero slack (consistent abort, `t` never lowered); plus 3 H3
  distributed-ceremony tests —
  three separate `init` runs + a public `assemble` booting a full-arc
  committee from per-party identity files (agreement + a verifying
  signature), `assemble` rejecting a duplicate party id, and tampered
  `.pub` bundles (swapped certificate, swapped transport key) failing
  the node closed at startup. These tests are
  serialized within their binary (a static `Mutex`, documented in the
  file) and run under a 300 s watchdog: each spawns 3 child processes
  whose localhost rounds starve when the whole workspace suite runs in
  parallel — the previous per-test parallelism + 180 s watchdog was
  flaky under load (load, not a protocol hang).
* `node/tests/persist.rs` (M3b, 9 tests): the durable store survives
  drop/reopen, a consumed id stays consumed across a simulated crash,
  duplicate inserts are rejected (live and consumed ids, on reopen),
  wrong-key reopen is rejected, stray `.tmp` files are dropped; the
  transcript archive dedups and decodes; the F2 dealt-share and F6
  sign-share tokens verify offline and reject tampering and a wrong
  registry; crash-recovery integration — a node signs (consuming the
  record), "restarts" (a fresh store instance on the same directory),
  and a second sign with the same id fails.
* `node/tests/mesh_tls.rs` (M3c, 3 tests, thread-level) plus 3 unit
  tests in `src/net/tls.rs` and 1 process-level test in
  `node/tests/process_demo.rs`: the full arc keygen → presign → sign
  over mTLS (thread-level AND across child processes via
  `spawn-demo --tls`); an unpinned/rogue peer cert is rejected in both
  handshake directions and every node fails closed (no plaintext
  fallback, keygen cannot complete); a plaintext peer poking a TLS
  listener is dropped and the node still completes keygen with its
  real TLS peers; the pinning verifiers accept exactly the pinned cert
  and reject any other (unit level).
* `node/tests/resilience.rs` (H2, 6 tests, thread-level): reconnection
  after a dropped outgoing connection (journal re-sync re-delivers the
  in-flight keygen, `reconnects >= 1`); a silent peer failing its round
  loudly on the round timeout with the honest drivers failing closed
  and no parked threads (clean shutdown asserted); clean shutdown idle
  and mid-session (all threads join, no hangs); the listener
  accept-rate window counting a raw poke flood while the honest keygen
  completes; garbage frames (absurd length prefix, undecodable
  payloads) dropped while the honest keygen completes; and MULTIPLE
  concurrent sessions — a background factory keeping 2 presignatures
  in the pool per node while signing 3 messages, signatures verifying
  under the fresh X, factory progress asserted at every node.
* `node/tests/pool.rs` (H5, 5 tests, deterministic — sim-produced
  records, injectable clock, no mesh): the pool manager refills to the
  target under drain (consumed records are replaced with FRESH ids,
  production pauses at target); TTL expiry erases aged records (the
  sealed file removed, the `<id>.expired` tombstone fsync'd, the id
  burned — consume rejected, re-insert rejected, double-expire a
  no-op) while fresh refills survive; ttl 0 never expires; a simulated
  restart counts persisted records toward the target and resumes id
  allocation above the persisted max; and a legacy v1 SEALED record
  (pre-TTL format) is accepted with the file-mtime fallback, stays
  consumable, and expires under a TTL like any other record.

## Layout

`src/` is organized into four layers — `net/` (transport substrate),
`party/` (per-node protocol drivers + pool manager), `setup/` (committee
ceremonies), `store/` (durability + key protection) — with `lib.rs`
flat-re-exporting every module, so all public paths
(`ohm_ecdsa_node::mesh`, `ohm_ecdsa_node::party::PartyNode`, …) are
unchanged by the layering.

| Module | Role |
|---|---|
| `src/net/wire.rs` | `WireMessage<M>` (original / signed echo), canonical framing, signature validation — generic over the payload; H2 `FrameBound` (per-variant frame size bounds derived from protocol message sizes) |
| `src/net/mesh.rs` | `Node<M>`: listener + full-mesh connections + reader threads, first-echo rule, verified-only bounded mailbox, self-echo loopback (M2 per-node acceptor), config-driven send delay (benchmarks), optional M3c mTLS wrapping (`bind_tls`); H2: `ReconnectConfig` + per-session send journal with reconnect re-sync, `Node::shutdown` (join-with-deadline, also on `Drop`), write/handshake timeouts, per-connection rate window, listener accept-rate window, mTLS handshake concurrency cap, `MeshMetrics` drop counters |
| `src/net/tls.rs` | M3c: `CommitteeTls` (own cert/key + the pinned committee cert set), committee-pinned TLS 1.3 client/server configs and blocking handshakes (rustls + ring) under the H2 `HANDSHAKE_TIMEOUT` (socket-timeout strategy), rcgen cert generation for tests/demos, the PEM file layout (`party-<id>.crt.pem` / `.key.pem`) |
| `src/net/transport.rs` | `MeshTransport` (M1): echo-broadcast acceptor + the core `Transport` trait impl over `DkgMessage` (+ the M1 family's H2 `FrameBound` impl) |
| `src/party/party.rs` | `PartyNode` + `NodePayload` (M2/M3a): per-node keygen driver with §6.1 complaints/defenses on the wire (factored as `joint_vss` + the wire complaint subprotocol), per-node §7.2 triple and §8 presign drivers (the M3a offline factory), per-node §9/§10.4 sign driver, per-node §8.7 KI drivers (`presign_ki` — P1–P3 verbatim, P4 omitted — and the 2-round `sign_ki`, plus the in-memory key-free pool wrappers `presign_ki_pooled` / `sign_ki_pooled`), per-node echo-broadcast acceptor, `Cheat` fault injection; M3b store/archive wiring (`presign_stored`, `sign_stored`, `store_offer`); M3c `bind_with_tls`; H2: the collector thread + condvar acceptor (MULTIPLE concurrent sessions demultiplexed by sid), acceptor-level caps (distinct-sid, per-slot equivocation), per-session journal retirement, `PartyNode::shutdown`, `metrics`/`set_reconnect`/`debug_drop_outgoing`; H4: the OPT-IN §10.4-robust drivers (`presign_robust`, `triple_robust` with the `ReshareRequests`/`ReshareSupply` reconstruction rounds, `sign_ki_robust`) and the §10.3 expel-and-restart wrappers (`keygen_with_restart`, `presign_with_restart` + `sign_over`/`sign_stored_over` over the surviving committee, original ids, poisoned sid/id, zero-slack refusal) — every driver is committee-aware (`*_over` id sets) so restart sessions run over survivors |
| `src/party/pool.rs` | H5 (§8.6): `PoolManager` — the per-node pool maintenance layer over the durable store: refill-to-target (single writer; signing only consumes), per-record TTL expiry with secure erase (§8.6(3), injectable clock), crash/restart discipline (ids re-seeded from the persisted max, insert dedup — never over-produces), `PoolConfig`/`PoolStats`/`PoolCounters` |
| `src/setup/seed.rs` | the DEMO-ONLY one-process ceremony + seed/committee files (the `--seeded` fallback for presignature distribution; transport keys come from the seed files in that mode) |
| `src/setup/ceremony.rs` | H3: the DISTRIBUTED committee ceremony — the standard setup path: per-party `init` (own keypair + M3c cert on its own machine; SECRET `party-<id>.identity`, PUBLIC `party-<id>.pub` with id/verifying key/addr hint/cert), short hex `fingerprint` for out-of-band verification, and the PUBLIC `assemble` (validates bundles — ids exactly `1..=n`, uniform TLS posture — and writes the unchanged `committee.hex` format + the pinned cert set; committee `x` is the identity point: no ceremony key) |
| `src/store/persist.rs` | M3b: `DiskPresigStore` (§8.6 durable single-use store, write-tmp-rename + fsync, consume tombstone fsync'd before the record is handed out; H5: sealed records with the versioned v2 payload — created-at stamp for the pool TTL — `<id>.expired` tombstones burning expired ids forever, legacy v1 sealed records accepted with the mtime fallback, legacy cleartext rejected), `Archive` (§4.7 accepted-envelope transcript + `aborts.log`), `BlameEvidence` token files (F2 dealt-share, F6 sign-share; other classes `token: none`), `audit_token` offline verifier (§A.4) |
| `src/store/locked.rs` | H5 (§13.3): `LockedSecret<T>` / `LockedBytes` — page-locked (`mlock`) wrappers for long-lived secrets at the node boundary (key shares, transport key, pooled records, the storage key); FAIL-OPEN with a loud WARNING when the OS refuses wiring (the only fail-open path in H5) |
| `src/store/seal.rs` | H5 (§8.6(2)): `StorageKey` — ChaCha20-Poly1305 AEAD at rest for every secret file (versioned + purpose-bound sealed format, legacy cleartext rejected fail-closed), storage-secret resolution (`OHM_STORAGE_KEY` / `OHM_STORAGE_KEY_FILE` / generated `0600` dev key — the KMS interface, not a KMS), `0600` enforcement + looseness warnings |
| `src/lib.rs` | crate docs (M1–M3c, §8.7, H2–H5) + the four layer modules with flat re-exports preserving every pre-layering public path |
| `src/main.rs` | `node` / `setup` (DEMO-ONLY) / `init` / `assemble` / `spawn-demo` (DEMO-ONLY) / `auditor` / `m1-demo` subcommands (`--tls` on `setup`/`init`/`node`/`spawn-demo` for M3c, `--ki` on `node`/`spawn-demo` for the §8.7 KI arc, `--factory N` + `--pool-ttl SECS` on `node`/`spawn-demo` for the H2/H5 concurrent-sessions pool-manager demo, `--restart` on `node`/`spawn-demo` for the H4 §10.4-robust + §10.3-restart arc, `--identity` on `node` for the H3 distributed ceremony; a node fails closed at startup when its own key/cert does not match the committee registry/pins) |
| `examples/mesh_perf.rs` | the latency benchmark described above |
