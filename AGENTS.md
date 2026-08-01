# AGENTS.md — OHM-ECDSA

Guidance for AI coding agents working in this repository. Assumes no prior
knowledge of the project.

## Project overview

`ohm-ecdsa` is a Rust **library crate** (not a binary) implementing
OHM-ECDSA: an open, honest-majority threshold ECDSA protocol over secp256k1.
It is a **reference implementation of an unreviewed protocol draft** —
unaudited research code, not for securing real assets (see `SPEC.md` §13).

The repo is a **two-crate workspace**: the core library at the repo root
(`ohm-ecdsa`, dependency-pure, no networking) and the transport
companion in `node/` (`ohm-ecdsa-node`, which owns all networking — see
`node/README.md`; M1 orchestrator driver, M2 per-party node drivers,
M3a per-node offline factory — triples + presign over the wire, so the
demo signs under the key its own keygen produced, M3b persistence —
durable presignature stores, transcript + blame-token archiving, offline
auditor, A4 store rollback DETECTION — chained store journal + sign-
transcript cross-check, detect-and-refuse at startup (§13.3; prevention
still needs external state), M3c optional committee-pinned mTLS via
rustls/rcgen, §8.7 KI
mode over the wire — per-node key-free pool production (`presign_ki`,
P1–P3 verbatim, P4 omitted) and the 2-round online KI sign (`sign_ki`),
with an in-memory key-free pool per node, H2 network resilience —
reconnection with backoff + journal re-sync, clean shutdown, IO
timeouts, DoS guards with `MeshMetrics` counters, multiple concurrent
sessions demultiplexed by sid with the `--factory` demo).
H4 robust continuation + expel-and-restart over the wire
(`node/src/party/party.rs`, SPEC §10.4 + §10.3, OPT-IN — the default drivers
stay fail-fast): §10.4-robust drivers (`presign_robust` — openings
filtered-and-continued via the core's `open_robust` with consistent
blame; `triple_robust` — T3 re-share faults publicly reconstruct the
cheater's committed re-sharing polynomial via two added broadcast
rounds, `ReshareRequests` carrying the dealer's own signed envelope as
self-authenticating evidence + `ReshareSupply`; `sign_ki_robust`) and
the §10.3 expel-and-restart wrappers (`keygen_with_restart` /
`presign_with_restart` — the core's `policy::restart_committee`
computed deterministically at every node, poisoned sid/id per §10.3(2),
survivors' ORIGINAL ids preserved, zero-slack refusal — `t` never
lowered; `sign_over` / `sign_stored_over` sign over the post-restart
committee; `node --restart` / `spawn-demo --restart`).
H3 distributed committee ceremony (`node/src/setup/ceremony.rs`) is the
standard setup path: per-party `init` on each party's OWN machine
(own transport keypair + M3c cert; SECRET `party-<id>.identity`,
PUBLIC `party-<id>.pub`), out-of-band bundle exchange with hex
fingerprints, and a PUBLIC `assemble` writing the unchanged
`committee.hex` format (committee `x` = identity point: no ceremony
key, `--seeded` impossible with `--identity`); nodes fail closed at
startup when their own key/cert does not match the registry/pins.
The one-process `setup`/`spawn-demo` ceremony is DEMO-ONLY.
A6 operability (`node/src/party/metrics.rs`): a pull-based metrics dump —
`node --metrics-file PATH` appends a greppable counter block (`#` header
+ `name value` lines: mesh frames/drops/reconnects/sessions, F8
equivocations, pool + store counts, A4 integrity warnings) every 15 s
and once at shutdown; no HTTP endpoint by design. A7 soak testing
(`node/src/main.rs`, `run_soak_node` / `run_soak_demo`):
`spawn-demo --soak SECS [--factory N] [--pool-ttl S] [--persist]
[--metrics] [--fault-rate P] [--restart-every S] [--seed S]` runs the
committee CONTINUOUSLY — the factory keeps each node's pool at target
on the fault-tolerant `PoolManager::tick_tolerant` loop (a failed
production session's id is DURABLY burned via
`DiskPresigStore::burn` — never re-issued, so a retried session never
reuses a sid the wire may still hold), the demo parent drives jittered
(~2–5 s) sign ticks of a deterministic message sequence (every
signature verified at children AND parent), arms ONE per-session cheat
at a random node with probability P per tick, and (with `--persist`)
cycles one child through kill/restart/rejoin — the restarted node
reloads its SEALED key share (`persist::save_keyshare` /
`load_keyshare`, `<data-dir>/keyshare.sealed`, H5 AEAD at rest — same
X, no re-keygen) and a MESH-CHECK echo-quorum probe proves the
survivors' write-triggered H2 reconnect healed before signs resume.
Exit 0 iff signs_failed == 0 AND no unarmed party was ever blamed AND
the end-of-soak A4 store audit passes at every node AND every child
shut down cleanly; `--soak 0` runs until killed (children take the H2
clean-shutdown path when the dying parent closes their stdin).
Deterministic from `--seed`.
The operator runbook is `docs/runbook.md`.

Protocol properties:

- Honest majority: `n >= 2t - 1`, tolerates `t - 1` malicious parties
  (`Params::new` enforces this in `src/lib.rs`).
- One-round online signing; identifiable abort at every broadcast (a wrong
  share is caught by point-equality against public Feldman commitments and
  the sender is blamed via `Error::Abort { abort: IdentifiableAbort }`).
- Built only from classical components: Shamir sharing, Feldman VSS,
  commit-then-reveal Pedersen DKG, Beaver triples, Chaum–Pedersen DLEQ
  proofs. No Paillier, no OT, no range proofs, no class groups.

`SPEC.md` is the authoritative protocol specification; `README.md` has
status and usage. Module doc comments cite the relevant SPEC sections —
keep those citations accurate when changing code.

## Technology stack

- Rust, edition 2021, MSRV 1.75 (`Cargo.toml`).
- Core crate dependencies: `k256` (0.13, features `ecdsa` + `sha256`) for
  all curve / ECDSA arithmetic, `sha2`, `thiserror`, `rand` (0.8),
  `zeroize`. No serde, no async, no networking **in the core crate** — the
  "no networking" rule is core-only; the `node/` companion crate owns all
  networking (`std::net` blocking threads, no external runtime). Node
  crate dependencies: the path dependency on the core plus `k256` and
  `rand` for keys/RNGs, and — since M3c — `rustls` (0.23, ring provider,
  TLS 1.3 only) + `rcgen` (test/dev self-signed certs) +
  `rustls-pki-types` for the OPTIONAL mTLS layer (`node/src/net/tls.rs`);
  `time` is pinned (`=0.3.36`) transitively via rcgen because newer
  releases need edition2024 toolchains, and the committed `Cargo.lock`
  pins `base64ct 1.6.0` / `zeroize 1.8.2` for the same reason — the whole
  tree builds with the workspace MSRV 1.75 (verify with
  `cargo +1.75.0 check --workspace --all-targets`). `Cargo.lock` is
  committed — keep it reproducible. Core dev-dependencies (tests only,
  never in `[dependencies]`): `proptest` (`=1.5.0`, pinned for MSRV —
  newer releases pull `tempfile`/`getrandom` versions needing edition2024
  toolchains).
- Parties are numbered `1..=n` (`PartyId = usize`); evaluation point 0 is
  reserved for the secret.
- Fiat–Shamir / hashing domain separation uses versioned tags in
  `lib.rs::tags` (e.g. `b"OHM-ECDSA/v0.1/dkg-commit"`).

## Build and test commands

Commands run workspace-wide by default (both crates); scope to the core
with `-p ohm-ecdsa` and to the node crate with `-p ohm-ecdsa-node`.

- `cargo build` / `cargo build --workspace` — build the library and the
  node crate.
- `cargo test -p ohm-ecdsa` — runs 31 unit tests (inline `#[cfg(test)]`
  modules in `src/lib.rs`, `src/primitives/{shamir,vss,open,dleq}.rs`,
  `src/protocol/{dkg,triples}.rs`, `src/runtime/{policy,transport}.rs` —
  including the `wire_*` canonical `Encode`→`Decode` roundtrip and
  malformed-input tests, and the honest-majority/Committee parameter
  enforcement test),
  49 integration tests in `tests/e2e.rs`, 5 example smoke tests in
  `tests/examples.rs` (each narrative example is run via `cargo run
  --example` and checked for its guarantee lines),
  20 fault-injection tests in `tests/blame_matrix.rs` (the SPEC §10 F1–F8
  blame matrix: each fault class injected via the tamper hooks, exact
  `phase`+`blamed` asserted, §10.4 robust blame-and-continue variants,
  and the framing-freeness control; F7 unreachable by construction and
  F8 wire-level — both documented in the file header),
  12 property-based tests in `tests/properties.rs` (proptest: Shamir
  reconstruction/subset-independence, VSS homomorphism + zero-padding,
  verified openings, DLEQ roundtrip/rejection, triple multiplicativity,
  presign/sign invariants — capped case counts for the protocol-level
  ones), and 6 deterministic test-vector cases in `tests/vectors.rs`
  (byte-pinned keygen/presign/sign outputs under `tests/vectors/*.vec`;
  each sign vector re-parsed and k256-verified; regenerate with
  `OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors`). All 123
  pass at the time of writing.
- `cargo test -p ohm-ecdsa-node` — 109 tests: 3 M1 tests in
  `node/tests/mesh_keygen.rs` (3 nodes on localhost ephemeral ports:
  keygen over `MeshTransport` reconstructs the joint key, a cheating
  dealer is blamed with a verifying `BlameToken`, forged/unknown-sender/
  malformed frames are dropped while the honest keygen completes),
  2 §4.7 echo-consistency tests in `node/tests/echo_consistency.rs`
  (the reviewer attack on the superseded majority-echo rule — a 3-of-5
  corrupt sender signing two conflicting values plus a colluding
  equivocating echoer never splits honest acceptance: all honest nodes
  output ⊥ for the sender's slot, hold the two signed envelopes as F8
  evidence, and the constructed blame token audits VALID; an echo of a
  value the sender never signed is dropped + counted while the honest
  keygen completes),
  6 M2 thread-level tests in `node/tests/party_mesh.rs` (per-node keygen
  2-of-3 and 3-of-5, cheating dealer and false accuser each named by
  every node via the wire §6.1 rounds, per-node signing with valid low-s
  signature, wrong sign share blamed while the signature still delivers),
  8 M3a thread-level tests in `node/tests/party_offline.rs` (per-node
  triples multiplicative at the public commitments 2-of-3 and 3-of-5,
  bad DLEQ proof / bad re-share via wire complaints / false accusation
  each named consistently, bad nonce point and bad opening share named
  in presign, full arc keygen→presign→sign under the nodes' own key),
  21 M2/M3a/M3b/M3c/§8.7/H2/H3/H4/A7 process-level tests in `node/tests/process_demo.rs`
  (real child processes — 18 via `spawn-demo`, serialized within the test
  binary by a static `Mutex` and run under a 300 s watchdog, because 3
  child processes per test starve under a parallel full-workspace run:
  honest full arc, the `--ki` KI arc (keygen → KEY-FREE pool record →
  2-round KI sign, all processes agreeing on X and a verifying
  signature), sign cheater
  named by the other two processes with the signature still delivered,
  DKG cheater and false accuser named by all three — full arc and
  `--seeded` fallback — bad DLEQ proof and bad re-share named as
  `BLAME triples`, bad nonce point and bad opening share named as
  `BLAME presign`, `--persist` full arc leaving fsync'd consume
  tombstones and decodable transcripts, a `bad-deal` token file
  verified by the `auditor` subcommand and a tampered copy rejected,
  the `--tls` full arc over mTLS, the `--factory 2` H2 demo — a
  background presignature factory per process overlapping 3 online
  signatures, factory progress asserted, every signature verifying,
  the `--restart` H4 demos — a bad opening share named by every process
  while the presign and signature still COMPLETE (blame + continued
  service), and a dealing-phase cheat REFUSED at zero slack (consistent
  abort, `t` never lowered);
  plus 2 A7 soak tests (`--soak 20 --factory 2 --fault-rate 0.9` —
  per-session fault injection: every sign delivers and verifies, blame
  lands only on armed parties, stats lines present, exit 0; and
  `--soak 30 --persist --restart-every 10` — a kill/restart/rejoin
  cycle: the restarted node reloads its sealed key share (same X),
  survivors' reconnects ≥ 1, signs continue after the rejoin, the
  end-of-soak A4 store audit passes at every node);
  plus 3 H3 distributed-ceremony tests — three separate `init` runs +
  a public `assemble` booting a full-arc committee from per-party
  identity files (X agreement + a signature verifying under the fresh
  key), `assemble` rejecting a duplicate party id, and tampered `.pub`
  bundles — swapped certificate, swapped transport key — failing the
  node closed at startup),
  10 H4 thread-level tests in `node/tests/party_robust.rs` (strict
  per-node key separation: robust sign — bad `s_j` filtered and blamed
  `[2]` at every node, the SAME valid low-`s` signature delivered, the
  archived F6 token verifying offline at every node; robust presign —
  bad `v` opening share and bad nonce point each completing with
  consistent blame and records that sign and verify; robust triples —
  a bad re-share publicly reconstructed via the request/supply rounds
  (the victim's recovered c-share verifies against A[γ], `c == a·b`,
  dealer blamed consistently), a fabricated reconstruction request
  blaming the requester; §10.3 restart — 3-of-6 keygen and presign
  dealing cheaters restarting over the 5 survivors' ORIGINAL ids (the
  presign id poisoned to `first_id + 1`), completing and signing over
  the final committee; zero-slack refusal in 2-of-3; robust KI sign —
  bad R2 share and bad R1 opening share each blamed with the KI
  signature delivered),
  6 H2 thread-level tests in `node/tests/resilience.rs` (reconnection
  after a dropped outgoing connection — journal re-sync completes the
  in-flight keygen with `reconnects >= 1`, a silent peer failing its
  round loudly on the round timeout with no parked threads, clean
  shutdown idle and mid-session with all threads joined, the listener
  accept-rate window counting a raw poke flood, garbage frames dropped
  while the honest keygen completes, and concurrent sessions — a
  background factory keeping 2 presigs pooled per node while signing 3
  messages, signatures verifying under the fresh key),
  3 §8.7 KI-over-wire thread-level tests in `node/tests/party_ki.rs`
  (strict per-node key separation: the KI full arc signs under the
  nodes' own key with pool single-use enforced, ONE key-free pool signs
  for TWO different keys from two independent keygens — each signature
  verifies under its own X — and a bad R1 opening share is blamed by
  every node in `Phase::Sign`),
  15 M3b tests in `node/tests/persist.rs` (the durable store
  survives drop/reopen, consumed ids stay consumed across a simulated
  crash, duplicate inserts rejected live/consumed/on reopen, wrong-key
  reopen rejected, stray `.tmp` files dropped, transcript dedup +
  decode, F2/F6 tokens verified offline and tampering/wrong-registry
  rejected, crash-recovery: sign → "restart" on the same store dir →
  second sign with the same id fails; A4 rollback detection: a tampered
  record/tombstone/journal fails `open` with `PersistError::Integrity`,
  a crash between tombstone fsync and journal append heals consumed, a
  store backup restored over an intact transcript is refused as
  `ROLLBACK DETECTED` naming the spent id — downgraded to a warning by
  `open_unverified` — and a whole-directory rollback opens with the
  unverifiable-integrity warning, the re-issuable spent id demonstrating
  the residual risk; A7: `DiskPresigStore::burn` durably tombstones a
  failed-production id (never re-issued, covered by `max_seen_id`,
  survives reopen, live-id burn refused) and the sealed key-share file
  round-trips / fails closed on tampering or a wrong storage key),
  3 M3c thread-level tests in `node/tests/mesh_tls.rs` (the full arc
  over committee-pinned mTLS, an unpinned rogue peer cert rejected in
  both handshake directions with every node failing closed — no
  plaintext fallback — and a plaintext peer dropped by a TLS listener
  that still completes keygen afterwards), and 3 M3c unit tests in
  `node/src/net/tls.rs` (pinning verifiers accept exactly the pinned cert
  and reject any other; inconsistent own/pinned material rejected),
  and 4 H3 unit tests in `node/src/setup/ceremony.rs` (identity/pub
  roundtrip with the secret key matching the bundle's verifying key,
  fingerprint sensitivity to id/key/cert but not the addr hint,
  `assemble` committee-shape validation — duplicate ids, id gaps, bad
  threshold — and mixed-TLS-posture rejection),
  4 H5 unit tests in `node/src/store/locked.rs` (mlock fail-open policy) and
  12 in `node/src/store/seal.rs` (seal/open roundtrip, wrong-key/tamper/
  wrong-purpose fail-closed, legacy cleartext rejected, 0600
  enforcement, generated-key roundtrip; A5 `StorageKeySource`: Command
  helper valid-hex/non-zero-exit/garbage-stdout/timeout cases,
  Command→EnvVar→KeyFile→Generated precedence, a failing configured
  Command never silently generating a dev key), 2 §4.7 acceptor unit tests
  (`node/src/net/transport.rs`, `node/src/party/party.rs`: a sender's
  self-echo never counts toward the `T−1` echo quorum — only echoes
  from parties OTHER than the sender do), and 5 H5 pool-manager tests in
  `node/tests/pool.rs` (deterministic — sim records, injectable clock,
  no mesh: refill-to-target under drain with fresh ids and no
  over-production at target, TTL expiry erasing aged records — sealed
  file removed, `<id>.expired` tombstone, id burned: consume/re-insert
  rejected — while fresh refills survive, ttl 0 never expires, a
  simulated restart counting persisted records toward the target and
  resuming id allocation above the persisted max, and a legacy v1
  SEALED record accepted with the mtime fallback, consumable, and
  TTL-expiring like any other), and 2 A6 thread-level tests in
  `node/tests/metrics.rs` (a 3-node full arc with durable stores, then a
  metrics snapshot per node — every documented counter present with a
  sane value: `frames_sent`/`frames_received` > 0, `sessions_completed`
  ≥ 3, `store_consumed` 1, the `#` header + `name value` format parsed
  line-by-line — plus the `MetricsReporter` interval/final blocks).
- `cargo run -p ohm-ecdsa-node -- spawn-demo [--cheat-node K --cheat C]
  [--seeded] [--persist] [--tls] [--ki] [--factory N] [--pool-ttl SECS] [--restart] [--delay-ms D]
  [--soak SECS] [--fault-rate P] [--restart-every SECS] [--seed S] [--soak-stats-every S]
  [--metrics] [--allow-unverified-store]` — M3a demo: 3 child
  processes, each holding only its own seed; the FULL ARC keygen →
  presign → sign, all under the key the processes' own keygen produced;
  prints per-process logs with per-phase timings, the joint key, the
  self-produced presignature, the signature, and blame (`C` ∈
  `bad-deal:V`, `false-accuse:D`, `bad-sign-share`, `bad-product-proof`,
  `bad-reshare:V`, `bad-nonce-point`, `bad-open-share`; `--seeded`
  falls back to the M2 ceremony-presig sign; `--persist` gives each
  child a per-node `--data-dir` — durable presig store + transcript /
  blame-token archive; `--tls` (M3c) generates per-party self-signed
  certs with rcgen and runs the arc over committee-pinned mTLS — nodes
  take `--tls CERT KEY --pinned DIR`, and `setup --tls` writes the
  per-party cert files for manual runs; `--ki` (§8.7) runs the
  key-independent arc: keygen → KEY-FREE pool record (P1–P3, no P4) →
  2-round online KI sign under the fresh key; `--factory N` (H2/H5) runs
  the concurrent-sessions demo: the H5 pool manager (`node/src/party/pool.rs`)
  keeps N presignatures in the node's DURABLE store (M3b sealed records)
  while the main thread signs 3 messages (`--pool-ttl SECS` expires aged
  records per §8.6(3) — erased, never served, ids burned; 0 = never),
  ending with a clean `PartyNode::shutdown`; `--restart` (H4) runs the
  arc on the §10.4-robust + §10.3-restart drivers — a continuable
  cheater is named AND the arc completes, a dealing-phase cheater is
  expelled and the session re-runs over the survivors (refused at zero
  slack — 2-of-3 refuses, `t` never lowered); `--soak SECS` (A7)
  requires `--factory N` and runs the continuous soak (see the A7
  paragraph above: jittered sign ticks, `--fault-rate P` per-session
  cheats, `--restart-every SECS` kill/rejoin cycles with `--persist`,
  deterministic under `--seed S`; rejects `--seeded/--ki/--tls/
  --restart/--cheat`).
  `cargo run -p ohm-ecdsa-node -- auditor TOKEN_FILE COMMITTEE_FILE` is
  the M3b offline §A.4 evidence check (exit 0 = VALID).
  `cargo run -p ohm-ecdsa-node -- m1-demo [-- PORT_BASE]` is the original
  M1 orchestrator demo.
  `cargo run -p ohm-ecdsa-node -- init --id N --dir D [--addr H:P]
  [--tls]` (H3) is the per-party ceremony step (own keypair + cert on
  its own machine; prints the bundle FINGERPRINT);
  `cargo run -p ohm-ecdsa-node -- assemble --committee D --inputs
  PUB,... [--t T]` (H3) is the PUBLIC assembly step (validates the
  bundles, writes `committee.hex` + the pinned cert set, prints all
  fingerprints); `node --identity FILE` boots from an H3 identity
  (`--seed` stays for the DEMO-ONLY one-process ceremony).
- `cargo run --release -p ohm-ecdsa-node --example mesh_perf` — M2
  latency benchmark over the real mesh: keygen and online-sign wall time
  for 2-of-3 and 3-of-5, localhost and with per-link artificial delay.
- `cargo run --release --example perf` — `examples/perf.rs` wall-clock
  micro-benchmarks for the SPEC §13.5 rows (std `Instant` only, no extra
  dependencies).
- `sage analysis/g1_probe.sage` — empirical probe of the proof's one
  named heuristic (G1, F-uniformity of the x-coordinate map): small-scale
  collision-search exponents for `Φ(M,τ)` under adversarial tweaks, with a
  Wagner 4-sum positive control on the affine (GS21) condition. Dev tool
  only, like `fuzz/`; results + interpretation in `analysis/README.md`
  (full log `analysis/g1_probe_results.txt`), cited in
  `docs/proof/PROOF.md` §8.2.6.
- `cd demo-evm && cargo test` / `cargo run` — the EVM testnet demo
  (workspace-EXCLUDED like `fuzz/`, own `Cargo.toml`/`Cargo.lock`; deps
  beyond the core: `tiny-keccak` only). M1 is local-only: hand-rolled
  RLP + EIP-1559 sighash, a 2-of-3 committee arc (keygen → presign →
  sign with the sighash as the message scalar — the protocol layer takes
  `m: &Scalar`, no core change), y-parity from `presig.big_r` flipped by
  low-`s` normalization, and `VerifyingKey::recover_from_prehash` as the
  local ecrecover check. Prints a broadcast-ready signed Sepolia
  transfer. M2 (JSON-RPC broadcast) and M3 (per-node drivers, soak,
  Plume) are roadmap.
- `cargo run --example NAME` — narrative examples (living documentation,
  deterministic `sim::make_rngs` seeds, every signature k256-verified):
  `wallet_2_of_3` (presig pool + single-use stores + lost-phone
  recovery), `consortium_custody` (3-of-5 batch presign, subset signing,
  §9.4 HD tweak), `identifiable_abort` (fail-fast blame vs §10.4 robust
  delivery), `blame_token` (§10.2/§A.4 signed envelopes + offline-verifiable
  blame tokens, forgery rejection), `epoch_refresh` (§13.4 refresh +
  re-share, X unchanged).
  All five are smoke-tested by `tests/examples.rs` (run + stdout
  guarantee lines).
- `cargo fmt` / `cargo clippy` — standard toolchain; no custom config
  files, use defaults.

There is no CI configuration, no deployment process, and no release
pipeline in the repo.

## Code organization

Two crates: the core library at the repo root (one module per protocol
building block, grouped into three layers mirroring the spec (`src/`,
~5400 lines total): `primitives/` (SPEC §4 building blocks), `protocol/`
(§6–§9, §13.4), `runtime/` (transport/orchestration/policy)) and the
transport companion in `node/` (same layering convention under
`node/src/`: `net/` transport substrate, `party/` per-node drivers +
pool manager, `setup/` committee ceremonies, `store/` durability + key
protection). Each crate's `lib.rs` declares its layer
modules and re-exports each building-block module FLAT
(`pub use primitives::{dleq, open, shamir, vss};`,
`pub use net::{mesh, tls, transport, wire};` etc.), so the public
paths `ohm_ecdsa::shamir`, `ohm_ecdsa_node::party::PartyNode`, … are
unchanged by the
layering — internal `crate::…` references resolve through those
re-exports too:

| Module | SPEC § | Role |
|---|---|---|
| `lib.rs` | — | `Params`, `PartyId`, `Committee` (explicit party-id set for §10.3 restarts; default `1..=n`), domain-separation tags, hashing helpers, `session_id` (§13.1 sid derivation); declares the three layer modules and flat-re-exports every building-block module (`pub use primitives::{dleq, open, shamir, vss};`, `pub use protocol::{dkg, presign, refresh, sign, triples};`, `pub use runtime::{policy, sim, store, transport};`) so `ohm_ecdsa::<module>` paths are unchanged; re-exports `Error`/`Result` |
| `error.rs` | 10 | `Error`, `IdentifiableAbort { phase, blamed, detail }` (crate root — shared by all layers) |
| `primitives/shamir.rs` | 4.1, 7.4.1 | `ShamirPoly`, Lagrange interpolation at 0 (`lagrange_coeffs`, `interpolate_at_zero`) and at an arbitrary point (`lagrange_coeffs_at`, `interpolate_at` — used for §10.4 public reconstruction and §7.4 slot openings); evaluation at an arbitrary `Scalar` point (`eval_at`); packed slot points (`slot_point(b) = -(b)`, §7.4.1); `random_packed_const` — constant-pack polynomials taking one value at every slot point (packed re-sharings) |
| `primitives/vss.rs` | 4.2, 7.4.3 | `FeldmanCommitment` and its homomorphic ops (`add`, `scale`, `add_const`, `sum`); `add`/`sum` tolerate MIXED-LENGTH vectors by zero-padding the shorter one (§7.4.3 — identity points are zero high coefficients); `eval_at_point` — commitment evaluation at an arbitrary `Scalar` point (packed slot binding checks) |
| `primitives/dleq.rs` | 4.4, 7.3 | Chaum–Pedersen DLEQ proofs (triple product proofs); `verify_batch` — §7.3 aggregate verification of one prover's B proofs (two MSMs, Fiat–Shamir'd combination weights `ρ_b`, per-proof fallback for blame) |
| `primitives/open.rs` | 4.6, 7.4, 10.4 | The verified-opening subprotocol — **all** openings go through `open::open`; this is where identifiable abort is structural. `open_robust` filters and blames bad senders and still reconstructs; `open_at` interpolates at an arbitrary point (§7.4 packed slot openings) with an explicit quorum |
| `protocol/dkg.rs` | 6, 6.1, 7.3, 7.4 | Commit-reveal Pedersen DKG, message-oriented (`DkgInstance` with `start`/`start_committee`/`start_with_secret` (fixed-secret deals for §13.4)/`reveal`/`finalize`/`defend`, `DkgBcast1`/`DkgBcast2`/`DkgP2P`); §6.1 complaint resolution (`resolve_complaint`), `DkgTamper` fault-injection hooks (`bad_deal`, `corrupt_share` — the false-accuser branch, `bad_reveal` — the F1 reveal-hash-mismatch branch); `DkgBatchInstance` deals `B` polynomials in ONE commit-reveal session (batch VSS, §7.3: R1 hash covers the concatenation of all `B` vectors, P2P carries `B` shares) at ANY uniform degree — `start_committee_with_degree` (random degree-`d` packed sharings, §7.4.2 PT1) and `start_with_polys` (explicit polys with constrained slot values, e.g. the §7.4.3 P4 constant-pack key re-sharing). Instances run over a `Committee` — an explicit, possibly non-contiguous id set for §10.3 restarts |
| `protocol/triples.rs` | 7, 7.3, 7.4, 10.4 | Beaver triple factory with verifiable degree reduction (`generate`, `generate_with_tamper`), `TripleTamper` fault-injection hook; `generate_robust` (§10.4) publicly reconstructs a cheating dealer's committed re-sharing polynomial from the `≥ t` valid shares and continues (excluding a dealer is impossible: `γ` needs `2t−1` product points); bad DLEQ product proofs still abort; `generate_batch` is structurally per-batch (§7.3): one commit-reveal for all `2B` secrets, one re-sharing pass carrying all `B` vectors + `B` DLEQ proofs per party; T3 verifies each prover's `B` proofs AGGREGATELY via `dleq::verify_batch` (§7.3 optional optimization — identical accept/reject to individual verification, per-proof fallback keeps F3 per-triple blame; `generate_batch_with_tamper` + `TripleTamper::bad_product_proof_at` fault-inject one indexed batch proof). `generate_packed` (§7.4.2, Protocol 7.2′ — Franklin–Yung) produces `B` triples from ONE pair of degree-`d` packed sharings (`d = t + B − 2`, slots `e_b = -(b)`; requires `n ≥ 2t + 2B − 3`, §7.4.1, else `Error::InvalidParams`): PT1 deals `⟦α⟧_pack`/`⟦β⟧_pack` in one commit-reveal (`joint_random_packed`), PT2 re-shares each party's ONE local product with a CONSTANT-PACK polynomial (value `h_j = α_j·β_j` at every slot) plus ONE DLEQ proof, PT3 adds a slot-binding check (`EvalCom(C_j, e_b) == C_j.points[0]`, dealer blamed) before the per-slot Lagrange recombination — outputs are constant-pack `⟦γ_b⟧` (value at every slot, so packed Beaver consumption opens consistently at `e_b`); per the crate convention `TripleShare.a`/`.b` hold the party's packed-share scalar (same for every slot). `joint_deal` deals explicit per-party polys in one commit-reveal and returns the revealed commitments for public slot-binding checks. `*_with_committee` variants run over an explicit id set |
| `protocol/presign.rs` | 8, 8.5, 8.7, 10.4, 7.4.3 | Key-dependent presignatures; `KeyShare` (alias of `DkgOutput`), `Presignature`, `PresignTamper` fault-injection hooks (`bad_nonce_point`, `bad_open_share`, `triple_tamper` — forwarded to the first triple session's dealing phase); `presign_robust` (§10.4) runs openings through `open_robust`, filters and blames bad `R_j` (interpolating `R` over the valid senders), expels blamed parties, and returns records for the survivors plus the blame list; `presign_batch` generates `B` records per session (§8.5). `presign_packed` (§7.4.3) consumes packed triples (two `generate_packed` sessions of `B` slots) and deals `⟦u⟧_pack`/`⟦a⟧_pack` plus each party's constant-pack re-sharing of `λ_j·x_j` in ONE commit-reveal (dealt polys publicly bound to `A[x]` by slot-point `EvalCom` equality — the key must enter P4 as a constant packed vector because `⟦x⟧`'s degree-`(t−1)` polynomial evaluates to `p_x(e_b) ≠ x` at slots `b ≥ 1`); openings interpolate at the slot points with quorum `d + 1 = t + B − 1`; output records are degree-`d` sharings. `presign_ki` (§8.7, optional KEY-INDEPENDENT mode) runs P1–P3 verbatim with NO P4 — takes no key shares (P1–P3 never touch `x`), consumes ONE triple (P4's triple moves online) — and outputs `KiPresignature { id, index, r, big_r, u_share, u_com }` (NOT key-equivalent: `t` pool shares reveal no key; still strictly single-use; binds to a key only at signing time). `*_with_committee` variants run over an explicit id set (`keys[k]`/`rngs[k]` positional in `ids`, `keys[k].index` checked) |
| `protocol/sign.rs` | 9, 9.4, 10.4, 7.4.3, 8.7 | `sign_share` (local) + `combine` (verified interpolation, low-`s` handled by caller); `combine_robust` filters and blames bad shares and still interpolates; `combine_at` (§7.4.3) interpolates at an explicit point with an explicit quorum — packed presignatures combine at the record's slot point with quorum `t + B − 1` (per-share point-equality verification unchanged). KI online signing (§8.7): `ki_z_share`/`ki_z_com` (party `j`'s `z`-share and the public `A[z]` from a fresh triple and the opened R1 masks — EXACTLY the §8 P4 formula run online; `u·x` is never computed directly, §12), `sign_share_ki` (`s_j = m·u_j + r·z_j`), `combine_ki` (verified against `m·A[u] + r·A[z]`, same blame semantics as `combine`), `combine_ki_robust` (the §10.4 filter-and-continue variant, H4 — the node crate's `sign_ki_robust` drives it), `KiSignTamper` fault-injection hooks (`bad_open_share`, `bad_sign_share`). EXPERIMENTAL (§9.4 candidate, §11.3(8) open lemma — NOT for production): `rerand_gamma` (domain-separated `γ = H(sid ‖ id ‖ M ‖ τ ‖ X)`, nonzero by counter-rehash), `sign_share_rerand` / `combine_rerand` — multiplicative re-randomization `k′ = γk` as local scalings (`u′ = γ⁻¹u`, `z′ = γ⁻¹z`, tweaked `z′ = γ⁻¹(z + τu)`) with commitments scaled by the same public factors, so the point-equality blame check survives unchanged |
| `protocol/refresh.rs` | 13.4 | Committee maintenance, `X` unchanged: `refresh` — proactive zero-constant re-sharing over the same committee (dealt via `DkgInstance::start_with_secret`; per-dealer zero-constant check on the revealed vectors; new shares `x'_j = x_j + Σ_i z_i(j)`); `reshare` — re-sharing to a NEW committee (each old party deals `x_j` over the new id set; public binding check `C_j.points[0] == EvalCom(A[x], j)`; new shares `x'_m = Σ_j λ_j^S · p_j(m)`, new commitment `A'[x] = Σ_j λ_j^S · C_j`); `ReshareTamper` fault-injection hooks (`bad_deal`, `bad_commitment`). Both assert `A'[x].points[0] == X`; both mandate `PresigStore::clear` on epoch change (§8.6) |
| `runtime/store.rs` | 8.6, 8.7 | `PresigStore`: per-party single-use presignature store bound to one key (atomic `consume`, duplicate-id rejection, `clear` for the §13.4 epoch-change invalidation); `KiPool` (§8.7): KEY-FREE pool for key-independent records — same §8.6(1) single-use discipline (atomic consume, duplicate-id rejection) without the one-key binding, and NO epoch-change `clear` mandate (KI records carry no key-equivalent material) |
| `runtime/policy.rs` | 10.3 | `restart_committee`: expel-and-restart committee computation — removes blamed ids, refuses (never lowers `t`) when the remainder would drop below `2t−1` (below the bound, use §13.4 re-sharing — `protocol/refresh.rs`) |
| `runtime/transport.rs` | 4.7, 10.2, 13.1, 13.2 | The explicit transport seam: `Envelope<M>` (exactly the per-message fields a production transport signs — sid/phase/round/from/to/payload), object-safe sync `Transport<M>` trait modeling the LOGICAL rounds (§2.2), `DkgMessage` payload enum, `SimTransport` reference in-process impl (delivers identical accepted sets — echo-broadcast consistency), `drive_dkg` transport-driven DKG driver. §10.2/§13.1 signing: `Encode`/`Decode` (THE canonical wire format: length-prefixed, no serde — implemented for `DkgMessage`, the DKG bcast/p2p structs, `FeldmanCommitment`, the scalar/point/`Signature` primitives, and `Envelope`/`SignedEnvelope` themselves; other message types implement it as needed), `SignedEnvelope<M>` (sender ECDSA signature over the canonical encoding, domain-separated under `tags::TRANSPORT_SIGN`), `SigningTransport` (wraps any `Transport<SignedEnvelope<M>>` — signs on send, verifies accepted sets against the party key registry, a forged/tampered envelope is `Error::Abort` blaming the claimed sender), `BlameToken` (§A.4 evidence: abort + offending signed share envelope + dealer commitment; `verify(party_keys)` is the auditor's offline check), `drive_dkg_signed` (returns `SignedDriveError { error, token }` — `drive_dkg` stays the unsigned entry point for `sim::run_keygen*`); triples/presign orchestration still drives DKG instances internally (incremental pattern in the `transport` module docs) |
| `runtime/sim.rs` | 4.7, 10.3, 13.2, 7.4.3, 9.4 | Single-threaded reference orchestrator: `run_keygen` / `run_keygen_with_tamper` (message delivery routes through `transport::SimTransport` + `transport::drive_dkg`), `run_presign` / `run_presign_robust` / `run_presign_batch` / `run_presign_packed` (§7.4.3), `run_sign` / `run_sign_stored` / `run_sign_robust` / `run_sign_packed` (§7.4.3 — slot-point interpolation, quorum `t + B − 1`), `run_sign_rerand` (§9.4 candidate — EXPERIMENTAL, §11.3(8) open lemma, off by default: γ via `sign::rerand_gamma`, local scaled shares, verified combine under the publicly scaled commitments), `run_sign_ki` / `run_sign_ki_pooled` (§8.7 — the 2-round online flow: R1 generates a FRESH triple and opens `δ = ⟦u⟧−⟦α⟧`, `ε = ⟦x⟧−⟦β⟧` through `open::open`; R2 computes `z_j` locally and broadcasts `s_j`, verified via `sign::combine_ki`; fail-fast only — no §10.4 robust variant), §10.3 expel-and-restart wrappers `run_keygen_with_restart` / `run_presign_with_restart` / `run_triples_with_restart` (poisoned sid/id per retry; blame in original ids; keygen/triples retries renumber, presign retries keep original ids; the presign/triples wrappers drive the §10.4 ROBUST variants per attempt, so continuable faults complete in-attempt without poisoning — only dealing-phase aborts cascade to restart), §13.4 wrappers `run_refresh` / `run_reshare` (caller must clear presignature stores on epoch change), `make_rngs` (deterministic `StdRng` seeds — tests only) |
| `node/` (crate `ohm-ecdsa-node`) | 4.7, 10.2, 13.1, 13.2 | Transport companion (localhost scale, `std::net` blocking threads, NO async runtime — rustls since M3c, tokio never): `src/net/wire.rs` (length-prefixed framing of the core's canonical `Encode`/`Decode` format; `WireMessage<M>` = original signed envelope or echoer-signed §4.7 echo, generic over the payload; `verify` against the party key registry), `src/net/mesh.rs` (`Node<M>`: listener + full-mesh connections + reader threads; first-echo-per-slot rule; unknown sender/bad signature/misrouted p2p dropped + logged; self-echo loopback for the M2 per-node acceptor; config-driven send delay for benchmarks; `bind_tls` wraps every connection in M3c mTLS — same frames inside the TLS stream), `src/net/tls.rs` (M3c, SPEC §13.1: OPTIONAL mTLS with certificates PINNED to the committee — `CommitteeTls` own cert/key + pinned per-party cert set, TLS 1.3 only, rustls ring provider, blocking `StreamOwned` over `TcpStream`; outgoing handshakes accept ONLY the expected peer's pinned cert (TLS identity == PartyId), incoming accept any pinned committee cert and are attributed to the matching party; NO PKI/system roots, NO plaintext fallback; rcgen self-signed certs are the dev/test stand-in for a deployment PKI; `setup --tls` / `spawn-demo --tls` / `node --tls CERT KEY --pinned DIR`; envelope signatures stay ON regardless), `src/net/transport.rs` (`MeshTransport` — M1 — implementing the core `Transport<SignedEnvelope<DkgMessage>>`: echo-broadcast acceptor — the §4.7 signed-echo rule: accept `m` from `i` on `i`'s valid signature plus `T−1` echoes from parties OTHER than `i` (sender self-echoes are filtered out of the quorum count in `Acceptor::process` — same in `party.rs`'s per-node acceptor; the accepting node's OWN echo still counts for every slot but its own); a second conflicting sender-signed payload in a slot poisons the sender for the session (`⊥`, F8 evidence — the two signed envelopes), dedup by `(sid, phase, round, from)`; blocking round collection with a generous timeout that returns the partial set and lets the DKG fail closed), `src/party/party.rs` (M2/M3a: `PartyNode` — holds ONLY its own transport key/id and runs only its own logic; per-node keygen §6 with the §6.1 complaint subprotocol on the wire — signed `Complaints`/`Defenses` broadcast rounds adjudicated identically at every node, factored as `joint_vss` + a shared wire `complaint_round` helper — per-node §7.2 triple driver (T1 two `joint_vss` instances, T2 `FeldCommit(g_j)` + ONE DLEQ product proof broadcast + P2P re-shares, T3 proof checks ⇒ F3 blame and re-share checks ⇒ wire §6.1 complaints, Lagrange combine), per-node §8 presign driver (two triple sessions + ⟦u⟧/⟦a⟧ `joint_vss`, fail-fast point-equality openings δ/ε/v/δ′/ε′ and nonce-point `R_j == EvalCom(A[k], j)` checks ⇒ F5 blame, `v=0`/`r=0` ⇒ `Error::ZeroValue` retry-with-fresh-id; §10.4 robust continuation deliberately stays in the core's sim), and per-node §9/§10.4 signing: broadcast `sign_share`, point-equality verification, robust combine, low-s; §8.7 KI mode over the wire — `presign_ki` (P1–P3 of the presign driver verbatim via the shared `presign_p1_p3` helper, P4 omitted — the record is key-free and NOT key-equivalent), the 2-round `sign_ki` (R1 fresh per-node triple + fail-fast verified δ/ε openings, R2 `s_j` verified by core `combine_ki`, low-s; F6 sign-share tokens archived as in §9), and the in-memory key-free pool wrappers `presign_ki_pooled` / `sign_ki_pooled` (core `KiPool`, atomic consume — the M3b durable store stays per-key); `NodePayload` wire enum; `Cheat` fault injection — `BadDeal`/`FalseAccuse` (VSS), `BadProductProof`/`BadReshare` (triples), `BadNoncePoint`/`BadOpenShare` (presign), `BadSignShare`), `src/setup/seed.rs` (the DEMO-ONLY one-process ceremony writing per-party SECRET seed files + a PUBLIC committee file — the `--seeded` fallback for presignature distribution; transport keys come from the seed files in that mode), `src/setup/ceremony.rs` (H3: the DISTRIBUTED ceremony — the standard setup path: per-party `init` writing a SECRET `party-<id>.identity` + PUBLIC `party-<id>.pub` on each party's own machine, hex `fingerprint` for out-of-band verification, and the PUBLIC `assemble` validating bundles — ids exactly `1..=n`, uniform TLS posture — and writing the unchanged `committee.hex` format with `x` = identity point, i.e. NO ceremony key; nodes boot with `--identity` and fail closed when their own key/cert does not match the registry/pins), `src/main.rs` (`node`/`setup`/`init`/`assemble`/`spawn-demo` process separation + `m1-demo` + the M3b `auditor`; spawn-demo runs the FULL ARC keygen→presign→sign under the fresh key by default, `--persist` gives each child a per-node `--data-dir`, `--tls` runs the arc over M3c mTLS, `--soak` runs the A7 continuous soak — `run_soak_node`, the stdin-command worker (FACTORY-START / DRAIN / POOL-STATUS / MESH-CHECK / SIGN / STOP), and `run_soak_demo`, the parent owning the seeded schedule), `src/store/persist.rs` (M3b: `DiskPresigStore` — the §8.6 durable single-use presignature store, write-tmp-rename + fsync per insert, the consume tombstone fsync'd BEFORE the record is handed out so a kill/restart can never sign twice with the same presignature; H5: every record SEALED with the versioned v2 payload — created-at stamp for the pool TTL — `<id>.expired` tombstones burning expired ids forever, legacy v1 sealed records accepted with the file-mtime fallback, legacy cleartext rejected fail-closed; A7: `DiskPresigStore::burn` — a durable `OP_BURN` journal op + `<id>.expired` tombstone for a NEVER-INSERTED id whose production session failed (so `max_seen_id` covers it and a restarted pool manager never re-issues it), and `save_keyshare` / `load_keyshare` — the node's long-term key share SEALED at rest (`<data-dir>/keyshare.sealed`, H5 AEAD + 0600) for the soak's process-restart rejoin; A4 rollback DETECTION (§13.3) — every mutation chained into the fsync'd `journal.log` (`entry_hash = H(tag ‖ seq ‖ op ‖ id ‖ prev_hash ‖ payload_hash)`), verified against the directory at `open` (crash windows heal in the safe direction, any other divergence is `PersistError::Integrity` fail-closed) and cross-checked against the sign transcript (`<store>/../archive/transcript.log`): a spent id showing LIVE again is refused as `ROLLBACK DETECTED` naming the id; whole-directory rollback stays undetectable (startup warning — prevention needs state outside the directory); `open_unverified` is the `--allow-unverified-store` dev escape hatch; `Archive` — the §4.7 accepted-envelope transcript + `aborts.log`; `BlameEvidence` token files for the fault classes with wire evidence — F2 dealt shares, F6 sign shares; other classes logged `token: none`; `audit_token` — the §A.4 offline verifier reusing the core's `BlameToken::verify` where the shape fits), `src/store/locked.rs` (H5 §13.3: `LockedSecret<T>`/`LockedBytes` page-locked `mlock` wrappers for long-lived secrets at the node boundary — FAIL-OPEN with a loud warning when the OS refuses, the only fail-open path in H5), `src/store/seal.rs` (H5 §8.6(2): `StorageKey` — ChaCha20-Poly1305 AEAD at rest for every secret file, versioned + purpose-bound sealed format, `StorageKeySource` (A5 — storage secret from `OHM_STORAGE_KEY_CMD` helper command → `OHM_STORAGE_KEY`/`OHM_STORAGE_KEY_FILE` → generated `0600` dev key; the KMS interface, not a KMS; a configured-but-failing source fails closed, never silently generates; rotation needs re-sealing — rekey tooling NOT built); `0600` enforcement + looseness warnings), `src/party/pool.rs` (H5 §8.6: `PoolManager` — the per-node pool maintenance layer over the durable store: refill-to-target as the SINGLE WRITER (signing only consumes through the atomic consume), per-record TTL expiry with secure erase via `DiskPresigStore::expire` (§8.6(3), injectable clock for deterministic tests), crash/restart discipline — ids re-seeded from the persisted `max_seen_id`, insert dedup, never over-produces; `--factory N` + `--pool-ttl SECS` wire it into the demo; A7: `tick_tolerant` — the soak's fault-tolerant maintenance pass: a failed production session's id is DURABLY burned via `DiskPresigStore::burn` (never re-issued — a retried session must never reuse a sid the wire may still hold acceptor/journal state for), counted in `PoolCounters::failed`, and the loop keeps running instead of stopping loudly), `src/party/metrics.rs` (A6: the pull-based metrics snapshot — `snapshot` renders one greppable block: `#` header with node/committee/pid/uptime, then `name value` counters — mesh frames sent/received, drops per reason, reconnects, sessions active/completed, F8 equivocations, pool target/stored/produced/expired, store live/consumed/expired + A4 integrity-warning count; `MetricsReporter` appends every 15 s and once on drop — `node --metrics-file PATH`, `spawn-demo --metrics`; deliberately NO HTTP endpoint, documented in `docs/runbook.md`), `examples/mesh_perf.rs` (latency benchmark). M1 is the reference-orchestration pattern (one process holds all transport keys); M2/M3a enforce key separation by construction. H2 network resilience is done (reconnection with backoff + per-session journal re-sync, `Node::shutdown`/`PartyNode::shutdown` clean shutdown, write/handshake/round timeouts, DoS guards — per-connection frame-rate window, `wire::FrameBound` per-variant size bounds, listener accept-rate window, mTLS handshake concurrency cap, bounded mailbox, acceptor caps — counted in `MeshMetrics`, and multiple concurrent sessions via the collector-thread + condvar acceptor with the `node --factory N` demo as the proving ground), and H4 (`src/party/party.rs`, §10.4 + §10.3, OPT-IN — default stays fail-fast): the robust drivers (`presign_robust` — every opening filtered-and-continued through the core's `open_robust` with blame identical at every node, nonce points filtered with subset-Lagrange `R` interpolation, blamed expelled from later rounds' share sets; `triple_robust` — T3 re-share faults publicly reconstruct the cheater's committed re-sharing polynomial over two added broadcast rounds: `ReshareRequests` carrying the dealer's own signed `Reshare` envelope as self-authenticating evidence (a fabricated/verifying request blames the REQUESTER) and `ReshareSupply` pooling the received shares, first `t` valid supplies interpolate, `< t` aborts as in the core's `generate_robust`; `sign_ki_robust` — robust R1 openings + the core's new `sign::combine_ki_robust` in R2) and the §10.3 expel-and-restart wrappers (`keygen_with_restart` / `presign_with_restart` — deterministic `policy::restart_committee` verdicts, poisoned sid/id per §10.3(2), survivors' ORIGINAL ids preserved — the wire never renumbers, retries inherently bounded, zero-slack refusal propagates the abort with the refusal noted; every driver is committee-aware via `*_over` id sets, `sign_over` / `sign_stored_over` sign over the post-restart committee; `node --restart` / `spawn-demo --restart`); still open: crash recovery of finished rounds, committee rejoin after a full restart, SIGINT handling |

Architecture: per-party protocol logic is message-oriented (broadcast/P2P
structs keyed by sender); the `runtime/transport.rs` seam (`Envelope` /
`Transport` / `SimTransport`, §13.2) is the explicit contract between
that logic and any delivery layer — `runtime/sim.rs` models the echo-broadcast
channel by delivering identical accepted message sets through
`SimTransport`. A production deployment implements the same `Transport`
trait over a real transport (mTLS + echo broadcast + per-message
signatures, SPEC §13.1) without changing the per-party logic.

## Development conventions

- **Minimal, spec-faithful code.** Every module header cites its SPEC
  section; formulas in comments match SPEC notation (`[u] = [k⁻¹]`,
  `⟦v⟧`, `EvalCom`). Preserve this style — the code is a companion to the
  spec.
- Errors: `thiserror`-based `Error` enum; every verification failure that
  identifies a cheater must surface as `Error::Abort` with the blamed
  party ids, not a generic error.
- Secret-holding structs (`Presignature`, `TripleShare`, `DkgOutput`/
  `KeyShare`, `ShamirPoly`) erase their scalars on `Drop` via `zeroize`
  (compiler-fenced; k256's `Scalar` implements `DefaultIsZeroes`).
- Deterministic testing: per-party RNGs come from `sim::make_rngs(n,
  seed)`; tests never use OS randomness. Fault injection uses the
  `tamper` parameters (`DkgTamper`, `TripleTamper`, `PresignTamper`,
  `ReshareTamper`, `run_sign`'s / `run_sign_robust`'s `tamper`) rather than
  mocks.
- Rust defaults: `std`, standard 4-space rustfmt style. The CORE crate
  is unsafe-free and keeps it compiler-enforced via
  `#![forbid(unsafe_code)]` in `src/lib.rs`; the node crate keeps only
  its 5 documented `unsafe` sites in `node/src/store/locked.rs` (mlock).

## Testing instructions

- Run the full suite with `cargo test --workspace` (~25 s total; the
  M3c fail-closed TLS test waits out one 2 s round timeout by design,
  and the process-level tests are serialized within their binary — a
  static `Mutex` in `node/tests/process_demo.rs` — under a 300 s
  watchdog, the fix for load-induced flakes when the whole workspace
  runs in parallel).
  Core: `cargo test -p ohm-ecdsa`; node: `cargo test -p ohm-ecdsa-node`.
- `tests/e2e.rs` verifies real ECDSA signatures with `k256`'s verifier and
  asserts low-`s` normalization (BIP-62/EIP-2). Coverage: 2-of-3 and
  3-of-5 end-to-end, signing with only `t` parties, cheater identification
  in keygen (both §6.1 complaint branches), triples, presign, and sign,
  robust signing (`run_sign_robust`) with up to `t−1` cheaters, robust
  offline phases (§10.4): `run_presign_robust` completing with a tampered
  `v`-opening share or nonce point and `triples::generate_robust`
  reconstructing a cheating dealer's polynomial (bad product proofs still
  abort), key-independent presignatures (§8.7): one key-free pool
  signing for TWO independent keys (records bind online, verified under
  each `X`), single-use enforced through `KiPool` (atomic consume +
  duplicate-id rejection), and online-round cheaters identified (bad R1
  opening share, bad R2 signature share — `Error::Abort`, `Phase::Sign`),
  HD-tweak
  (additive key derivation, SPEC §9.4) signing, multiple presignatures over
  distinct messages, batched generation (§7.3/§8.5): batch triple
  correctness, `presign_batch` signing distinct messages, blame
  attribution inside a batch, and one tampered batch DLEQ proof among
  B ≥ 3 blamed to its prover via the aggregate-verification per-proof
  fallback (`TripleTamper::bad_product_proof_at`), packed mode (§7.4):
  packed triples multiplicative at every slot on the FY-minimal committee
  (t=2, B=2, n=5), B=1 packed degenerating to base mode on 2-of-3, packed
  presign+sign with distinct messages per slot (quorum `t+B−1 = 3`;
  signing with only `t = 2` shares fails `NotEnoughShares`), PT2 cheater
  blame (bad re-shared share, bad DLEQ proof), and `Error::InvalidParams`
  for undersized committees (2-of-3 with B=2), and §10.3 expel-and-restart composed with
  §10.4 (3-of-6 with one slack): `run_presign_with_restart` /
  `run_triples_with_restart` completing IN-ATTEMPT on continuable faults
  (bad `v`-opening share, bad re-share — no id poisoning, no renumbering),
  `run_presign_with_restart` restarting over the 5 survivors' original ids
  with the aborted id poisoned on a dealing fault, restart refusal at zero
  slack (2-of-3 — no silent `t`-lowering), `run_keygen_with_restart`
  completing over a renumbered committee, and `restart_committee` unit
  cases.
  Transport seam (§13.2): `tests/e2e.rs` runs keygen through
  `transport::drive_dkg` over `SimTransport` and signs end-to-end;
  `src/runtime/transport.rs` unit-tests accepted-set consistency (same broadcast
  set for all parties, p2p only to the addressee), driver key
  reconstruction, the §10.2 signing layer (signed roundtrip,
  wrong-key and tampered-payload rejection blaming the claimed sender,
  `drive_dkg_signed` honest run, blame-token `verify` positive and
  negative — forgery and wrong registry), and the canonical wire format
  (`wire_*`: `Encode`→`Decode` roundtrips for scalars/points — including
  the identity point — commitments, all `DkgMessage` variants, and signed
  envelopes; malformed-input rejection — truncation, non-canonical
  scalars, bad tags); `src/lib.rs` unit-tests
  `session_id` determinism and per-field domain separation. The node crate
  (`node/tests/mesh_keygen.rs`) runs the same keygen over real TCP:
  joint-key reconstruction through `MeshTransport`, a cheating dealer
  blamed with a verifying `BlameToken`, and forged/unknown-sender/
  malformed frames dropped while the honest keygen completes. M2 per-party
  drivers (`node/tests/party_mesh.rs`, thread-level with strict per-node
  key separation; `node/tests/process_demo.rs`, real child processes via
  `spawn-demo`): per-node keygen reconstructs the joint key (2-of-3 and
  3-of-5), a cheating dealer is named by EVERY node through the wire §6.1
  complaint/defense rounds, a false accuser is named by every node,
  per-node signing yields a valid low-`s` signature, and a wrong signature
  share is blamed by every node while the signature is still delivered.
  M3a per-node offline factory (`node/tests/party_offline.rs`,
  thread-level, and `node/tests/process_demo.rs`, process-level):
  per-node triples are multiplicative at the public commitments (2-of-3
  and 3-of-5), a bad DLEQ product proof / a bad re-shared share via the
  wire §6.1 rounds / a false accusation are each named consistently by
  every node (`BLAME triples`), a bad nonce point and a bad opening share
  are named in presign (`BLAME presign`), and the full arc
  keygen→presign→sign signs under the key the nodes' own keygen produced
  (the `--seeded` ceremony fallback stays covered).
  M3b persistence (`node/tests/persist.rs`, thread-level, and
  `node/tests/process_demo.rs`, process-level): the durable store
  survives drop/reopen with consumed ids staying consumed across a
  simulated crash (sign → "restart" on the same dir → second sign with
  the same id fails), duplicate inserts are rejected, the transcript
  archive decodes, and the F2/F6 blame tokens verify offline via the
  `auditor` subcommand (exit 0 = VALID; a tampered token is rejected).
  M3c mTLS (`node/tests/mesh_tls.rs`, thread-level, plus
  `node/src/net/tls.rs` unit tests and the `spawn-demo --tls` process
  test): the full arc runs over committee-pinned mTLS (thread- and
  process-level), an unpinned rogue peer cert is rejected in both
  handshake directions with every node failing closed (no plaintext
  fallback), a plaintext peer is dropped by a TLS listener that still
  completes keygen afterwards, and the pinning verifiers accept exactly
  the pinned cert only.
  Committee maintenance (§13.4): refresh
  preserves `X` while replacing every share and enables post-refresh
  presign+sign, outstanding presignatures are invalidated on refresh
  (`PresigStore::clear` — stale-id signing fails with `Error::PresigStore`),
  a cheating refresh dealer is blamed (§6.1 F2), re-sharing moves `x` from
  3-of-5 to a new 2-of-3 committee with fresh ids (and to an overlapping
  committee) with `X` unchanged and post-reshare signing, and both re-share
  fault classes blame the dealer (bad sub-share, `C_j.points[0]` mismatch).
- When adding protocol behavior, add both a positive-path test and, where
  applicable, a fault-injection test asserting the correct party is blamed
  (pattern: match on `Error::Abort { abort }` and check `abort.blamed`).

## Security considerations

- **Never weaken the verification checks.** Point-equality against Feldman
  commitments is the entire identifiable-abort mechanism; bypassing or
  "optimizing away" a `verify_share` / DLEQ check breaks the security
  model.
- **Presignatures are single-use and key-equivalent** (SPEC §8.6): `t`
  shares of the same presignature reveal the long-term key. They must
  never be reused or used across keys; `Drop` erasure uses `zeroize`
  (compiler-fenced volatile writes), the node crate adds `mlock`-wrapped
  secrets (`node/src/store/locked.rs`, fail-open with a warning) and AEAD
  sealing at rest (`node/src/store/seal.rs`); store rollback is DETECTED
  and refused at startup (`node/src/store/persist.rs` A4 journal +
  transcript cross-check) but not PREVENTED — a whole-directory restore
  stays undetectable, so HSM-backed storage and true rollback prevention
  (state outside the store directory) remain deployment concerns
  (SPEC §13.3).
- Commit-reveal exists to prevent nonce bias (rushing attacks); nonce
  uniformity is security-critical. Do not reorder or skip commit phases.
- `sim::make_rngs` is deterministic for tests; production must use an OS
  CSPRNG per party.
- `k256` provides constant-time curve arithmetic; keep new secret-dependent
  branching out of the code (verification paths may branch on public data
  only).
- The canonical wire decoders (`src/runtime/transport.rs` `Decode` impls)
  run on UNTRUSTED network input in the node crate: they must never panic,
  over-allocate on an untrusted length prefix, or accept non-canonical
  encodings. They are fuzzed with cargo-fuzz/libFuzzer — see
  `fuzz/README.md` (the workspace-excluded `fuzz/` crate is a dev tool
  only); keep new decoders panic-free and add them to the
  `decode_arbitrary` fuzz target.
- This is unaudited research code: do not add features that imply
  production readiness (networking, key storage, custody flows) without
  flagging the SPEC §13 disclaimers.
