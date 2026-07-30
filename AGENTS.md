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
auditor, M3c optional committee-pinned mTLS via rustls/rcgen).

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
  `rustls-pki-types` for the OPTIONAL mTLS layer (`node/src/tls.rs`);
  `time` is pinned (`=0.3.36`) transitively via rcgen because newer
  releases need edition2024 toolchains, and the committed `Cargo.lock`
  pins `base64ct 1.6.0` / `zeroize 1.8.2` for the same reason — the whole
  tree builds with the workspace MSRV 1.75 (verify with
  `cargo +1.75.0 check --workspace --all-targets`). `Cargo.lock` is
  committed — keep it reproducible.
- Parties are numbered `1..=n` (`PartyId = usize`); evaluation point 0 is
  reserved for the secret.
- Fiat–Shamir / hashing domain separation uses versioned tags in
  `lib.rs::tags` (e.g. `b"OHM-ECDSA/v0.1/dkg-commit"`).

## Build and test commands

Commands run workspace-wide by default (both crates); scope to the core
with `-p ohm-ecdsa` and to the node crate with `-p ohm-ecdsa-node`.

- `cargo build` / `cargo build --workspace` — build the library and the
  node crate.
- `cargo test -p ohm-ecdsa` — runs 29 unit tests (inline `#[cfg(test)]`
  modules in `src/lib.rs`, `src/primitives/{shamir,vss,open,dleq}.rs`,
  `src/protocol/{dkg,triples}.rs`, `src/runtime/{policy,transport}.rs` —
  including the `wire_*` canonical `Encode`→`Decode` roundtrip and
  malformed-input tests),
  45 integration tests in `tests/e2e.rs`, and 5 example smoke tests in
  `tests/examples.rs` (each narrative example is run via `cargo run
  --example` and checked for its guarantee lines). All 79 pass at the
  time of writing.
- `cargo test -p ohm-ecdsa-node` — 44 tests: 3 M1 tests in
  `node/tests/mesh_keygen.rs` (3 nodes on localhost ephemeral ports:
  keygen over `MeshTransport` reconstructs the joint key, a cheating
  dealer is blamed with a verifying `BlameToken`, forged/unknown-sender/
  malformed frames are dropped while the honest keygen completes),
  6 M2 thread-level tests in `node/tests/party_mesh.rs` (per-node keygen
  2-of-3 and 3-of-5, cheating dealer and false accuser each named by
  every node via the wire §6.1 rounds, per-node signing with valid low-s
  signature, wrong sign share blamed while the signature still delivers),
  8 M3a thread-level tests in `node/tests/party_offline.rs` (per-node
  triples multiplicative at the public commitments 2-of-3 and 3-of-5,
  bad DLEQ proof / bad re-share via wire complaints / false accusation
  each named consistently, bad nonce point and bad opening share named
  in presign, full arc keygen→presign→sign under the nodes' own key),
  12 M2/M3a/M3b/M3c process-level tests in `node/tests/process_demo.rs`
  (real child processes via `spawn-demo`: honest full arc, sign cheater
  named by the other two processes with the signature still delivered,
  DKG cheater and false accuser named by all three — full arc and
  `--seeded` fallback — bad DLEQ proof and bad re-share named as
  `BLAME triples`, bad nonce point and bad opening share named as
  `BLAME presign`, `--persist` full arc leaving fsync'd consume
  tombstones and decodable transcripts, a `bad-deal` token file
  verified by the `auditor` subcommand and a tampered copy rejected,
  the `--tls` full arc over mTLS),
  9 M3b tests in `node/tests/persist.rs` (the durable store
  survives drop/reopen, consumed ids stay consumed across a simulated
  crash, duplicate inserts rejected live/consumed/on reopen, wrong-key
  reopen rejected, stray `.tmp` files dropped, transcript dedup +
  decode, F2/F6 tokens verified offline and tampering/wrong-registry
  rejected, crash-recovery: sign → "restart" on the same store dir →
  second sign with the same id fails),
  3 M3c thread-level tests in `node/tests/mesh_tls.rs` (the full arc
  over committee-pinned mTLS, an unpinned rogue peer cert rejected in
  both handshake directions with every node failing closed — no
  plaintext fallback — and a plaintext peer dropped by a TLS listener
  that still completes keygen afterwards), and 3 M3c unit tests in
  `node/src/tls.rs` (pinning verifiers accept exactly the pinned cert
  and reject any other; inconsistent own/pinned material rejected).
- `cargo run -p ohm-ecdsa-node -- spawn-demo [--cheat-node K --cheat C]
  [--seeded] [--persist] [--tls] [--delay-ms D]` — M3a demo: 3 child
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
  per-party cert files for manual runs).
  `cargo run -p ohm-ecdsa-node -- auditor TOKEN_FILE COMMITTEE_FILE` is
  the M3b offline §A.4 evidence check (exit 0 = VALID).
  `cargo run -p ohm-ecdsa-node -- m1-demo [-- PORT_BASE]` is the original
  M1 orchestrator demo.
- `cargo run --release -p ohm-ecdsa-node --example mesh_perf` — M2
  latency benchmark over the real mesh: keygen and online-sign wall time
  for 2-of-3 and 3-of-5, localhost and with per-link artificial delay.
- `cargo run --release --example perf` — `examples/perf.rs` wall-clock
  micro-benchmarks for the SPEC §13.5 rows (std `Instant` only, no extra
  dependencies).
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
transport companion in `node/`. `lib.rs` declares the three layer
modules and re-exports each building-block module FLAT
(`pub use primitives::{dleq, open, shamir, vss};` etc.), so the public
paths `ohm_ecdsa::shamir`, `ohm_ecdsa::sim`, … are unchanged by the
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
| `protocol/dkg.rs` | 6, 6.1, 7.3, 7.4 | Commit-reveal Pedersen DKG, message-oriented (`DkgInstance` with `start`/`start_committee`/`start_with_secret` (fixed-secret deals for §13.4)/`reveal`/`finalize`/`defend`, `DkgBcast1`/`DkgBcast2`/`DkgP2P`); §6.1 complaint resolution (`resolve_complaint`), `DkgTamper` fault-injection hook; `DkgBatchInstance` deals `B` polynomials in ONE commit-reveal session (batch VSS, §7.3: R1 hash covers the concatenation of all `B` vectors, P2P carries `B` shares) at ANY uniform degree — `start_committee_with_degree` (random degree-`d` packed sharings, §7.4.2 PT1) and `start_with_polys` (explicit polys with constrained slot values, e.g. the §7.4.3 P4 constant-pack key re-sharing). Instances run over a `Committee` — an explicit, possibly non-contiguous id set for §10.3 restarts |
| `protocol/triples.rs` | 7, 7.3, 7.4, 10.4 | Beaver triple factory with verifiable degree reduction (`generate`, `generate_with_tamper`), `TripleTamper` fault-injection hook; `generate_robust` (§10.4) publicly reconstructs a cheating dealer's committed re-sharing polynomial from the `≥ t` valid shares and continues (excluding a dealer is impossible: `γ` needs `2t−1` product points); bad DLEQ product proofs still abort; `generate_batch` is structurally per-batch (§7.3): one commit-reveal for all `2B` secrets, one re-sharing pass carrying all `B` vectors + `B` DLEQ proofs per party; T3 verifies each prover's `B` proofs AGGREGATELY via `dleq::verify_batch` (§7.3 optional optimization — identical accept/reject to individual verification, per-proof fallback keeps F3 per-triple blame; `generate_batch_with_tamper` + `TripleTamper::bad_product_proof_at` fault-inject one indexed batch proof). `generate_packed` (§7.4.2, Protocol 7.2′ — Franklin–Yung) produces `B` triples from ONE pair of degree-`d` packed sharings (`d = t + B − 2`, slots `e_b = -(b)`; requires `n ≥ 2t + 2B − 3`, §7.4.1, else `Error::InvalidParams`): PT1 deals `⟦α⟧_pack`/`⟦β⟧_pack` in one commit-reveal (`joint_random_packed`), PT2 re-shares each party's ONE local product with a CONSTANT-PACK polynomial (value `h_j = α_j·β_j` at every slot) plus ONE DLEQ proof, PT3 adds a slot-binding check (`EvalCom(C_j, e_b) == C_j.points[0]`, dealer blamed) before the per-slot Lagrange recombination — outputs are constant-pack `⟦γ_b⟧` (value at every slot, so packed Beaver consumption opens consistently at `e_b`); per the crate convention `TripleShare.a`/`.b` hold the party's packed-share scalar (same for every slot). `joint_deal` deals explicit per-party polys in one commit-reveal and returns the revealed commitments for public slot-binding checks. `*_with_committee` variants run over an explicit id set |
| `protocol/presign.rs` | 8, 8.5, 8.7, 10.4, 7.4.3 | Key-dependent presignatures; `KeyShare` (alias of `DkgOutput`), `Presignature`, `PresignTamper` fault-injection hooks (`bad_nonce_point`, `bad_open_share`, `triple_tamper` — forwarded to the first triple session's dealing phase); `presign_robust` (§10.4) runs openings through `open_robust`, filters and blames bad `R_j` (interpolating `R` over the valid senders), expels blamed parties, and returns records for the survivors plus the blame list; `presign_batch` generates `B` records per session (§8.5). `presign_packed` (§7.4.3) consumes packed triples (two `generate_packed` sessions of `B` slots) and deals `⟦u⟧_pack`/`⟦a⟧_pack` plus each party's constant-pack re-sharing of `λ_j·x_j` in ONE commit-reveal (dealt polys publicly bound to `A[x]` by slot-point `EvalCom` equality — the key must enter P4 as a constant packed vector because `⟦x⟧`'s degree-`(t−1)` polynomial evaluates to `p_x(e_b) ≠ x` at slots `b ≥ 1`); openings interpolate at the slot points with quorum `d + 1 = t + B − 1`; output records are degree-`d` sharings. `presign_ki` (§8.7, optional KEY-INDEPENDENT mode) runs P1–P3 verbatim with NO P4 — takes no key shares (P1–P3 never touch `x`), consumes ONE triple (P4's triple moves online) — and outputs `KiPresignature { id, index, r, big_r, u_share, u_com }` (NOT key-equivalent: `t` pool shares reveal no key; still strictly single-use; binds to a key only at signing time). `*_with_committee` variants run over an explicit id set (`keys[k]`/`rngs[k]` positional in `ids`, `keys[k].index` checked) |
| `protocol/sign.rs` | 9, 10.4, 7.4.3, 8.7 | `sign_share` (local) + `combine` (verified interpolation, low-`s` handled by caller); `combine_robust` filters and blames bad shares and still interpolates; `combine_at` (§7.4.3) interpolates at an explicit point with an explicit quorum — packed presignatures combine at the record's slot point with quorum `t + B − 1` (per-share point-equality verification unchanged). KI online signing (§8.7): `ki_z_share`/`ki_z_com` (party `j`'s `z`-share and the public `A[z]` from a fresh triple and the opened R1 masks — EXACTLY the §8 P4 formula run online; `u·x` is never computed directly, §12), `sign_share_ki` (`s_j = m·u_j + r·z_j`), `combine_ki` (verified against `m·A[u] + r·A[z]`, same blame semantics as `combine`), `KiSignTamper` fault-injection hooks (`bad_open_share`, `bad_sign_share`) |
| `protocol/refresh.rs` | 13.4 | Committee maintenance, `X` unchanged: `refresh` — proactive zero-constant re-sharing over the same committee (dealt via `DkgInstance::start_with_secret`; per-dealer zero-constant check on the revealed vectors; new shares `x'_j = x_j + Σ_i z_i(j)`); `reshare` — re-sharing to a NEW committee (each old party deals `x_j` over the new id set; public binding check `C_j.points[0] == EvalCom(A[x], j)`; new shares `x'_m = Σ_j λ_j^S · p_j(m)`, new commitment `A'[x] = Σ_j λ_j^S · C_j`); `ReshareTamper` fault-injection hooks (`bad_deal`, `bad_commitment`). Both assert `A'[x].points[0] == X`; both mandate `PresigStore::clear` on epoch change (§8.6) |
| `runtime/store.rs` | 8.6, 8.7 | `PresigStore`: per-party single-use presignature store bound to one key (atomic `consume`, duplicate-id rejection, `clear` for the §13.4 epoch-change invalidation); `KiPool` (§8.7): KEY-FREE pool for key-independent records — same §8.6(1) single-use discipline (atomic consume, duplicate-id rejection) without the one-key binding, and NO epoch-change `clear` mandate (KI records carry no key-equivalent material) |
| `runtime/policy.rs` | 10.3 | `restart_committee`: expel-and-restart committee computation — removes blamed ids, refuses (never lowers `t`) when the remainder would drop below `2t−1` (below the bound, use §13.4 re-sharing — `protocol/refresh.rs`) |
| `runtime/transport.rs` | 4.7, 10.2, 13.1, 13.2 | The explicit transport seam: `Envelope<M>` (exactly the per-message fields a production transport signs — sid/phase/round/from/to/payload), object-safe sync `Transport<M>` trait modeling the LOGICAL rounds (§2.2), `DkgMessage` payload enum, `SimTransport` reference in-process impl (delivers identical accepted sets — echo-broadcast consistency), `drive_dkg` transport-driven DKG driver. §10.2/§13.1 signing: `Encode`/`Decode` (THE canonical wire format: length-prefixed, no serde — implemented for `DkgMessage`, the DKG bcast/p2p structs, `FeldmanCommitment`, the scalar/point/`Signature` primitives, and `Envelope`/`SignedEnvelope` themselves; other message types implement it as needed), `SignedEnvelope<M>` (sender ECDSA signature over the canonical encoding, domain-separated under `tags::TRANSPORT_SIGN`), `SigningTransport` (wraps any `Transport<SignedEnvelope<M>>` — signs on send, verifies accepted sets against the party key registry, a forged/tampered envelope is `Error::Abort` blaming the claimed sender), `BlameToken` (§A.4 evidence: abort + offending signed share envelope + dealer commitment; `verify(party_keys)` is the auditor's offline check), `drive_dkg_signed` (returns `SignedDriveError { error, token }` — `drive_dkg` stays the unsigned entry point for `sim::run_keygen*`); triples/presign orchestration still drives DKG instances internally (incremental pattern in the `transport` module docs) |
| `runtime/sim.rs` | 4.7, 10.3, 13.2, 7.4.3 | Single-threaded reference orchestrator: `run_keygen` / `run_keygen_with_tamper` (message delivery routes through `transport::SimTransport` + `transport::drive_dkg`), `run_presign` / `run_presign_robust` / `run_presign_batch` / `run_presign_packed` (§7.4.3), `run_sign` / `run_sign_stored` / `run_sign_robust` / `run_sign_packed` (§7.4.3 — slot-point interpolation, quorum `t + B − 1`), `run_sign_ki` / `run_sign_ki_pooled` (§8.7 — the 2-round online flow: R1 generates a FRESH triple and opens `δ = ⟦u⟧−⟦α⟧`, `ε = ⟦x⟧−⟦β⟧` through `open::open`; R2 computes `z_j` locally and broadcasts `s_j`, verified via `sign::combine_ki`; fail-fast only — no §10.4 robust variant), §10.3 expel-and-restart wrappers `run_keygen_with_restart` / `run_presign_with_restart` / `run_triples_with_restart` (poisoned sid/id per retry; blame in original ids; keygen/triples retries renumber, presign retries keep original ids; the presign/triples wrappers drive the §10.4 ROBUST variants per attempt, so continuable faults complete in-attempt without poisoning — only dealing-phase aborts cascade to restart), §13.4 wrappers `run_refresh` / `run_reshare` (caller must clear presignature stores on epoch change), `make_rngs` (deterministic `StdRng` seeds — tests only) |
| `node/` (crate `ohm-ecdsa-node`) | 4.7, 10.2, 13.1, 13.2 | Transport companion (localhost scale, `std::net` blocking threads, NO async runtime — rustls since M3c, tokio never): `src/wire.rs` (length-prefixed framing of the core's canonical `Encode`/`Decode` format; `WireMessage<M>` = original signed envelope or echoer-signed §4.7 echo, generic over the payload; `verify` against the party key registry), `src/mesh.rs` (`Node<M>`: listener + full-mesh connections + reader threads; first-echo-per-slot rule; unknown sender/bad signature/misrouted p2p dropped + logged; self-echo loopback for the M2 per-node acceptor; config-driven send delay for benchmarks; `bind_tls` wraps every connection in M3c mTLS — same frames inside the TLS stream), `src/tls.rs` (M3c, SPEC §13.1: OPTIONAL mTLS with certificates PINNED to the committee — `CommitteeTls` own cert/key + pinned per-party cert set, TLS 1.3 only, rustls ring provider, blocking `StreamOwned` over `TcpStream`; outgoing handshakes accept ONLY the expected peer's pinned cert (TLS identity == PartyId), incoming accept any pinned committee cert and are attributed to the matching party; NO PKI/system roots, NO plaintext fallback; rcgen self-signed certs are the dev/test stand-in for a deployment PKI; `setup --tls` / `spawn-demo --tls` / `node --tls CERT KEY --pinned DIR`; envelope signatures stay ON regardless), `src/transport.rs` (`MeshTransport` — M1 — implementing the core `Transport<SignedEnvelope<DkgMessage>>`: echo-broadcast acceptor — accept on `⌈(n+1)/2⌉` echoes from parties OTHER than the sender, dedup by `(sid, phase, round, from)`; blocking round collection with a generous timeout that returns the partial set and lets the DKG fail closed), `src/party.rs` (M2/M3a: `PartyNode` — holds ONLY its own transport key/id and runs only its own logic; per-node keygen §6 with the §6.1 complaint subprotocol on the wire — signed `Complaints`/`Defenses` broadcast rounds adjudicated identically at every node, factored as `joint_vss` + a shared wire `complaint_round` helper — per-node §7.2 triple driver (T1 two `joint_vss` instances, T2 `FeldCommit(g_j)` + ONE DLEQ product proof broadcast + P2P re-shares, T3 proof checks ⇒ F3 blame and re-share checks ⇒ wire §6.1 complaints, Lagrange combine), per-node §8 presign driver (two triple sessions + ⟦u⟧/⟦a⟧ `joint_vss`, fail-fast point-equality openings δ/ε/v/δ′/ε′ and nonce-point `R_j == EvalCom(A[k], j)` checks ⇒ F5 blame, `v=0`/`r=0` ⇒ `Error::ZeroValue` retry-with-fresh-id; §10.4 robust continuation deliberately stays in the core's sim), and per-node §9/§10.4 signing: broadcast `sign_share`, point-equality verification, robust combine, low-s; `NodePayload` wire enum; `Cheat` fault injection — `BadDeal`/`FalseAccuse` (VSS), `BadProductProof`/`BadReshare` (triples), `BadNoncePoint`/`BadOpenShare` (presign), `BadSignShare`), `src/seed.rs` (the ceremony writing per-party SECRET seed files + a PUBLIC committee file — the `--seeded` fallback for presignature distribution; transport keys come from the seed files in both modes), `src/main.rs` (`node`/`setup`/`spawn-demo` process separation + `m1-demo` + the M3b `auditor`; spawn-demo runs the FULL ARC keygen→presign→sign under the fresh key by default, `--persist` gives each child a per-node `--data-dir`, `--tls` runs the arc over M3c mTLS), `src/persist.rs` (M3b: `DiskPresigStore` — the §8.6 durable single-use presignature store, write-tmp-rename + fsync per insert, the consume tombstone fsync'd BEFORE the record is handed out so a kill/restart can never sign twice with the same presignature; `Archive` — the §4.7 accepted-envelope transcript + `aborts.log`; `BlameEvidence` token files for the fault classes with wire evidence — F2 dealt shares, F6 sign shares; other classes logged `token: none`; `audit_token` — the §A.4 offline verifier reusing the core's `BlameToken::verify` where the shape fits), `examples/mesh_perf.rs` (latency benchmark). M1 is the reference-orchestration pattern (one process holds all transport keys); M2/M3a enforce key separation by construction. M3c (optional mTLS) is done; remaining hardening (reconnection, clean shutdown, DoS) is open |

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
- Rust defaults: `std`, no `unsafe`, standard 4-space rustfmt style.

## Testing instructions

- Run the full suite with `cargo test --workspace` (~15 s total; the
  M3c fail-closed TLS test waits out one 2 s round timeout by design).
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
  `node/src/tls.rs` unit tests and the `spawn-demo --tls` process
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
  (compiler-fenced volatile writes), but `mlock`/HSM-backed storage remain
  deployment concerns (SPEC §13.3).
- Commit-reveal exists to prevent nonce bias (rushing attacks); nonce
  uniformity is security-critical. Do not reorder or skip commit phases.
- `sim::make_rngs` is deterministic for tests; production must use an OS
  CSPRNG per party.
- `k256` provides constant-time curve arithmetic; keep new secret-dependent
  branching out of the code (verification paths may branch on public data
  only).
- This is unaudited research code: do not add features that imply
  production readiness (networking, key storage, custody flows) without
  flagging the SPEC §13 disclaimers.
