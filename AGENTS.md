# AGENTS.md — OHM-ECDSA

Guidance for AI coding agents working in this repository. Assumes no prior
knowledge of the project.

## Project overview

`ohm-ecdsa` is a Rust **library crate** (not a binary) implementing
OHM-ECDSA: an open, honest-majority threshold ECDSA protocol over secp256k1.
It is a **reference implementation of an unreviewed protocol draft** —
unaudited research code, not for securing real assets (see `SPEC.md` §13).

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
- Dependencies: `k256` (0.13, features `ecdsa` + `sha256`) for all curve /
  ECDSA arithmetic, `sha2`, `thiserror`, `rand` (0.8). No serde, no async,
  no networking. `Cargo.lock` is committed — keep it reproducible.
- Parties are numbered `1..=n` (`PartyId = usize`); evaluation point 0 is
  reserved for the secret.
- Fiat–Shamir / hashing domain separation uses versioned tags in
  `lib.rs::tags` (e.g. `b"OHM-ECDSA/v0.1/dkg-commit"`).

## Build and test commands

- `cargo build` — build the library.
- `cargo test` — runs 18 unit tests (inline `#[cfg(test)]` modules in
  `src/lib.rs`, `src/primitives/{shamir,vss,open,dleq}.rs`,
  `src/protocol/{dkg,triples}.rs`, `src/runtime/{policy,transport}.rs`) and
  42 integration tests in `tests/e2e.rs`. All 60 pass at the time of
  writing.
- `cargo run --release --example perf` — `examples/perf.rs` wall-clock
  micro-benchmarks for the SPEC §13.5 rows (std `Instant` only, no extra
  dependencies).
- `cargo fmt` / `cargo clippy` — standard toolchain; no custom config
  files, use defaults.

There is no CI configuration, no deployment process, and no release
pipeline in the repo.

## Code organization

Single crate, one module per protocol building block, grouped into three
layers mirroring the spec (`src/`, ~5400 lines total): `primitives/`
(SPEC §4 building blocks), `protocol/` (§6–§9, §13.4), `runtime/`
(transport/orchestration/policy). `lib.rs` declares the three layer
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
| `protocol/presign.rs` | 8, 8.5, 10.4, 7.4.3 | Key-dependent presignatures; `KeyShare` (alias of `DkgOutput`), `Presignature`, `PresignTamper` fault-injection hooks (`bad_nonce_point`, `bad_open_share`, `triple_tamper` — forwarded to the first triple session's dealing phase); `presign_robust` (§10.4) runs openings through `open_robust`, filters and blames bad `R_j` (interpolating `R` over the valid senders), expels blamed parties, and returns records for the survivors plus the blame list; `presign_batch` generates `B` records per session (§8.5). `presign_packed` (§7.4.3) consumes packed triples (two `generate_packed` sessions of `B` slots) and deals `⟦u⟧_pack`/`⟦a⟧_pack` plus each party's constant-pack re-sharing of `λ_j·x_j` in ONE commit-reveal (dealt polys publicly bound to `A[x]` by slot-point `EvalCom` equality — the key must enter P4 as a constant packed vector because `⟦x⟧`'s degree-`(t−1)` polynomial evaluates to `p_x(e_b) ≠ x` at slots `b ≥ 1`); openings interpolate at the slot points with quorum `d + 1 = t + B − 1`; output records are degree-`d` sharings. `*_with_committee` variants run over an explicit id set (`keys[k]`/`rngs[k]` positional in `ids`, `keys[k].index` checked) |
| `protocol/sign.rs` | 9, 10.4, 7.4.3 | `sign_share` (local) + `combine` (verified interpolation, low-`s` handled by caller); `combine_robust` filters and blames bad shares and still interpolates; `combine_at` (§7.4.3) interpolates at an explicit point with an explicit quorum — packed presignatures combine at the record's slot point with quorum `t + B − 1` (per-share point-equality verification unchanged) |
| `protocol/refresh.rs` | 13.4 | Committee maintenance, `X` unchanged: `refresh` — proactive zero-constant re-sharing over the same committee (dealt via `DkgInstance::start_with_secret`; per-dealer zero-constant check on the revealed vectors; new shares `x'_j = x_j + Σ_i z_i(j)`); `reshare` — re-sharing to a NEW committee (each old party deals `x_j` over the new id set; public binding check `C_j.points[0] == EvalCom(A[x], j)`; new shares `x'_m = Σ_j λ_j^S · p_j(m)`, new commitment `A'[x] = Σ_j λ_j^S · C_j`); `ReshareTamper` fault-injection hooks (`bad_deal`, `bad_commitment`). Both assert `A'[x].points[0] == X`; both mandate `PresigStore::clear` on epoch change (§8.6) |
| `runtime/store.rs` | 8.6 | `PresigStore`: per-party single-use presignature store bound to one key (atomic `consume`, duplicate-id rejection, `clear` for the §13.4 epoch-change invalidation) |
| `runtime/policy.rs` | 10.3 | `restart_committee`: expel-and-restart committee computation — removes blamed ids, refuses (never lowers `t`) when the remainder would drop below `2t−1` (below the bound, use §13.4 re-sharing — `protocol/refresh.rs`) |
| `runtime/transport.rs` | 4.7, 10.2, 13.1, 13.2 | The explicit transport seam: `Envelope<M>` (exactly the per-message fields a production transport signs — sid/phase/round/from/to/payload), object-safe sync `Transport<M>` trait modeling the LOGICAL rounds (§2.2), `DkgMessage` payload enum, `SimTransport` reference in-process impl (delivers identical accepted sets — echo-broadcast consistency), `drive_dkg` transport-driven DKG driver. `sim::run_keygen*` routes through `SimTransport` + `drive_dkg`; triples/presign orchestration still drives DKG instances internally (incremental pattern in the `transport` module docs) |
| `runtime/sim.rs` | 4.7, 10.3, 13.2, 7.4.3 | Single-threaded reference orchestrator: `run_keygen` / `run_keygen_with_tamper` (message delivery routes through `transport::SimTransport` + `transport::drive_dkg`), `run_presign` / `run_presign_robust` / `run_presign_batch` / `run_presign_packed` (§7.4.3), `run_sign` / `run_sign_stored` / `run_sign_robust` / `run_sign_packed` (§7.4.3 — slot-point interpolation, quorum `t + B − 1`), §10.3 expel-and-restart wrappers `run_keygen_with_restart` / `run_presign_with_restart` / `run_triples_with_restart` (poisoned sid/id per retry; blame in original ids; keygen/triples retries renumber, presign retries keep original ids; the presign/triples wrappers drive the §10.4 ROBUST variants per attempt, so continuable faults complete in-attempt without poisoning — only dealing-phase aborts cascade to restart), §13.4 wrappers `run_refresh` / `run_reshare` (caller must clear presignature stores on epoch change), `make_rngs` (deterministic `StdRng` seeds — tests only) |

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

- Run the full suite with `cargo test` (fast: < 2 s integration).
- `tests/e2e.rs` verifies real ECDSA signatures with `k256`'s verifier and
  asserts low-`s` normalization (BIP-62/EIP-2). Coverage: 2-of-3 and
  3-of-5 end-to-end, signing with only `t` parties, cheater identification
  in keygen (both §6.1 complaint branches), triples, presign, and sign,
  robust signing (`run_sign_robust`) with up to `t−1` cheaters, robust
  offline phases (§10.4): `run_presign_robust` completing with a tampered
  `v`-opening share or nonce point and `triples::generate_robust`
  reconstructing a cheating dealer's polynomial (bad product proofs still
  abort), HD-tweak
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
  set for all parties, p2p only to the addressee) and driver key
  reconstruction; `src/lib.rs` unit-tests `session_id` determinism and
  per-field domain separation. Committee maintenance (§13.4): refresh
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
