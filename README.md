# OHM-ECDSA — reference implementation

> ⚠️ **Unaudited research code for an unreviewed protocol draft.**
> Do not secure real assets with this code. See `SPEC.md` §11 (security
> analysis *sketch*) and §13 (disclaimers). §12 is engineering analysis,
> not legal advice.

Open honest-majority threshold ECDSA over secp256k1: **one-round online
signing**, **identifiable abort at every broadcast**, no Paillier, no OT,
no class groups, no range proofs — just Shamir + Feldman VSS + Beaver
triples + commit-reveal DKG. The full protocol is specified in
[`SPEC.md`](./SPEC.md), including the patent design-around analysis
(US 11,757,657 / Sepior and KU23 / Dfns; §12).

## Why this is useful

The two practical honest-majority threshold-ECDSA protocols are
patent-encumbered (Blockdaemon's TSM descends from Sepior; Dfns
describes its KU23 line as patented). An Apache-2.0 implementation with
an express patent grant changes what teams can build and operate
themselves:

* **Self-hosted institutional custody.** Run and modify your own MPC
  signing core — no per-wallet vendor fee, no closed-source black box in
  the security-critical path, and a public element-by-element
  design-around analysis (SPEC §12) instead of a known-encumbered
  construction (still get an FTO opinion for commercial use — §12.6).
  Same dynamic that made GG18-class open code explode the wallet
  ecosystem, but for the honest-majority regime.
* **On-chain multisig replacement.** The output is an ordinary ECDSA
  signature under an ordinary key: the threshold policy is invisible
  on-chain — no multisig contract to deploy or audit, lower fees, policy
  privacy, and it works on any ECDSA chain, including ones with limited
  or no scripting.
* **Regulated issuance (RWA / tokenized securities).** A 3-of-5 across
  legally accountable entities (issuer, custodian, auditor, HSM
  provider, recovery agent) enforces segregation of duties
  cryptographically. Identifiable abort turns "who touched this signing
  session" into a verifiable fact: every deviation yields a blame token
  checkable offline (SPEC §10.2, once the deployment transport signs
  messages per §13.1) — usable for SLAs, insurance, examiner reviews.
  HD tweaks (§9.4) derive unlimited per-fund or per-investor sub-keys
  locally — one key ceremony, not one per listing.
* **Long-lived keys with proactive security.** Epoch refresh (§13.4,
  implemented) re-randomizes all shares while the public key stays put:
  shares from different epochs do not combine, so compromise of up to
  `T−1` parties *per epoch* — not just over the key's lifetime — yields
  nothing. Committee changes re-share to new operators without changing
  the key.
* **Chain infrastructure.** The NEAR Chain Signatures / ICP pattern: a
  validator committee is the key holder, so a chain holds and moves
  native BTC/ETH/etc. without bridge contracts or wrapped-asset
  counterparties. OHM-ECDSA is an open signing layer for exactly that
  topology (NEAR runs the sibling cait-sith construction in production).
* **High-throughput hot operations.** Triples and presignatures are
  produced offline in bulk (batched or packed, §7.3/§7.4/§8.5); the
  online path is one broadcast round plus sub-millisecond local math
  (§13.5) — exchange-grade withdrawal signing without any single
  machine able to sign. Honest majority also buys optional guaranteed
  output delivery: blame the saboteur and *still ship the signature*
  (§10.4 — impossible in the dishonest-majority model).
* **Seedless consumer wallets.** 2-of-3 (device + service + recovery)
  with one-round signing: normal-wallet UX, and compromise of any
  single party yields nothing. Open license means no per-user royalties
  on MPC recovery.
* **Standardization.** NIST's threshold standardization (MPTS) is
  evaluating threshold ECDSA now — and standards bodies route around
  encumbered technology (that routing is how ECDSA itself replaced
  Schnorr). Publishing this spec as defensive prior art keeps the
  construction unpatentable by others and gives that process an
  unencumbered candidate.

Where this does **not** fit: customer-facing 2-of-2 or any deployment
without an honest-majority assumption — that is CGGMP/DKLs territory
(Paillier/OT-flavored). OHM-ECDSA targets settings where a vetted
committee is the natural trust model: custodians, consortia, validator
sets, issuers, auditors.

## Status

**Implemented**

* Commit-then-reveal Pedersen DKG with public complaint arbitration (SPEC §6)
* Feldman VSS — every opening verified by point equality, no NIZKs (§4.2)
* Chaum–Pedersen DLEQ proofs (§4.4)
* Beaver triple factory with verifiable degree reduction (§7)
* Key-dependent presignatures `([k⁻¹], [k⁻¹x], R)` (§8)
* One-round signing with per-share verification and identifiable abort (§9–§10)
* Additive key derivation / HD tweaks (§9.4)
* Robust continuation (§10.4): blamed parties are excluded and the honest
  majority still delivers — online signing (`run_sign_robust`), presign
  (`run_presign_robust`: openings via `open_robust`, `R` interpolated over
  the valid nonce points), and triple generation
  (`triples::generate_robust`: the cheater's committed re-sharing
  polynomial is publicly reconstructed)
* Single-use presignature store (§8.6): atomic consume, duplicate-id rejection
* Batch generation (§7.3/§8.5): one commit-reveal per batch for triples and
  presignatures (`generate_batch`, `presign_batch`), with §7.3 aggregate
  batch DLEQ verification (`dleq::verify_batch`) plus per-proof fallback
  for blame attribution
* Packed-Shamir batching (§7.4, Franklin–Yung): `B` triples in ONE pair of
  degree-`d` packed sharings with one DLEQ proof per party
  (`triples::generate_packed`), packed presignatures
  (`presign::presign_packed`) with a publicly-bound constant-pack key
  re-sharing in P4, and slot-point signing (`sign::combine_at`,
  `sim::run_sign_packed`) — the §7.4.3 trade-off: the online quorum
  becomes `T + B − 1` (availability only; privacy stays at `T−1`)
* Expel-and-restart (§10.3) composed with robust continuation (§10.4):
  every presign/triples attempt drives the robust variant, so continuable
  faults finish in-attempt (no id poisoning); only dealing-phase aborts
  expel the blamed and restart over the surviving committee —
  keygen/triples renumber freely, presign keeps the survivors' original ids
  (`run_keygen_with_restart`, `run_presign_with_restart`,
  `run_triples_with_restart`); the aborted sid/id is poisoned, and `t` is
  never silently lowered (zero-slack refusal points at §13.4)
* Committee maintenance (§13.4), public key unchanged: proactive refresh
  (zero-constant re-sharing over the same committee, `run_refresh`) and
  committee-change re-sharing to a new id set with public old-share binding
  (`C_j.points[0] == EvalCom(A[x], j)`, `run_reshare`); `PresigStore::clear`
  invalidates outstanding presignatures on epoch change (§8.6)
* Explicit transport seam (§13.1/§13.2): `Envelope` per-message contract,
  sync `Transport` trait, `SimTransport` reference implementation; keygen
  delivery runs through the seam (`transport::drive_dkg`)
* Single-threaded reference orchestrator + fault-injection hooks

**Not yet** (roadmap): production transport over the seam (mTLS + echo
broadcast + per-message signatures — the `transport` module is the
contract, not an implementation), serde wire format, key rotation
(§13.4 — re-DKG with a new `X`), audit.

## Quick start

```bash
cargo test
```

Runs 18 unit tests and 42 integration tests: end-to-end 2-of-3 and 3-of-5
signatures verified by `k256`'s ECDSA verifier, subset signing with only
`T` parties, cheater identification in keygen (both §6.1 complaint
branches), triples, presign, and sign, robust signing with up to `T−1`
cheaters, robust presign/triples continuation with correct blame (§10.4),
expel-and-restart composed with the robust path (§10.3+§10.4, 3-of-6):
continuable faults complete in-attempt, dealing-phase aborts restart with
id poisoning, zero-slack refusal, presignature single-use enforcement,
HD-tweak signing, batched triple/presignature generation, packed mode
(§7.4: slot-multiplicative packed triples on the FY-minimal committee,
packed presign+sign with the `T+B−1` online quorum, PT2 cheater blame,
undersized-committee rejection), committee
maintenance (§13.4: refresh preserving `X`, presignature invalidation on
epoch change, re-sharing to a new committee with dealer-blame fault
injection), and keygen executed through the explicit transport seam
(`transport::drive_dkg` over `SimTransport`).

```bash
cargo run --release --example perf
```

prints the SPEC §13.5 wall-clock rows (keygen, triples, presign, sign,
batched variants, batch-DLEQ aggregate vs individual verification) as
medians over repeated runs — `std::time::Instant` only, no extra
dependencies.

## Layout

Sources are layered under `src/` — `primitives/` (SPEC §4 building
blocks), `protocol/` (§6–§9, §13.4), `runtime/` (transport seam,
orchestration, policy) — and every module is re-exported flat from the
crate root (`ohm_ecdsa::shamir`, `ohm_ecdsa::sim`, …).

| Module | SPEC § | Contents |
|---|---|---|
| `primitives/shamir` | 4.1, 7.4.1 | Shamir sharing, Lagrange interpolation (at 0 and at arbitrary points), packed slot points and constant-pack polynomials |
| `primitives/vss` | 4.2, 7.4.3 | Feldman commitments, homomorphic commitment ops (mixed-length zero-padding), arbitrary-point commitment evaluation |
| `primitives/dleq` | 4.4 | Chaum–Pedersen DLEQ (triple product proofs) |
| `primitives/open` | 4.6, 7.4, 10.4 | verified-opening subprotocol (structural identifiable abort), robust variant, arbitrary-point openings with explicit quorum |
| `protocol/dkg` | 6, 6.1, 7.3, 7.4 | commit-reveal DKG (message-oriented), complaint arbitration, batch VSS at any uniform degree (packed dealing, explicit-polynomial dealing), committee support (§10.3 restarts) |
| `protocol/triples` | 7, 7.3, 7.4, 10.4 | triple factory (joint random + degree reduction), robust reconstruction of a cheater's re-sharing polynomial, batched, packed (Franklin–Yung: constant-pack re-sharing + slot-binding checks), `*_with_committee` variants |
| `protocol/presign` | 8, 8.5, 10.4, 7.4.3 | presignatures, tweak derivation, tamper hooks, robust continuation, batched, packed (degree-`d` throughout, constant-pack key binding in P4), `*_with_committee` variants |
| `protocol/sign` | 9, 10.4, 7.4.3 | share computation, verified combine, robust combine, slot-point combine with explicit quorum (packed mode) |
| `runtime/store` | 8.6 | single-use presignature store (atomic consume, `clear` for epoch changes) |
| `runtime/policy` | 10.3 | `restart_committee` — expel-and-restart committee computation (never lowers `t`) |
| `protocol/refresh` | 13.4 | committee maintenance with `X` unchanged: proactive zero-constant refresh (`refresh`) and re-sharing to a new committee with public old-share binding (`reshare`), `ReshareTamper` hooks |
| `runtime/transport` | 4.7, 10.2, 13.1, 13.2 | transport seam: `Envelope` message contract, sync `Transport` trait, `SimTransport` reference impl, `drive_dkg` transport-driven keygen driver |
| `runtime/sim` | 4.7, 10.3, 13.2 | reference orchestrator (keygen routes through the `transport` seam), §10.3 restart wrappers |

## Usage

```rust
use ohm_ecdsa::{sim, Params};

let params = Params::new(3, 2).unwrap();            // 2-of-3, honest majority
let mut rngs = sim::make_rngs(params.n, 0xC0FFEE);  // OS CSPRNG in production

let keys    = sim::run_keygen(&params, b"key/0", &mut rngs).unwrap();
let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None).unwrap();

// any T parties sign; one round; low-s normalized
let sig = sim::run_sign(&params, &presigs[..2], b"hello threshold", None).unwrap();
```

## Security notes

* Presignature records are **single-use** and their shares are
  **key-equivalent** (SPEC §8.6) — store and erase them like key shares.
* Every broadcast is verified against public commitments; a wrong share
  aborts with the sender's identity (`Error::Abort`).
* Secret-holding structs erase on `Drop` via `zeroize` (compiler-fenced;
  production additionally needs mlock, ideally HSMs; §13.3).

## Patent notes

The construction uses only 1989–2007 public-domain building blocks plus
openly published presignature algebra, and is engineered to practice no
element of US 11,757,657 B2 claim 1 and to differ materially from KU23
(element-by-element analysis: SPEC §12). Open-source ≠ patent-free; get
an FTO opinion for commercial custody use.

## License

Apache-2.0 (with its express patent grant). See `LICENSE`.
