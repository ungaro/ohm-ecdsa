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
  presignatures (`generate_batch`, `presign_batch`)
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
contract, not an implementation), serde wire format, packed-Shamir
batching (§7.4), key rotation (§13.4 — re-DKG with a new `X`), audit.

## Quick start

```bash
cargo test
```

Runs 14 unit tests and 36 integration tests: end-to-end 2-of-3 and 3-of-5
signatures verified by `k256`'s ECDSA verifier, subset signing with only
`T` parties, cheater identification in keygen (both §6.1 complaint
branches), triples, presign, and sign, robust signing with up to `T−1`
cheaters, robust presign/triples continuation with correct blame (§10.4),
expel-and-restart composed with the robust path (§10.3+§10.4, 3-of-6):
continuable faults complete in-attempt, dealing-phase aborts restart with
id poisoning, zero-slack refusal, presignature single-use enforcement,
HD-tweak signing, batched triple/presignature generation, committee
maintenance (§13.4: refresh preserving `X`, presignature invalidation on
epoch change, re-sharing to a new committee with dealer-blame fault
injection), and keygen executed through the explicit transport seam
(`transport::drive_dkg` over `SimTransport`).

## Layout

| Module | SPEC § | Contents |
|---|---|---|
| `shamir` | 4.1 | Shamir sharing, Lagrange interpolation (at 0 and at arbitrary points) |
| `vss` | 4.2 | Feldman commitments, homomorphic commitment ops |
| `dleq` | 4.4 | Chaum–Pedersen DLEQ (triple product proofs) |
| `open` | 4.6, 10.4 | verified-opening subprotocol (structural identifiable abort), robust variant |
| `dkg` | 6, 6.1, 7.3 | commit-reveal DKG (message-oriented), complaint arbitration, batch VSS, committee support (§10.3 restarts) |
| `triples` | 7, 7.3, 10.4 | triple factory (joint random + degree reduction), robust reconstruction of a cheater's re-sharing polynomial, batched, `*_with_committee` variants |
| `presign` | 8, 8.5, 10.4 | presignatures, tweak derivation, tamper hooks, robust continuation, batched, `*_with_committee` variants |
| `sign` | 9, 10.4 | share computation, verified combine, robust combine |
| `store` | 8.6 | single-use presignature store (atomic consume, `clear` for epoch changes) |
| `policy` | 10.3 | `restart_committee` — expel-and-restart committee computation (never lowers `t`) |
| `refresh` | 13.4 | committee maintenance with `X` unchanged: proactive zero-constant refresh (`refresh`) and re-sharing to a new committee with public old-share binding (`reshare`), `ReshareTamper` hooks |
| `transport` | 4.7, 10.2, 13.1, 13.2 | transport seam: `Envelope` message contract, sync `Transport` trait, `SimTransport` reference impl, `drive_dkg` transport-driven keygen driver |
| `sim` | 4.7, 10.3, 13.2 | reference orchestrator (keygen routes through the `transport` seam), §10.3 restart wrappers |

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
