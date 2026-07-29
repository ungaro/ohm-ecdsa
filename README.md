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
* Robust signing (§10.4): blamed shares are excluded and the signature is
  still delivered from the remaining honest shares (`run_sign_robust`)
* Single-use presignature store (§8.6): atomic consume, duplicate-id rejection
* Batch generation (§7.3/§8.5): one commit-reveal per batch for triples and
  presignatures (`generate_batch`, `presign_batch`)
* Single-threaded reference orchestrator + fault-injection hooks

**Not yet** (roadmap): async transport with echo broadcast, serde wire
format, packed-Shamir batching (§7.4), proactive refresh (§13.4), robust
continuation in the offline phases (§10.4), audit.

## Quick start

```bash
cargo test
```

Runs 9 unit tests and 19 integration tests: end-to-end 2-of-3 and 3-of-5
signatures verified by `k256`'s ECDSA verifier, subset signing with only
`T` parties, cheater identification in keygen (both §6.1 complaint
branches), triples, presign, and sign, robust signing with up to `T−1`
cheaters, presignature single-use enforcement, HD-tweak signing, and
batched triple/presignature generation.

## Layout

| Module | SPEC § | Contents |
|---|---|---|
| `shamir` | 4.1 | Shamir sharing, Lagrange interpolation |
| `vss` | 4.2 | Feldman commitments, homomorphic commitment ops |
| `dleq` | 4.4 | Chaum–Pedersen DLEQ (triple product proofs) |
| `open` | 4.6, 10.4 | verified-opening subprotocol (structural identifiable abort), robust variant |
| `dkg` | 6, 6.1, 7.3 | commit-reveal DKG (message-oriented), complaint arbitration, batch VSS |
| `triples` | 7, 7.3 | triple factory (joint random + degree reduction), batched |
| `presign` | 8, 8.5 | presignatures, tweak derivation, tamper hooks, batched |
| `sign` | 9, 10.4 | share computation, verified combine, robust combine |
| `store` | 8.6 | single-use presignature store (atomic consume) |
| `sim` | 4.7, 13.2 | reference orchestrator (models broadcast) |

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
* Secret-holding structs scrub on `Drop` (best effort — production needs
  real zeroization, mlock, ideally HSMs; §13.3).

## Patent notes

The construction uses only 1989–2007 public-domain building blocks plus
openly published presignature algebra, and is engineered to practice no
element of US 11,757,657 B2 claim 1 and to differ materially from KU23
(element-by-element analysis: SPEC §12). Open-source ≠ patent-free; get
an FTO opinion for commercial custody use.

## License

Apache-2.0 (with its express patent grant). See `LICENSE`.
