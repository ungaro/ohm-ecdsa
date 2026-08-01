# `analysis/` — empirical probes for the proof's named heuristics

Dev-tool scripts (like `fuzz/`): not part of the library, not a proof.
They exist to pressure-test the one named heuristic in the
re-randomization lemma — **G1, the F-uniformity heuristic** of
`docs/proof/PROOF.md` §8.2.6 — at scales where full enumeration and
exponent fitting are feasible.

## `g1_probe.sage`

**What it tests.** The re-randomization lemma (PROOF.md §8.2) claims the
GS21 cube-root attack degrades to birthday `Θ(√q)` once the presignature
x-coordinate is re-randomized per `(M, τ)`, because the collision
condition becomes a collision search in

```
Φ(M, τ) = h(M) + F(H(sid‖id‖M‖τ‖X)·R)·τ
```

with `h` and the γ-hash independent random oracles and `F` the ECDSA
x-coordinate map. The gap G1 is precisely: *does the adversary's free
algebraic control of the tweak `τ` (free over all of 𝔽_q, SPEC §9.4) let
it beat a generic birthday search on `Φ`?* If a sub-`√q` strategy exists,
it lives in the τ-handle.

**Model fidelity.** secp256k1's own equation `y² = x³ + 7` over small
prime fields, chosen so `#E(GF(p))` is prime and `p < N` (the `p < N`
choice avoids the x-coordinate mod-N fold merging distinct coordinates —
on secp256k1 `|p − q|/q ≈ 2⁻¹²⁸`, so the fold is negligible there).
Both hashes are SHA-256-based ROs reduced mod N; `sid, id, X, R` are
fixed per run — only `(M, τ)` vary, matching the real attack. Work is
counted in `Φ`-evaluations (= RO budget `q_H`).

**Experiments.**

- *Aux checks* — the 2-to-1 genericity lemma (§8.2.6(ii), a theorem, so
  it must hold exactly; a failure means the harness is broken) and the
  F-distribution itself: support, statistical distance, χ², and the
  effective output-space size `N_eff = 1/Σp_v²`, the quantity that
  actually enters the birthday bound.
- *Exact table* (smallest field) — `Φ` enumerated over its full
  `N²`-point domain; collision statistics compared against a same-size
  random-function control.
- *Strategy suite* — eight adversarial-τ strategies covering every
  degenerate schedule named in §8.2.5: plain birthday (baseline),
  sign-then-find preimage, fixed-`M`, fixed-`τ`, two-block MITM,
  `τ′ = 0` grind, small-τ grid, adaptive chaining (memoryless ρ).
- *Positive control* — a Wagner 4-sum on the **affine** (constant-`r`,
  GS21) condition. The harness must recover the cube-root exponent there;
  if it does, its null results on the re-randomized `Φ` are meaningful
  rather than a reassuring green checkmark.

**Run.**

```
sage analysis/g1_probe.sage     # a few minutes; deterministic (fixed seed)
```

## Results (SageMath 10.9, full log in `g1_probe_results.txt`)

Four-prime ladder, `N` from 613 to 999,907. Verbatim fitted exponents
(`log₂ work` vs `log₂ N`):

| Strategy | Prediction | Fitted exponent |
|---|---|---|
| A — baseline birthday | 0.50 | 0.512 |
| B1 — preimage (sign-then-find) | 1.00 | 0.969 |
| B2 — fixed M (M = M′) | 0.50 | 0.475 |
| B3 — fixed τ (τ = τ′) | 0.50 | 0.492 |
| B4 — two-block MITM | 0.50 | 0.498 |
| B5a — τ′ = 0 grind | 1.00 | 0.996 |
| B5b — small-τ grid | 0.50 | 0.507 |
| B5c — adaptive chain | 0.50 | 0.530 |
| **Affine Wagner 4-sum (control)** | **0.33** | **0.305** |

Auxiliary results:

- 2-to-1 lemma: exact at every scale (max multiplicity 2, image exactly
  `(N−1)/2`).
- F-distribution: `N_eff/N = 0.500` at every scale — F is *not* uniform
  (support on half the field, SD 0.5), but the non-uniformity is a
  constant `√2` factor in work, not a structure. This is the quantitative
  content of "uniform enough."
- Exact table: colliding-pair ratio **1.0000** vs the random-function
  control — `Φ` is statistically indistinguishable from a random function
  at this scale.

**Reading.** Every degenerate τ-schedule is confirmed *worse* than
birthday, never better; no sub-birthday strategy exists at these scales;
and the control shows the harness would have found the cube-root
structure if `Φ` retained it. Small-scale empirical support for G1 —
cited as such, not as a proof, in `docs/proof/PROOF.md` §8.2.6.
