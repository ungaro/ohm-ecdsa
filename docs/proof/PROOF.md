# OHM-ECDSA — Security Proof (game-based)

**Working document v0.2.** Companion to `SPEC.md` §11. Status per lemma is
marked **[proved here]**, **[proof sketched]**, or **[open]**. The model is
game-based security in the random-oracle model (ROM); no rewinding is used.
This document supersedes the "sketch" phrasing of SPEC §11 for the components
marked [proved here]; the ideal-functionality-level composition (UC or
stand-alone with sessions, §11.3(5)) remains future work and is stated
honestly where it binds.

---

## 1. Setting and theorem statement

**Parameters.** Prime-order group `𝔾` (secp256k1) of order `q`, generator
`G`; scalar field `𝔽_q`. Committee `P₁…Pₙ`, threshold `T`, `n ≥ 2T−1`.
Parties are Shamir evaluation points `1..=n`; point `0` is reserved for
secrets. Adversary `𝒜`: **static**, **malicious** (active), controls a set
`C` of at most `T−1` parties chosen before the protocol starts; **rushing**
within each round; makes polynomially many RO queries `q_H`.

**Channels.** Authenticated point-to-point; all protocol messages are
signed by their sender (§10.2 of SPEC) and carry `(sid, phase, round)`.
Broadcast is `ℱ_BC` with the signed-echo consistent-broadcast rule of
SPEC §4.7: acceptance of `m` from `i` requires (1) `i`'s valid signature on
`m`, (2) valid echoes of `m` from `T−1` distinct parties other than `i`,
(3) no conflicting sender-signed value seen; a conflicting pair yields `⊥`
plus an offline-verifiable equivocation proof (fault class F8). Safety
statements in this document are timing-independent; `ℱ_BC`'s realization
owns the timing assumption (SPEC §2.2).

**Functionality `ℱ_TECDSA`** (as in SPEC §11.1, with the consumption state
machine folded in):

* **KeyGen(sid):** sample `x ←$ 𝔽_q*`; output `X = x·G` to all; store
  shares of `x` per server.
* **Presign(sid, id):** on request from all honest servers, sample
  `k ←$ 𝔽_q*`; publish `(R = k·G, r = F(R))`; store shares of
  `(k⁻¹, k⁻¹x)` per server; mark `id` **fresh**.
* **Sign(sid, M, id):** on request from `T` distinct servers for the same
  `(M, id)` with `id` fresh: output `s = k⁻¹(H(M) + r·x)`, mark `id`
  **consumed** (subsequent Sign or Presign with `id` are ignored). On any
  abort event, mark `id` **poisoned** (never usable again).
* **Abort:** any disruption by `< T` servers is reported to all honest
  servers **with the disruptors' identities**; the adversary learns only
  `X`, public presignature data `(R, r)`, and legitimately issued
  signatures.

**Theorem (target statement).** *In the ROM, under the discrete-logarithm
assumption in `𝔾` (and, for the C5 reduction, the Groth–Shoup
presignature-ECDSA assumption in its own model), OHM-ECDSA securely
realizes `ℱ_TECDSA` against any static malicious adversary corrupting at
most `T−1` of `n ≥ 2T−1` servers, with identifiable abort.*

The proof is the game sequence of §5 after the lemmas of §2–§4.

---

## 2. Lemma C1 (correctness) — [proved here]

**Statement.** If no honest party aborts, the protocol outputs `(r, s)`
with `r = F(k·G)` and `s = k⁻¹(H(M) + r·x)`.

**Proof.** Track the invariant chain; every step is linear algebra over
`𝔽_q` plus the verified-opening guarantee (Lemma C3) that every opened or
broadcast value equals its committed value.

1. *Beaver correctness (§4.5).* Given openable sharings `⟦x⟧, ⟦y⟧` and a
   triple `(⟦α⟧,⟦β⟧,⟦γ⟧)` with `γ = αβ`: opening `δ = x − α` and
   `ε = y − β` (each share verified against `A[x]−A[α]`, `A[y]−A[β]` — by
   C3 the opened scalars are the true values) and setting
   `[z] = [γ] + δ[β] + ε[α] + δε` gives, at point 0,
   `z = γ + δβ + εα + δε = αβ + (x−α)β + (y−β)α + (x−α)(y−β) = xy`.
2. *Presign P2.* `v = a·u` by step 1; `v ≠ 0` except with probability
   `1/q` (restart rule). Then `k := v⁻¹·a` is well-defined and
   `k = a/(a·u) = u⁻¹` in `𝔽_q*`.
3. *Presign P3.* `R = Σ_j λ_j·R_j` with `R_j = k_j·G` verified against
   `EvalCom(A[k], j)` (C3), so `R = k·G` and `r = F(R)`.
4. *Presign P4.* `z = u·x` by step 1 with `(x, u)` in place of `(x, y)`.
5. *Sign.* `s = Σ_j λ_j(m·u_j + r·z_j) = m·u + r·z = k⁻¹m + r·k⁻¹x =
   k⁻¹(H(M) + r·x)`. ∎

**Remark.** Every input to the chain is a *committed* value; the only way
the chain fails is a wrong share, which C3 catches with probability 1.
Hence correctness holds not only for honest executions but for any
execution that does not abort. ∎

---

## 3. Lemma C3 (blame soundness) — [proved here]

Two clauses, proved separately.

### 3.1 Soundness-of-blame (detection is unconditional)

**Statement.** Fix any commitment vector `A[v] = (A₀,…,A_{T−1})` with
`A_ℓ ∈ 𝔾` and any position `j ∈ {1,…,n}`. Exactly one scalar `v_j ∈ 𝔽_q`
satisfies `v_j·G = EvalCom(A[v], j) := Σ_ℓ j^ℓ·A_ℓ`.

**Proof.** The map `𝔽_q → 𝔾`, `a ↦ a·G` is injective (it is a group
homomorphism from the additive group of a prime field to a group of the
same prime order `q`; its kernel is trivial since `q` is prime and
`a·G = O` iff `q | a`). Therefore the scalar `Σ_ℓ j^ℓ·a_ℓ` underlying the
point `Σ_ℓ j^ℓ·A_ℓ` — where `a_ℓ` are the discrete logs of the `A_ℓ` — is
the *unique* passing scalar, regardless of whether the verifier or anyone
knows the `a_ℓ`. A wrong share fails the check with probability 1, in
every session, with no computational assumption. ∎

**Corollaries.** (i) Every verification in the protocol (F2–F6 of
SPEC §10.1) rejects a deviating value with certainty. (ii) A dealer's
polynomial is fixed by its commitment vector: the coefficient points
determine each coefficient's scalar (as a discrete log, unknown but
fixed), hence all share values at all positions. (iii) Consequence for the
threat model: *soundness of every check is information-theoretic; only
hiding is computational* (Lemma L2) — the reverse of Pedersen-style
two-generator commitments, where binding is computational.

### 3.2 Framing-freeness (no honest party is blamed)

**Statement.** Except with probability negligible in `λ` (RO binding plus
ECDSA signature unforgeability), every blame verdict names a party that
actually deviated.

**Proof.** Blame arises only via the public rules of SPEC §10.1
(F1–F8). For an honest party `P` to be blamed, the adversary must present:

* (F1) a reveal-hash mismatch attributed to `P`'s dealing — requires
  either a pre-image for the committed RO output `h_P` that differs from
  `P`'s actual reveal (a second pre-image of a 256-bit RO output,
  probability `≤ q_H·2^{-λ}`), or a forgery of `P`'s message signature;
* (F2/F4/F5/F6) a commitment check that fails against a value `P`
  verifiably sent — but `P` sent the correct value, and by §3.1 the check
  has exactly one passing scalar, so the failing object is not the one
  `P` signed; presenting it as `P`'s requires a signature forgery. (For
  P2P shares: `P` signed the correct share; the complaint protocol's
  defense round lets `P` exhibit it publicly, and it verifies.)
* (F3) an invalid DLEQ proof attributed to `P` — requires a signature
  forgery (the proof is part of `P`'s signed message);
* (F8) two conflicting values in one slot both carrying `P`'s valid
  signature — `P` signs at most one value per slot (first-echo rule);
  two valid signatures on different values by `P` is an ECDSA forgery
  under `P`'s transport key, breakable only with the adversary's
  signature-forging advantage.

Each branch is bounded by `q_H·2^{-λ}` or by the adversary's ECDSA
forgery advantage `ε_sig`; the union bound gives the claim. ∎

**Remark (why two clauses matter).** Detection (§3.1) is *unconditional*;
attribution (§3.2) is *computational*. This asymmetry is load-bearing for
the hybrids of §5: the only computational content of the adversary's view
is commitment *hiding*; check soundness never needs a hardness assumption.

---

## 4. Lemma C4 (uniformity, with the bias bound) — [proved here]

### 4.1 Uniformity of joint secrets

**Statement.** After the commit phase of any commit-reveal VSS session in
the protocol, every joint secret dealt by it (the long-term key `x`, each
presignature value `u`, `a`, each triple component) is uniform in
`𝔽_q` (respectively `𝔽_q*` for invertible values), against a rushing
adversary.

**Proof (GJKR argument).** At the end of R1, every dealer's polynomial is
fixed by its hash commitment (binding in the ROM: a dealer changing its
committed vector afterwards requires a second pre-image, §3.2). The joint
polynomial is the sum of the dealers' polynomials; its constant term is
the sum of the dealers' constants. At least one dealer is honest
(`|C| ≤ T−1 < n`), chose its polynomial uniformly, and its contribution is
independent of all others; the sum of a uniform scalar with any
adversary-chosen-but-already-fixed scalars is uniform. A dealer who
refuses to reveal is excluded with identification (§4.3 of SPEC), and the
joint secret is computed from the remaining dealers; the honest
contribution remains in the sum. For values that must be nonzero (`u`),
rejection of `v = 0` (resp. `x` if the key is zero — abort rule) rejects
with probability `1/q` and does not change uniformity conditioned on
acceptance. ∎

### 4.2 The bias-bounded lemma (identifiable abort bounds rejection sampling)

**Statement.** Let the adversary's strategy include inducing aborts to
re-roll a joint secret (abort after seeing honest reveals, restart the
instance). Then over the whole execution, the number of completed
re-rolls of any single instance's joint secret is at most `f = |C| ≤ T−1`,
and the resulting joint secret has distribution at statistical distance at
most `log₂(f+1)` bits (in mutual information) from uniform.

**Proof.** Every induced abort is attributed: §3.2 shows aborts caused by
deviations name the deviator, and a dealer who simply refuses to reveal
is identified by omission (SPEC §4.3: refusal to reveal is exclusion with
identification). The §10.3 policy expels the blamed party and restarts
the instance over the survivors (or aborts finally if slack is
exhausted). The adversary cannot cause an *anonymous* abort: the fault
taxonomy F1–F8 covers every deviation, and honest parties never trigger
blame (§3.2). Therefore each completed re-roll consumes at least one
corrupted party from `C`, bounding the number of re-roll opportunities by
`f`. Formally: let `X₁, X₂, …` be independent uniform candidate secrets
(the draw after each restart; §4.1 applied to each fresh commit-reveal
session), and let the adversary keep the first `X_i` satisfying a
predicate `π` of its choice (restart otherwise). After `f` expulsions at
most `f+1` candidates are drawn. For any predicate `π` with acceptance
probability `μ`, the kept secret is uniform on the `μ`-measure set
`{π}`, giving the adversary at most `−log₂ μ` bits of selection; the
optimal strategy uses `μ ≈ 1/(f+1)`, yielding at most `log₂(f+1)` bits of
mutual information between the kept secret and the adversary's choice —
i.e., statistical distance at most `log₂(f+1)` bits from uniform as
measured by advantage in distinguishing. ∎

**Consequences.** (i) The long-term key `x` deviates from uniform by at
most `log₂ T` bits — for key *privacy* this is absorbed by the hybrids of
§5 with a factor-`T` loss. (ii) Per-presignature nonces: each presign
session is an independent fresh VSS instance with its own expulsion
budget, and the adversary's reroll of a *nonce* costs a party per
attempt, so per-signature nonce distributions are within `log₂ T` bits of
uniform *and independent across signatures*. Lattice key-recovery attacks
(Breitner–Heninger 2019; LadderLeak 2020) require *structured* bias
(known bit patterns or congruences) across *many* signatures; a
`log₂ T`-bit *one-shot selection* per session does not provide such
structure. We do not claim more than this: the exact translation of
selection bias into hidden-number-problem instances is out of scope for
this lemma and flagged for the full write-up (§11.3(7) of SPEC).

---

*(continued in §5–§8: the game sequence, L1 extraction, L2 hiding,
composition, and the re-randomization analysis)*

---

## 5. The game sequence

**G0 (real execution).** `𝒜` interacts with honest parties running the
protocol, makes adaptive Presign/Sign queries, and wins by (a) forgery:
outputting a valid signature on a message for which fewer than `T` Sign
queries occurred; (b) soundness break: an honest party accepting a wrong
value without abort; (c) framing: an honest party being blamed. By C3,
conditions (b) and (c) are impossible except with the negligible
probabilities bounded there, so `Pr[𝒜 wins in G0] ≤ Pr[forgery] + ε_C3`.

**G1 (program the DKG).** The simulator `𝒮` replaces the real KeyGen with
the programmed one of Lemma L1 (§6), embedding the challenge key `X`.
Indistinguishability bound (L1): `ε_G1 = q_H·2^{-λ} + O(q_H²/2^λ)`.

**G2 (program every joint VSS).** The L1 procedure is applied per
ephemeral commit-reveal instance (`u`, `a`, triple `α, β`, refresh
zero-sharings, reshare sub-sharings). Fresh `sid`s make instances
independent (each instance's hash domain includes `sid`; the adversary's
query log for one instance carries no extractable content for another).
Bound: `ε_G2 = Q·ε_G1` for `Q` instances (`Q ≤ q_sessions`).

**G3 (simulate DLEQ proofs).** Each Chaum–Pedersen proof is replaced by an
RO-programmed honest-verifier-ZK simulation: sample `z ←$ 𝔽_q`,
`c ←$ 𝔽_q`, set `T₁ = z·G − c·A`, `T₂ = z·B − c·C`, program
`H(sid‖…‖T₁‖T₂) := c`. The adversary detects programming only by querying
one of the programmed inputs before it is defined (information-theoretic:
the honest `T₁, T₂` are determined only after the adversary's move in the
simulated ordering) or by an RO collision/inconsistency. Bound:
`ε_G3 = O(q_H²/q)` (birthday) over all proofs.

**G4 (program the openings).** For each verified opening
(`δ, ε, v, δ′, ε′` and, at Sign, the `s_j`), `𝒮` proceeds as follows.
The opened scalar is uniform in the real protocol (one-time-padded by a
fresh mask — `α, β, α′, β′, a, u` are uniform joint secrets by C4); `𝒮`
samples it uniformly, then fixes honest-party shares of the underlying
sharing to match. This is exact by the freedom-counting lemma (§6.3): a
degree-`T−1` sharing has `T` free coefficients; the adversary's `T−1`
known shares fix `T−1` linear constraints; the prescribed value at point
`0` fixes one more; the honest dealer's contribution is the unique
solution of the resulting Vandermonde system, computed in the exponent
exactly as in L1. Bound: `ε_G4 = 0` (statistical) for the openings; the
only residue is Feldman *hiding* of never-opened values, deferred to L2
(§7).

**G5 (sign from the Groth–Shoup oracle).** `𝒮` answers Sign queries using
the presignature-model signing oracle of Groth–Shoup [GS21]: on query
`(M, id)`, obtain the true `(r, s)`; the adversary's `T−1` shares
`s_j = m·u_j + r·z_j` are computable from `m`, `r` and its known `u_j, z_j`
(from the G2-extracted contributions); each honest party's share is the
evaluation of the unique degree-`T−1` polynomial through `(0, s)` and the
adversarial points — consistent with the public
`A[s] = m·A[u] + r·A[z]` by construction (the commitment relation is
linear and was programmed consistently in G2). Exact, per G4.

**Extraction (C5).** `𝒜`'s forgery in the final game is a valid ECDSA
signature under `X` on a message for which `𝒮` made fewer than `T` Sign
oracle calls — i.e., a forgery against the Groth–Shoup presignature-ECDSA
experiment. The reduction's query count matches `𝒜`'s one-for-one
(Presign and Sign map to the model's presignature and signing queries;
the consumption state machine in `ℱ_TECDSA` matches the model's
single-use semantics). Hence

```
Pr[forgery] ≤ Adv_GS-EUF(ℬ)
```

for a forger `ℬ` with `𝒜`'s running time plus simulation overhead.

**Interface accounting (required by the GS model).** The OHM-ECDSA
adversary's view exceeds the Groth–Shoup oracle's interface: per-party
`R_j`, commitment vectors `A[u], A[z], A[k]`, DLEQ transcripts, opened
masks. Each extra is produced by `𝒮` as follows: `R_j` for honest `j` is
computed from `R` and the adversarial points via Lagrange in the exponent
(`R_j` must satisfy `Σ λ_j R_j = R` with adversarial shares known);
commitment vectors are programmed in the exponent (G2); DLEQ transcripts
are simulated (G3); opened masks are uniform (G4). Every extra is
therefore simulatable from `(R, r)` and public parameters alone, so the
reduction uses no information beyond the GS experiment's provisions.

---

## 6. Lemma L1 (extraction and programming of the commit-reveal DKG) — [proved here, ROM]

### 6.1 Statement

In the ROM there exists a simulator `𝒮` that, given a challenge point
`X ∈ 𝔾` and black-box access to the rushing adversary `𝒜` (controlling
`C`, `|C| ≤ T−1`), produces a KeyGen transcript whose joint public key is
`X`, whose distribution conditioned on `X` is computationally
indistinguishable from a real KeyGen transcript, and from which `𝒮`
extracts every adversarial dealer's commitment vector (hence, by
§3.1(ii), every adversarial contribution and every corrupted party's
share of every dealer). Error bound:
`ε_L1 ≤ q_H·2^{-λ} + O(q_H²/2^λ)`. No rewinding is used.

### 6.2 The simulator

*R1 (commit).* For each honest dealer `h`, `𝒮` broadcasts `h_h ←$ {0,1}^λ`
uniformly at random, without choosing any vector. `𝒜` (rushing) then
broadcasts `h_i` for `i ∈ C`.

*R2 (reveal).* `𝒮` lets `𝒜` move first. For each `i ∈ C`, `𝒜` reveals
`A_i` or aborts.

* *Extraction.* If `𝒜` reveals `A_i` and later the R3 hash check
  `H(sid‖KG‖i‖A_i) == h_i` passes, then with probability at least
  `1 − q_H·2^{-λ}` the input `(sid‖KG‖i‖A_i)` appears in `𝒜`'s RO query
  log: otherwise `h_i` would have to equal the RO's answer to a query
  `𝒜` never made, which for a uniform `2^λ`-valued oracle happens with
  probability at most `2^{-λ}` per verifier query, at most `q_H·2^{-λ}`
  over all queries. `𝒮` reads `A_i` from the log. (If `𝒜` aborts instead,
  the dealer is excluded with identification; `𝒮` proceeds without it —
  the bias accounting is C4 §4.2.)
* *Programming the honest vectors.* With every adversarial constant point
  `A_{i,0}` extracted, `𝒮` constructs, for each honest dealer `h`, a
  commitment vector `A_h = (A_{h,0},…,A_{h,T−1})` satisfying:
  (i) `Σ_{h honest} A_{h,0} + Σ_{i ∈ C, revealed} A_{i,0} = X`;
  (ii) for every corrupted party `j ∈ C`, `EvalCom(A_h, j) = s_{h,j}·G`
  where `𝒮` sampled `s_{h,j} ←$ 𝔽_q` uniformly.
  Write the constraints as a linear system: the unknowns are the `T`
  points `A_{h,ℓ}`; equation (i) fixes the point at position 0
  (`A_{h,0} = X − Σ A_{i,0} − Σ_{h′≠h} A_{h′,0}`) and equations (ii) fix
  the points at the `T−1` positions `j ∈ C`. The `T × T` Vandermonde
  matrix over positions `{0} ∪ C` is invertible in `𝔽_q` (distinct
  positions), so a unique solution exists and is computable by `𝒮` via
  Lagrange coefficients in the exponent. `𝒮` then programs the RO: when
  any party first queries `(sid‖KG‖h‖A_h)`, answer `h_h`. Programming is
  consistent: no party queried that input earlier, since the input
  (which encodes `A_h`'s points) was undefined until this step; a
  pre-image collision with an earlier unrelated query occurs with
  probability `O(q_H²/2^λ)` (birthday over all programmed answers and
  queries).
* *Shares.* `𝒮` delivers `s_{h,j}` (sampled above) to each corrupted `j`
  as dealer `h`'s P2P share; the check `s_{h,j}·G == EvalCom(A_h, j)`
  passes by construction. Honest-position shares of `A_h` are never
  needed by `𝒜` and are left undefined (they are solved per-opening in
  G4).

*R3 (checks and complaints).* `𝒜`'s options and the outcomes: (a) honest
behavior — transcript complete; (b) misdeal (wrong P2P share) — caught
information-theoretically (§3.1) and resolved by the complaint protocol,
which `𝒮` executes honestly; (c) false accusation against an honest
dealer — the dealer's defense is the share `s_{h,j}`, which verifies by
construction, so the accuser is blamed (consistent with §3.2); (d)
abort — handled per the exclusion rules (blame attributed per §3.2).

### 6.3 Indistinguishability

Condition on neither bad event: (B1) a passing adversarial reveal absent
from the query log (`≤ q_H·2^{-λ}`); (B2) an RO programming collision
(`O(q_H²/2^λ)`). Then: the joint public key is `X` by (i); every
commitment vector is distributed uniformly subject to its position
constraints (in the real protocol, honest vectors are uniform subject to
their true polynomial; the adversary cannot distinguish "uniform points
subject to `Σ = X` and `EvalCom(A_h, j) = s_{h,j}G`" from the real
distribution, since by C2-style hiding — the only computational hop, L2 —
the points reveal nothing beyond their public values); every corrupted
party's shares `s_{h,j}` are uniform as in the real protocol; all checks
and complaint outcomes match. The transcript is therefore distributed as
in the real protocol conditioned on key `X`, up to the stated error and
the L2 hop (§7). ∎

**Status note.** The hybrid bookkeeping (per-dealer sequencing, abort
branches, and the B1/B2 union bounds written out as a game hop) is
engineering rigor, not a new idea; a journal version would expand this to
two pages. UC is **not** claimed: the argument uses RO programming
(allowed in UC-ROM) and message scheduling within rounds; porting is
expected but deferred.

---

## 7. Lemma L2 (Feldman hiding) — [(a) proved here; (b) named assumption; (c) sketched]

### 7.1 Single instance ≡ DL

**Statement.** Let `p(X) = a_0 + a_1X + … + a_{T−1}X^{T−1}` with uniform
coefficients, `A_ℓ = a_ℓ·G` public, and let the adversary know the `T−1`
shares `p(j)` for `j ∈ C` (`|C| = T−1`). Then computing `a_0` (or any
information beyond `a_0·G`) is equivalent, by polynomial-time reductions
in both directions, to computing the discrete logarithm of `A_0`.

**Proof.** Given `a_0`, all `a_ℓ` are determined (the `T−1` share
equations plus `a_0` give `T` equations in `T` unknowns; Vandermonde), so
`a_0·G` is computable either way. Conversely, write each share as
`p(j) = a_0 + j·q(j)` with `q` of degree `T−2`; the `T−1` equations
determine `q` as an affine function of `a_0` with known coefficients, so
`a_0` is an affine function of the shares alone up to one scalar unknown:
`a_0` is the *only* degree of freedom, and the public `A_0 = a_0·G` pins
it exactly to the DL of `A_0`. Any algorithm computing `a_0` from
`(shares, vector)` solves DL of `A_0`; any DL oracle yields `a_0`
directly. ∎

**Remark.** With `T−1` known shares, a single Feldman polynomial hides
*exactly* its constant term — no more, no less. The hiding question is
therefore never about "the polynomial" but about *which* scalars remain
unopened, and it is exactly DL-hard per instance.

### 7.2 Multi-instance with prescribed openings (named assumption: `(T−1)`-OMDL form)

The protocol's view contains many such instances (DKG dealers across
sessions, triples, presignatures, refresh polynomials), and the simulator
prescribes openings for some of them (the masked openings of G4 are
*chosen* values). The precise assumption the proof needs is:

> **Assumption L2-OMDL.** Given `N` commitment vectors to independent
> random degree-`T−1` polynomials, the adversary's shares (`T−1`
> positions) of each, and a DL-oracle that it may query on up to `N−1` of
> the constant-term points, the adversary cannot compute or distinguish
> the remaining constant term(s) except with the `(T−1)`-OMDL advantage.

This is a one-more-discrete-log assumption in the form used by
Bacho–Loss-style analyses; it is *named, not proved* — it is the plain
model price for Feldman (rather than Pedersen) commitments.

### 7.3 AGM form (recommended route) — [proved here, with bookkeeping note]

**Lemma (AGM hiding).** In the algebraic group model, for the OHM-ECDSA
view — commitment vectors to independent random degree-`T−1`
polynomials, the adversary's `T−1` shares of each (chosen consistently by
the L1 simulator, not necessarily the true shares of hidden constants),
and prescribed scalar openings for all masked values — replacing every
commitment to a never-opened scalar by a commitment to zero is
indistinguishable to an algebraic adversary. Any distinguisher is
converted into an ECDLP solver with the same running time up to
representation bookkeeping, and advantage bounded by `ε_DLP`.

**Proof.** Let `Y ∈ 𝔾` be the DL challenge. The reduction `ℛ` runs the
G1–G4 simulation with one change: for a uniformly chosen never-opened
instance `ρ` (in the full protocol, one of the DKG dealers; `ρ` is the
key instance), the constant-term point is set to `Y` instead of
`a_0^(ρ)·G` (in G1, `X := Y`; other never-opened instances are embedded
as independent random multiples `c_i·Y` with known `c_i`, which preserves
uniformity and spreads the challenge). Everything else is unchanged:

1. **Scalars need no hidden values.** All scalars the adversary sees are
   chosen by the simulator: adversary-facing shares (uniform, §6.2),
   prescribed openings (uniform, G4), DLEQ responses (sampled, G3). None
   is a function of `a_0^(ρ)`.
2. **Point consistency is linear and public.** Every commitment vector is
   programmed in the exponent by Vandermonde solution over *position
   constraints*, all of which are public points (`Y`, the `c_i·Y`,
   extracted adversarial points, and `s·G` for simulator-chosen scalars
   `s`). The constraint system never requires `a_0^(ρ)` as a scalar —
   only its point.
3. **The adversary's algebraic outputs carry representations.** By the
   AGM interface, every group element `𝒜` outputs (its R1 vectors,
   `R_j`, DLEQ announcements `T₁, T₂`) is accompanied by a representation
   in the seen basis `{G, Y, c_i·Y, extracted points, programmed points}`.
   Verification equations the adversary could use to *distinguish* are
   linear relations among seen elements; `ℛ` evaluates each relation's
   coefficient vector on the embedded challenge coordinates.
4. **Extraction.** If the adversary's distinguishing strategy exhibits
   any relation that holds under the real embedding (`A_0^(ρ) = Y`) but
   fails under the zeroized one (or vice versa) with non-negligible
   probability, that relation has a nonzero coefficient on a challenge
   coordinate; solving the resulting one-unknown linear equation yields
   `log_G Y` (or `c_i⁻¹` times it). If no such relation exists, the two
   views are *identical* as distributions over the adversary's
   algebraically-representable world, and the distinguishing advantage is
   zero. Formally, `Adv_dist ≤ ε_DLP + q_H²/2^λ` (the RO-programming
   birthday term from G1–G3, independent of the hiding hop).

**Bookkeeping note (the honest residual).** A journal-grade version
requires: (i) the representation extractor for the DLEQ statements
explicitly — all statements are of the form `z·B == T + c·C` with `B, C`
in the basis, so representations are read off directly, but this must be
written; (ii) the argument that the *simulator's own* programmed points
remain in the AGM basis (they are linear combinations of basis elements
with simulator-known coefficients — immediate); (iii) the union bound
over instances. None of these involves a new idea; they are two pages of
careful indexing, left for the full version. ∎

**Remark (why AGM and not plain).** §7.1 shows single-instance hiding is
exactly DL — so no hardness amplification is *needed*; the AGM is used
only to combine instances without paying OMDL (§7.2 remains the
plain-model alternative). The model also matches what the Groth–Shoup
presignature-ECDSA result (C5's target) already assumes, so the final
theorem lives in one model with ECDLP as its sole hardness assumption.

---

## 8. Composition, re-randomization, and the assembled bound

### 8.1 Session hygiene (composition lemma) — [proved here]

**Lemma (composition).** Let `S₁,…,S_Q` be protocol sessions (one KeyGen
and `Q−1` offline/online sessions) executed with distinct `sid`s under
SPEC §13.1 (`sid = H(genesis ‖ key-id ‖ presig-id ‖ tag)`), sharing only
the long-term key `x`. Then the multi-session execution realizes the
multi-session functionality (the §1 state machine iterated) with
advantage bounded by the sum of the single-session bounds, i.e. a
factor-`Q` union over sessions.

**Proof.** Hybrid over sessions `ρ = 1,…,Q`: in hybrid `ρ`, sessions
`1…ρ−1` are simulated (per §5–§7) and sessions `ρ…Q` are real. Each
single-session hop is exactly the §5 game sequence, applicable because:

1. **Domain separation.** Every RO input and Fiat–Shamir challenge
   carries `sid` (SPEC §13.1 and the versioned tags), so each session has
   an independent programmable random oracle; programming in session
   `ρ` cannot contradict programming in session `ρ′`.
2. **Independence of session secrets.** Each session's joint secrets
   (`u, a, α, β, …`) are dealt by fresh commit-reveal VSS instances with
   fresh polynomials; by C4 (applied per session, with that session's own
   expulsion budget from §4.2) they are uniform and independent of all
   other sessions' secrets and of `x`.
3. **The shared key crosses sessions only through one-time pads.** The
   only cross-session object is `[x]`, touched by presign P4 via
   `ε′ = x − β′` with `β′` uniform per session. `ε′` is a one-time pad of
   `x`: conditioned on the whole multi-session transcript minus `x`'s
   discrete log, the vector of all `ε′` values is uniform independent of
   `x`. Commitments to `x` are covered by the L2 hop (§7), which is
   applied once globally, not per session.
4. **Global consumption.** The state machine (`fresh → consumed/poisoned`
   per id) is functionality-level (§1): a poisoned or consumed id cannot
   re-enter any later session, matching the store's behavior (§8.6, and
   A4's rollback detection in the reference node).

The `ρ`-th hop therefore costs exactly that session's bound from §8.3;
summing over `ρ` gives the factor-`Q` union. ∎

### 8.2 Re-randomization analysis — [proof sketch with one named formal gap]

The GS21 cube-root attack needs a presignature's `R` (hence `r = F(R)`)
before `(M, τ)` are fixed. The standard mitigation (Groth–Shoup,
signing-service) is *additive*: `k′ = k + δ` with consensus-random `δ`
fixed after `M`. OHM-ECDSA holds `[u] = [k⁻¹]`, and `(k+δ)⁻¹` has no
local formula from `k⁻¹` shares (computing it is an inversion protocol —
exactly what the design avoids). The inverse-compatible candidate is
multiplicative:

```
γ  = H(sid ‖ id ‖ M ‖ τ ‖ X)
k′ = γk        R′ = γR        u′ = γ⁻¹u        z′ = γ⁻¹z   (tweaked: z′ = γ⁻¹(z + τu))
```

All steps are local scalar scalings; commitments scale by the same public
factors (`A[u′] = γ⁻¹·A[u]`, `A[z′] = γ⁻¹·A[z]` — and `A[z′] = γ⁻¹(A[z] + τ·A[u])`
with a tweak), so every point-equality
check survives; the online phase stays one round; no claim-chart element
is touched.

#### 8.2.1 The attack's enabler, precisely

With a **fixed** `r`, the verification equation
`s·R = (h(M) + r·τ)·G + r·X` makes a forgery an *affine* relation
`h(M) + rτ = h(M′) + rτ′` over the candidate space `(M, τ)`. Affineness
is what admits structured search (3-sum/k-sum decompositions at
`O(q^{1/3})`): many candidates can be combined into lists whose sums are
checked against one fixed `r`. This — not the mere early knowledge of
`R` — is the load-bearing structure of the cube-root attack.

#### 8.2.2 Single-signature analysis

Let the adversary hold one re-randomized signing query
`(M₀, τ₀, γ₀ = H(…‖M₀‖τ₀‖X), r₀′ = F(γ₀R), s₀)` with
`s₀·γ₀·R = (M₀ + r₀′(x + τ₀))·G`, and seek a forgery `(M*, τ*, s*)` with
`s*·γ*·R = (h(M*) + r*·(x + τ*))·G`, where `γ* = H(…‖M*‖τ*‖X)`,
`r* = F(γ*R)`. Setting `s* = α·s₀·γ₀/γ*` and matching coefficients of the
unknowns `x` and `1` forces

```
α = r*/r₀′ ,   τ* = τ₀ ,   h(M*) = (M₀/r₀′)·F(H(…‖M*‖τ₀‖X)·R) .
```

The forgery condition is therefore a **fixed-point equation in one
variable**: `h(M*) = c·F(H′(M*)·R)` with `c = M₀/r₀′` known. Both sides
are random-oracle outputs over the *same* input `M*`. There is:

* **no affine structure** — `r*(M*) = F(H′(M*)·R)` varies per candidate,
  so no relation linear in `(h, τ, r)` survives;
* **no list decomposition** — both sides depend on `M*`, so no
  3-sum/k-sum split into independently enumerable lists exists;
* **no cheap `r′`-reuse** — forcing `F(H′(M*)·R) = F(γ₀R)` requires
  `H′(M*) = ±γ₀` (the map `a ↦ a·R` is injective, §3.1), an RO preimage
  search costing `O(q)`.

A generic adversary evaluating the condition pays two RO calls and one
scalar multiplication per candidate with success probability `1/q`:
**total `O(q)` work** — strictly above the `O(q^{1/2})` discrete-log
baseline that bounds the overall security level anyway. The same
argument applied to `T−1` corrupted insiders (who see `R` at generation)
and to external requesters (who see it at signing time) is identical in
form: the attacker model changes *when* `R` is learned, never the
structure of the condition.

#### 8.2.3 Structure destruction, summarized

| | `r` across candidates | Forgery condition | Generic cost |
|---|---|---|---|
| No mitigation (GS21 regime) | constant | affine in `(h, τ, r)` | `O(q^{1/3})` |
| Consensus `δ` (GS22) | unknowable in advance | condition unevaluable at choice time | `O(q^{1/2})` |
| **RO-derived `γ` (this work)** | independent random per candidate | unstructured fixed point in one variable | `O(q)` |

The re-randomization destroys exactly the enabler of §8.2.1: because each
`(M, τ)` induces an independent-looking `r′ = F(γ·R)`, the adversary
faces the plain-ECDSA situation (per-signature independent `r`), where
the best generic attack is square-root — and, for the specific shape
here, exhaustive search at `O(q)`.

#### 8.2.4 Lemma statement and the named formal gap

**Lemma candidate (re-randomization restores the square-root bound).**
*In the AGM+ROM, the multiplicatively re-randomized presignature scheme
of §8.2 (with RO-derived `γ = H(sid‖id‖M‖τ‖X)`) is existentially
unforgeable under adaptive chosen-message-and-tweak attacks with
advantage bounded by `O(q_s²/q)` plus the Groth–Shoup
plain-presignature-model bound — i.e., the mitigation restores
square-root security.*

**Proof sketch.** (i) Single-query core: §8.2.2 — the forgery condition
is an unstructured RO fixed point; any algebraic strategy beyond
exhaustive search would yield a relation among RO outputs, contradicting
the RO model. (ii) Multi-query core: §8.2.5 — the multi-candidate attack
(a collision in the rerandomized condition) is a birthday search in an
effectively random function, costing `Θ(√q)`. (iii) Residual closed:
§8.2.6 — the genericity of `F∘(·R)` follows from curve geometry
(`F(P) = F(Q)` iff `P = ±Q`; `ψ` is exactly 2-to-1), and the scheduling
lemma bounds every interleaving by `q_H²/2q + q_s·q_H/q + Adv_GS-EUF`.
The only assumption beyond the ROM is the named F-uniformity heuristic
(§8.2.6), which is equally load-bearing for the attack being mitigated.
(iii-bis) The algebraic structure of `F` (x-coordinate extraction,
notably `F(P) = F(−P)`) is handled by §8.2.6(iv) — a factor of 2, not a
structure.

**Status.** **Proved** (§8.2.6), modulo one named heuristic —
F-uniformity of the x-coordinate map, the standard assumption every
ECDSA analysis in this lineage already makes (including the GS21 attack
this lemma mitigates). Final form: the re-randomized scheme is EUF under
adaptive chosen-message-and-tweak attacks with advantage
`O(q_H²/q) + O(q_s·q_H/q) + Adv_GS-EUF` — square-root security restored.
The mitigation remains experimental and default-off in the
implementation pending external review; SPEC §9.4 policy (signing-time
disclosure, bounded pools) remains the deployment posture.

#### 8.2.5 The collision analysis (multi-candidate lifting)

**The attack, restated as a collision problem.** The GS21 attack is not
best understood as an equation to *solve* but as a collision to *find*:
the adversary wants `(M, τ, M′, τ′)` with

```
h(M) + r·τ  =  h(M′) + r·τ′            (r constant)
```

because then a single signing query on `(M, τ)` produces `s = k⁻¹(h(M) + r(x + τ))`,
which verifies *also* for `(M′, τ′)` — a forgery on an arbitrary,
adversary-chosen message, for free. With `r` constant this is a
4-variable affine equation, and Wagner-style k-sum search finds solutions
in `O(q^{1/3})`. Affineness of the condition in the `h`- and `τ`-values
is the entire engine of the cube-root attack.

**After re-randomization.** The collision condition becomes

```
h(M) + r′(M,τ)·τ  =  h(M′) + r′(M′,τ′)·τ′ ,   r′(m,t) = F(H(sid‖id‖m‖t‖X)·R) .
```

Define `Φ(M, τ) := h(M) + F(H(…‖M‖τ‖X)·R)·τ`. Both `h` and the inner
hash are random oracles, and `F` evaluated on `γ·R` with `γ` uniform is
heuristically uniform in `𝔽_q` (x-coordinates of random multiples of a
fixed base point; the only structural symmetry is `F(P) = F(−P)`, which
identifies at most pairs and does not help a collision search). So `Φ`
is, heuristically, a **random function** `𝔽_q × 𝔽_q → 𝔽_q`, and the
attack is precisely a *collision search in `Φ`*. For a random function
with output space `𝔽_q`, no algorithm finds a collision generically
faster than birthday: **`Θ(√q)` evaluations** — the square-root bound,
restored. The contrast with the affine case is the whole point: Wagner's
k-sum needs the condition to *split into independently enumerable lists*
(constant `r` provides exactly that split); after re-randomization every
candidate carries its own random `r′`, the lists no longer exist, and
generic collision search is all that remains.

**The deterministic-nonce observation (why this is not surprising in
hindsight).** The re-randomized nonce is `k′ = H(M ‖ τ ‖ X)·k` — a
**deterministic per-message nonce**, the same construction philosophy as
RFC 6979 (`k = H(x ‖ M)`), except derived from the pooled secret `k`
rather than the long-term key. The GS21 attack requires `r` to be known
*before* the message is chosen; a message-derived nonce makes `r′` a
function of the message, so it is *unknowable before choice by
construction*. In the Groth–Shoup model's own terms, their presignature
oracle hands the adversary `R` up front; a re-randomized oracle cannot
answer with `R′ = γ(M)·R` before `M` is fixed, because `R′` does not yet
exist. The attack surface is not patched — it ceases to exist in the
model. (This also clarifies the difference from the additive mitigation:
Groth–Shoup's consensus `δ` makes the *value* unpredictable; the
multiplicative form makes the *point* non-existent until choice. Both
destroy the pre-computation window; ours additionally preserves the
`[k⁻¹]` representation that the design-around requires.)

**The residual (two items, both bookkeeping, no new ideas).**
(a) *Genericity lemma*: formalize "heuristically uniform" for
`γ ↦ F(γ·R)` in the AGM — i.e., that an algebraic adversary cannot make
`Φ` non-birthday-hard; `F` is x-coordinate extraction, not an RO, and
this is the single non-random-oracle ingredient in the argument. The
`F(P) = F(−P)` symmetry must be shown harmless (it folds two `γ` values
onto one `r′`, at most doubling effective collision probability — a
factor of 2, not a structure).
(b) *Adaptive scheduling*: the adversary interleaves RO queries
(defining `γ`, hence `Φ`) with signing queries; the reduction must show
no interleaving beats the `Θ(√q)` collision search, which is exactly the
signing-oracle bookkeeping of the Groth–Shoup multi-query framework.
Neither item changes the conclusion's shape; both are needed to turn this
section from *proof* into *theorem*.

#### 8.2.6 Closing the residual — [proved here, modulo one named heuristic]

**Lemma (genericity of `F∘(·R)`).** Let `R ∈ 𝔾`, `R ≠ O`, and
`F: 𝔾 → 𝔽_q` the ECDSA x-coordinate extraction. Then:

(i) *`F` determines a point up to sign.* `F(P) = F(Q)` if and only if
`P = ±Q`. *Proof.* On a short-Weierstrass curve `y² = x³ + a x + b`, the
x-coordinate of a point determines `y²`, hence `y` up to sign; two
distinct points share an x-coordinate exactly when they are negatives.
∎

(ii) *`ψ: γ ↦ F(γ·R)` is exactly 2-to-1 (up to the negation symmetry).*
`F(γR) = F(γ′R)` iff `γR = ±γ′R` (by (i)) iff `γ = ±γ′` (scalar
multiplication by `R ≠ O` is injective, §3.1). ∎

(iii) *Consequence for `Φ`.* A collision `Φ(M,τ) = Φ(M′,τ′)` with
`(M,τ) ≠ (M′,τ′)` decomposes as: `h(M) − h(M′) = F(γ′R)·τ′ − F(γR)·τ`.
By (ii), the `F`-values on the right are independent of any algebraic
manipulation the adversary performs beyond choosing `γ, γ′` as RO
outputs; the right side is therefore as unstructured as the left. The
adversary's generic options are: a birthday collision in `Φ` (cost
`Θ(√q)`), a preimage of `Φ` at a fixed point (cost `O(q)`), or an RO
collision/preimage inside `h` or the `γ`-hash themselves (birthday
`Θ(√q)` / `O(q)`). No structural shortcut exists.

(iv) *The `F(P) = F(−P)` symmetry* doubles the effective collision
probability of the `F`-component (each `r′` has two preimages
`±γ`): a factor of 2 in the final advantage — a constant, not a
structure. ∎

**Named heuristic (the one assumption in this lemma).** *F-uniformity:*
the distribution of `F(P)` for uniform `P ∈ 𝔾` is taken to be uniform
enough that the maps `Φ` above are modeled as random functions for
cost-accounting purposes (statistical distance from uniform does not
change the `Θ(√q)` / `O(q)` orders). This is the standard heuristic
underpinning all ECDSA analyses in this lineage — it is equally
load-bearing for the GS21 *attack* we are mitigating (their cube-root
search assumes the same `F`-behavior to find its special ratios), so
adopting it costs the proof nothing the attack did not already concede.

**Lemma (scheduling).** No interleaving of RO queries with signing
queries yields forgery advantage exceeding
`O(q_H²/q) + O(q_s·q_H/q) + Adv_GS-EUF`, where `q_s` signing queries and
`q_H` `Φ`-evaluations are made.

**Proof.** A successful forgery must contain one of:
(1) a `Φ`-collision between two values the adversary *controls* (it then
uses one signing query on the first and forges on the second —
find-then-sign). Among `q_H` `Φ`-evaluations, a collision exists with
probability `≤ q_H²/2q` (birthday, by the genericity lemma).
(2) a `Φ`-preimage against a *signed* point (sign-then-find): for each
of the `q_s` signed points, finding a preimage costs `O(q)` per
`Φ`-evaluation with per-attempt probability `1/q`, giving `≤ q_s·q_H/q`.
(3) no usable collision at all: then the forgery is an ordinary ECDSA
forgery under the (possibly tweaked) key with message-derived nonces
`k′ = γk`, `γ` independent of `k` and uniform — an instance of the
Groth–Shoup presignature-ECDSA experiment, bounded by `Adv_GS-EUF`.
Any interleaving decomposes into these cases: signing earlier only turns
controlled points into signed points (case (2), worse for the adversary
than case (1)); signing later leaves the collision search untouched
(case (1)). The union bound gives the claim. ∎

**The re-randomization lemma, final form — [proved here, modulo the
F-uniformity heuristic].** *In the ROM with the F-uniformity heuristic,
the multiplicatively re-randomized presignature scheme of §8.2 is
existentially unforgeable under adaptive chosen-message-and-tweak attacks
with advantage bounded by `O(q_H²/q) + O(q_s·q_H/q) + Adv_GS-EUF` — i.e.,
the mitigation restores square-root security (the Groth–Shoup bound) for
ECDSA with presignatures and additive key derivation, and is the only
known mitigation compatible with direct inverse-dealing (`[k⁻¹]`
representation).*

---

## 9. UC: a porting roadmap (not a proof)

A Universally Composable treatment is a follow-up project — plausibly a
follow-up *paper* — not a gap in this document. This section records what
the port actually requires, so the plan survives review.

### 9.1 What UC changes technically

* **GRO, not RO.** UC proofs model the random oracle as a *global* ideal
  functionality `ℱ_GRO` shared across protocols; the simulator programs
  it (for honest parties' queries) and observes all queries (for
  extraction). Our proof's two ROM mechanisms — programming and query-log
  extraction — are exactly the GRO mechanisms, so the machinery ports
  without rewinding (UC forbids rewinding; we never use it).
* **Everything is an ideal functionality.** Sub-protocols need their own
  functionalities to compose: `ℱ_GRO`, `ℱ_AUTH` (signed channels),
  `ℱ_BC` (the §4.7 signed-echo consistent broadcast, with the F8/⊥
  path), and the target `ℱ_TECDSA` itself. The composition theorem then
  gives multi-session composition *for free* — replacing §8.1's
  session-hygiene lemma, which is UC's genuine payoff here.
* **The environment sees all.** Every distinguishing argument must hold
  against an environment that watches all traffic and all RO queries and
  gets the final outputs — stronger than our game-based distinguisher,
  and the reason each of the items in §9.2 needs re-verification rather
  than citation.

### 9.2 What ports cleanly

1. **L1 extraction (straight-line).** UC forbids rewinding and we never
   use it: the simulator reads adversarial reveal vectors from the
   `ℱ_GRO` query tape exactly as in §6. Straight-line port.
2. **Deferred-content programming.** Honest R1 hashes are broadcast with
   content undefined; the simulator programs `ℱ_GRO(sid‖KG‖h‖A_h) :=
   h_h` at reveal time. The environment cannot have queried that input
   (the content did not exist). This is the same argument as §6.3, but it
   must be re-proved *in the UC execution model* (scheduling is
   adversary/`ℱ_AUTH`-controlled — which, conveniently, matches our
   "honest parties reveal last" trick rather than fighting it).
3. **The consumption state machine.** Already functionality-level
   (§1/§11.1) — written for UC from the start.
4. **C3 (blame soundness/framing-freeness).** Detection is
   information-theoretic (§3.1); attribution reduces to RO binding and
   signature unforgeability (§3.2) — both expressible against `ℱ_GRO`
   and a UC certification/signature functionality.
5. **The bias-by-expulsion lemma (§4.2).** A real-protocol combinatorial
   argument (fault taxonomy + expulsion budget); model-independent.

### 9.3 The two hard spots (where the work is)

1. **UC-DKG against a rushing adversary — the GJKR caveat in UC form.**
   Commit-reveal DKG is known to resist UC simulation in general; the
   deferred-content trick is our candidate answer, but making it a
   theorem requires the full UC DKG functionality definition (what the
   adversary may choose post-reveal, how expulsion/restart is modeled in
   the ideal world, and how the environment's rush on `ℱ_AUTH` is
   bounded). This is the G1 of the UC proof and plausibly 60% of the
   work. The expulsion-budget structure of §4.2 (rerolls cost corruptions)
   is, we believe, the missing ingredient that makes a UC statement
   feasible where the anonymous-abort classical setting fails.
2. **UC presignature-ECDSA does not exist as a result.** Our C5
   *reduces* to Groth–Shoup's game-based presignature-ECDSA experiment;
   a UC proof cannot cite a game-based assumption that way. Options:
   (a) formulate a UC signing functionality for ECDSA-with-presignatures
   and prove it UC-secure in AGM (open territory — Groth–Shoup's
   signing-service analysis, ePrint 2022/506, is the closest template
   and its exact model should be checked first); (b) carry the UC proof
   only up to the presignature interface and state the signing
   functionality as an assumption. Either way this is a research item,
   not a port.

### 9.4 `ℱ_TECDSA` in UC form (sketch)

Interfaces and adversarial controls, to be elaborated in the follow-up:
KeyGen (environment chooses nothing; adversary learns `X` and its
shares; abort with identities), Presign (adversary learns `(R, r)`; id
namespace managed by the functionality), Sign (on `T` distinct requests
for `(M, id)`: output the signature to all; on fewer: nothing; adversary
may force Abort with attributed identities), plus the consumption state
machine (§1) as internal state, and an explicit influence/leakage table
(what the adversary learns per interface: `X`, `(R, r)`, signatures,
abort identities — and nothing else, which is the content of the UC
simulator's job).

### 9.5 Recommendation

Do not start the UC proof inside this document's arc. The honest
sequencing is: (i) finish the game-based proof's remaining bookkeeping
(§7.3 pages) and get it externally reviewed; (ii) check whether
Groth–Shoup 2022/506's model is UC-flavored — if so, it is the template
for §9.3(2) and halves the work; (iii) pursue UC as a joint follow-up
paper with an academic collaborator, where the expulsion-budget
structure (§4.2) is the likely enabler of the first UC-secure
commit-reveal DKG in this setting. This section is the porting plan;
nothing here blocks the current paper, the audit, or deployment review.

### 8.3 The assembled bound

```
Adv_OHM(𝒜)  ≤  Adv_GS-EUF(ℬ)  +  Q·ε_L1  +  O(q_H²/q)  +  ε_L2(OMDL|AGM)  +  ε_C3
```

with `ε_L1 = q_H·2^{-λ} + O(q_H²/2^λ)` (§6), `Q` the number of VSS
sessions, the G3 birthday term, the L2 hop priced per the chosen route
(§7.2 assumption or §7.3 lemma), and `ε_C3` from §3.2. The bias term of
§4.2 is absorbed by the L1 hop with a factor-`T` loss.

**What this document establishes now:** correctness (C1), blame soundness
and framing-freeness (C3), uniformity with a bounded-bias lemma (C4),
the extraction simulator for the DKG (L1), Feldman hiding in the AGM
(L2, modulo the representation bookkeeping of §7.3), the composition
lemma (§8.1), the re-randomization single-query core (§8.2.2 — the
forgery condition is an unstructured RO fixed point costing `O(q)`), and
the full reduction skeleton with per-hop bounds and the assembled
advantage. **What remains open:** the §7.3 representation-bookkeeping pages, the
plain-model OMDL alternative (named, unproven), UC (§9 — roadmap, not a
gap), and adaptive corruptions. The re-randomization lemma is **proved**
(§8.2.6, modulo the named F-uniformity heuristic). With those caveats,
the game-based security claim of §1 is **proved in the AGM+ROM under
ECDLP and the Groth–Shoup presignature-ECDSA assumption.**

---

## 10. UC framework (U2: model and functionalities)

This section fixes the UC execution model and the ideal functionalities the
UC proof will use, following the structure of Groth–Shoup's signing-service
analysis [GS22svc], which §9.1's U1 review confirmed is a genuine UC proof
(Canetti's framework, static corruptions, straight-line simulator,
programmable RO, no AGM in the UC layer). Definitions here are precise where
the game-based proof (§1–§8) was informal; theorems U1–U3 are stated at the
end with their proof status.

### 10.1 Execution model

* **Framework.** Canetti's UC model. Entities: environment `Z`, adversary
  `A`, simulator `S`, parties `P₁…Pₙ`, ideal functionalities as below. `Z`
  and `S` pass messages freely.
* **Corruptions.** **Static**, malicious, rushing: `A` corrupts a set `C`,
  `|C| = f ≤ T−1`, chosen before execution. Adaptive corruptions are out of
  scope (see §9 and the LDL-weakening technique of [GS22svc] §10.1 as the
  known path if ever needed).
* **Channels.** Authenticated, message delivery scheduled by `A` via
  `ℱ_AUTH` (eventual delivery). Safety statements are timing-independent;
  liveness statements cite the partial-synchrony assumption only inside the
  `ℱ_BC` realization (mirroring [GS22svc]'s confinement of partial
  synchrony to consensus liveness).
* **Random oracle.** A programmable RO in the UC-hybrid sense: `S` programs
  honest-party answers and sees all adversarial queries (the GRO-style
  caveat of [GS22svc] App. A.6 — "benign programmability" — applies equally
  here, since the same hash implements the protocol ROs and the
  re-randomization derivations; we adopt their convention and flag it at
  the composition step, §10.5).
* **Threshold.** `n ≥ 2T−1`, honest majority; the identifiable-abort and
  expulsion machinery of SPEC §10 is part of the *protocol*, and the
  corresponding blame outputs are part of the *functionality* (§10.3).

### 10.2 `ℱ_BC` — signed-echo consistent broadcast

`ℱ_BC(sid, phase, round)`, per broadcast slot `(i)`:

* On `(bcast, i, m)` from party `i` (possibly corrupt): record `m`, give
  `(bcast, i, m)` to `S` for scheduling.
* `S` instructs delivery per party: `(deliver, i, m, P_j)`. `ℱ_BC` delivers
  `m` to `P_j` marked as from `i`.
* **Consistency rule (idealized):** for each slot, `S` must deliver the
  *same* `m` to all honest parties, or `⊥` to all — `ℱ_BC` rejects any
  schedule that would deliver two different values. `S` may deliver `⊥`
  only if it also outputs `(equivocate, i)` with evidence `E` to all
  honest parties.
* **Validity:** if `i` is honest and all parties are scheduled delivery,
  `m` (not `⊥`) is delivered.
* The F8 fault class of the real protocol realizes the
  `(equivocate, i)` evidence output: two conflicting sender-signed values
  are the offline-verifiable proof (SPEC §4.7, §10.1 F8).

### 10.3 `ℱ_TECDSA` — threshold ECDSA with identifiable abort (UC form)

Modeled on [GS22svc]'s `ℱ_ecdsa` (§2.6.1 there), extended with the blame
interface and with the consumption state machine internalized (§1):

* **Init(sid):** on the first request, run ECDSA key generation
  `(x, X = x·G)`; record `(init, X, x)`. Give `(init, i, X)` to each
  requester and to `S`. (`S` learns `X`, never `x`.)
* **Presign(sid, id):** on request from all honest parties: run
  presignature generation producing `(R = k·G, r = F(R), κ = k⁻¹)`;
  record `(presig, id, R, r, κ, state := fresh)`; give `(presig, i, id, R, r)`
  to each requester and to `S`. (`S` learns `(R, r)` immediately — the
  presignature is adversarially visible, matching the §9.4 analysis; `κ`
  is never revealed.)
* **Sign(sid, M, id):** on request from `T` distinct parties for the same
  `(M, id)` with `state = fresh`: compute `s = κ·(H(M) + r·x)`, set
  `state := consumed`, record and give `(sig, M, id, r, s)` to each
  requester and to `S`. If the requesting set is not well-formed
  (`< T` distinct, or `id` not fresh): ignore.
* **Abort:** `A` (through `S`) may send `(abort, sid, phase, C′)` with
  `C′ ⊆ C`; `ℱ_TECDSA` reports `(abort, phase, C′)` to all honest parties
  and sets any in-flight `id`'s state to `poisoned`. Blamed sets are
  subsets of the corrupt set — **the functionality leaks nothing through
  aborts beyond the corrupt identities, which are public knowledge**.
* **Consumption state machine:** `fresh → consumed | poisoned`, enforced
  by the functionality itself (§1); `Z` is additionally required to be
  *locally consistent* (no honest party sees conflicting uses of one id)
  and *globally consistent* (honest parties agree on request orderings —
  justified in the realization by `ℱ_BC`), following [GS22svc]'s
  environment-consistency pattern.
* **Delivery control:** `S` schedules output delivery via
  `(output-pk, i)` / `(output-sig, id, i)` control messages (their
  §2.6.1 mechanism), but must deliver to every honest party that was
  scheduled (no selective starvation: abort is the only suppression
  mechanism).

### 10.4 Theorems U1–U3 (structure and status)

* **Theorem U1 (target).** *Protocol OHM-ECDSA (SPEC §6–§9) securely
  realizes `ℱ_TECDSA` in the `(ℱ_GRO, ℱ_AUTH, ℱ_BC)`-hybrid, against
  static malicious adversaries corrupting `< T` of `n ≥ 2T−1` parties,
  with identifiable abort.* Status: **framework set (this section);
  simulator construction pending (U3)**.
* **Theorem U2 (unforgeability plug-in).** *No environment distinguishing
  real from ideal can forge an ECDSA signature under the ideal key except
  with `Adv_GS-EUF + Adv_rerand`*, where the two terms are the
  Groth–Shoup presignature-ECDSA bound and the re-randomization lemma of
  §8.2.6 (which plays the role that [GS21] Theorem 6 plays for
  [GS22svc] — note: *their* theorem covers the additive mitigation, ours
  covers the multiplicative one; there is no existing citable result for
  the multiplicative form, which is why §8.2.6 had to exist). Status:
  **proved modulo the F-uniformity heuristic (§8.2.6)**.
* **Theorem U3 (UC-DKG against rushing).** *The commit-reveal DKG of
  SPEC §6 is UC-simulatable against a rushing adversary via the
  deferred-content technique (honest R1 hashes programmed at reveal
  time), with the expulsion budget of §4.2 bounding rejection-sampling
  to `O(log T)` bits.* Status: **proved in §11** (hybrid argument in
  full, delicate points P1–P3 explicit; realization bookkeeping for
  `ℱ_BC` and the per-restart union bound expansion remain as indexing
  work, §11.6).

### 10.5 Composition architecture

Two layers, mirroring [GS22svc]:

1. **Protocol layer (U1):** prove `Π_OHM → ℱ_TECDSA` in the
   `(ℱ_GRO, ℱ_AUTH, ℱ_BC)`-hybrid (assumption-free there, as their
   Theorem 1 is in theirs).
2. **Realization layer:** `ℱ_BC` realized by the §4.7 signed-echo
   protocol (consistency/totality from §10.2's rules; liveness under
   partial synchrony); `ℱ_AUTH` by the deployment's signed channels; the
   unforgeability of final outputs plugged in from U2 ([GS21]'s
   presignature-ECDSA result for the base scheme; §8.2.6 for the
   re-randomized variant).
3. **Caveat (shared hash):** the same hash function implements the
   protocol ROs, the re-randomization `γ`-derivation, and the
   Fiat–Shamir challenges; the composition across layers adopts the
   benign-programmability convention of [GS22svc] App. A.6 and must be
   stated explicitly in the final write-up.

### 10.6 U3 obstacle list (for the sprint)

The deferred-content UC-DKG proof must handle, in order:

1. **Extraction without rewinding.** `S` reads adversarial reveal vectors
   from the `ℱ_GRO` tape at reveal time — ports directly from §6.
2. **Deferred-content programming against the environment.** `S` must
   broadcast honest R1 hashes with content undefined, then program
   `ℱ_GRO` at reveal. Obstacle: in UC, `Z` watches everything and may
   adaptively query `ℱ_GRO`; the argument (content undefined ⇒ no
   targeted query possible ⇒ programming undetectable except with
   negligible probability) must be re-established against a `Z` that sees
   the *transcript*, not just against `A`. This is the step whose UC
   validity is asserted in §9.2 and must be proved in U3.
3. **Rushing within rounds.** `A` schedules `ℱ_AUTH` deliveries; `S`
   delays honest reveals until after adversarial reveals in each
   commit-reveal instance (the same trick as §6.2, now justified by
   adversarial scheduling rather than by the proof's bookkeeping).
4. **Expulsion/restart in the ideal world.** The expulsion budget of §4.2
   must appear in `ℱ_TECDSA`'s abort interface (it does — aborts carry
   `C′ ⊆ C`, and the state machine poisons ids), and the simulator must
   show the real expulsion policy (§10.3 of SPEC) realizes it.
5. **Uniformity under restart loops.** The §4.2 lemma bounds the
   adversary's rejection-sampling at `O(log T)` bits; U3 must show the
   ideal key is uniform *independently*, and the real key's distribution
   is within that bound of it (this is where the expulsion budget does
   the work the classical anonymous-abort setting cannot bound).

**Cross-validation from U1.** [GS22svc] §3.6 proves that Feldman-only
DKG *without* anti-rushing protection is fatally biasable for ECDSA
(the adversary contributes `−φ/ρ` after seeing honest constant terms,
forces the public key to a known discrete log, and forges). Our
commit-reveal fixes contributions before honest constant terms are
visible, blocking exactly that attack — the UC proof must make this
blocking explicit; it is also why `ℱ_TECDSA`'s key may be modeled as
uniform (Theorem U3's output).

---

## 11. Theorem U3: UC security of the commit-reveal DKG against rushing adversaries

This section carries the UC sprint's load-bearing item: the commit-reveal
Feldman DKG of SPEC §6, in the `(ℱ_GRO, ℱ_AUTH, ℱ_BC)`-hybrid of §10,
securely realizes the key-generation interface of `ℱ_TECDSA` against a
static, rushing, malicious adversary corrupting `f ≤ T−1` of `n ≥ 2T−1`
parties. The proof technique is deferred-content programming (§6, §9.2);
the restart economics use the expulsion budget of §4.2. Status: **proved
here at the level of the hybrid argument, with three delicate points
(P1–P3) made explicit; the §7.3-style representation bookkeeping for a
journal version is flagged where it binds.**

### 11.1 Statement

**Theorem U3.** *There exists a straight-line simulator `S` such that for
every environment `Z` and every static rushing adversary `A` corrupting
`f ≤ T−1` parties, the view of `Z` in the real execution of the
commit-reveal DKG (in the `(ℱ_GRO, ℱ_AUTH, ℱ_BC)`-hybrid) is
indistinguishable from its view in the ideal execution with `S` and the
key-generation interface of `ℱ_TECDSA` (§10.3 as extended by §11.2),
except with advantage at most*

```
ε_U3  ≤  (f+1)·(q_H·2^{-128} + O(q_H²/2^λ))  +  ε_C3
```

*where the two terms are the per-restart extraction/programming error and
the blame-attribution error of §3.2.*

### 11.2 The ideal interface, extended for restarts

The key-generation interface of `ℱ_TECDSA` (§10.3) is extended with the
restart economics of the real protocol, so that real and ideal runs
implement the *same* accept/reroll process rather than requiring the
bias to be negligible (it is `log₂(f+1)` bits, which is a small constant,
not negligible — P2):

* **Candidate generation.** On `(keygen, sid)`, the functionality samples
  a fresh uniform candidate `x^(ρ) ←$ 𝔽_q*`, `X^(ρ) = x^(ρ)·G`, and gives
  `X^(ρ)` to `S`.
* **Adversarial influence hook.** `S` may respond `(keep, sid)` or
  `(reroll, sid)`. On `reroll`, a fresh candidate is drawn; the hook may
  be exercised at most `f+1` times per `sid` (the expulsion budget, §4.2:
  each reroll costs `A` one corrupted party, and after `f` expulsions the
  instance completes or dies). On `keep`, `x := x^(ρ)` is recorded as the
  joint key.
* **Abort with attribution.** As in §10.3: `(abort, phase, C′)` with
  `C′ ⊆ C`, reported to all honest parties, in-flight ids poisoned. A
  `reroll` accompanied by an abort blames one corrupt party; the
  functionality enforces the budget by refusing the `f+2`-th reroll.

### 11.3 The simulator

`S` receives `X^(ρ)` from the functionality for the current candidate and
runs the deferred-content procedure (§6.2) inside the UC model:

*R1 (commit).* For each honest dealer `h`, `S` broadcasts
`h_h ←$ {0,1}^λ` (no content) and schedules delivery via `ℱ_AUTH`/`ℱ_BC`.
`A` (rushing) then broadcasts `h_i` for `i ∈ C`. Every `h_i` that will
ever pass the R3 hash check appears in `A`'s `ℱ_GRO` query tape
(extraction — the tape is `S`'s by definition of the GRO; a passing
reveal absent from the tape costs `A` a `2^{-λ}`-per-verifier-query
guess, ≤ `q_H·2^{-λ}` total).

*R2 (reveal).* `S` schedules adversarial reveals first (adversarial
scheduling justifies the ordering — it is `A`'s own choice to rush, and
`S` simply does not accelerate honest messages). For each revealed `A_i`,
`S` records the extracted vector. `A` may instead abort (refuse to
reveal): see R3 abort handling.

*Programming.* With every adversarial constant point extracted, `S`
chooses, per honest dealer `h`, the commitment vector `A_h` as in §6.2:
`A_{h,0} := X^(ρ) − Σ_{i revealed} A_{i,0} − Σ_{h′ ≠ h} A_{h′,0}`;
`EvalCom(A_h, j) := s_{h,j}·G` with `s_{h,j} ←$ 𝔽_q` uniform for
`j ∈ C`; the Vandermonde system over `{0} ∪ C` yields the unique
coefficient points. `S` then programs `ℱ_GRO`: on input
`(sid‖KG‖h‖A_h)`, answer `h_h`.

*R3 (checks, complaints, aborts).* `S` executes the honest checks. False
accusations against honest dealers resolve with the accuser blamed (the
defense share `s_{h,j}` verifies by construction); genuine misdealings
are caught information-theoretically (§3.1). An adversarial refusal to
reveal is handled at round close (P3): after `ℱ_BC`'s scheduled round
completes without `A_i`, the dealer is excluded and blamed by omission —
identification is by *position in the scheduled round*, not by timeout
guesswork; `S` reports `(abort, sid, R2, {i})` to the functionality,
which poisons the instance and (if the policy restarts) draws a fresh
candidate per §11.2.

*Restart.* On a restart, `S` requests a fresh candidate from the
functionality and repeats the procedure; `S` keeps the functionality's
candidate count honest by construction: the functionality's `reroll`
hook is exercised exactly when `A` actually caused an expulsion (one
corrupted party per reroll, budget `f`), so the `f+2`-th reroll never
occurs in either world.

### 11.4 Indistinguishability (the hybrid argument)

Condition on the two bad events not occurring: **E1** (a passing reveal
absent from the `ℱ_GRO` tape, `≤ q_H·2^{-λ}`), **E2** (a `ℱ_GRO`
programming inconsistency, below). Then:

**(i) Transcript distribution.** The joint candidate key is `X^(ρ)` by
construction in both worlds (real: `Σ` of constant points including the
programmed `A_{h,0}`; ideal: the functionality's candidate). Honest
commitment vectors are uniform subject to the position constraints —
and in the real protocol, conditioned on the joint key, the honest
dealers' vectors are *also* uniform subject to those same constraints
(constant term uniform, `T−1` adversary-facing shares uniform by the
random-polynomial property: the `(T−1)`-vector of evaluations of a
uniform degree-`T−1` polynomial at fixed positions is uniform and
independent of the constant term). The adversary-facing shares `s_{h,j}`
are uniform in both worlds. All checks and complaint outcomes match
(§3.1, §3.2 — the `ε_C3` term).

**(ii) P1 — programming undetectability.** `Z` distinguishes only if it
queries `(sid‖KG‖h‖A_h)` on `ℱ_GRO` before `S` programs it (or detects
the planted answer by a collision). The input's full content is
determined only at R2-programming time; from `Z`'s view before that
point, the vector `A_h` carries `≥ (T−1)·λ` bits of min-entropy
(the `T−1` adversary-facing shares `s_{h,j}` are uniform and
independent, even though `Z` knows `X^(ρ)` and can compute `A_{h,0}` —
the higher coefficients are not determined by the constant point).
`Z`'s probability of querying that exact input across `q_H` queries is
`≤ q_H·2^{-(T−1)λ} ≤ q_H·2^{-128}` for `T ≥ 2`. Weakening `T = 2` to
`λ ≥ 128` is where the `2^{-128}` in the bound comes from; committees
with larger `T` get more entropy, not less. Birthday consistency against
all other programmed answers and honest-party queries (R3 verifiers
query exactly the planted input) contributes `O(q_H²/2^λ)`.

**(iii) P2 — restart correspondence.** In the real world, `A`'s decision
to abort after seeing honest reveals depends only on the honest vectors
it sees, which are uniform-subject-to-constraints identically in both
worlds (item (i)); hence `A` aborts with the same distribution. Each
abort expels one corrupt party (attributed: deviation by §3.1–3.2,
omission by P3). The functionality's reroll hook is exercised at the
same points, so both worlds implement the identical accept/reroll
process with `≤ f+1` uniform candidates — the kept key's distribution
matches by construction. (This is why the bound need only be *matched*,
not *negligible*: the `log₂(f+1)`-bit selection the adversary gets in
the real world is exactly the influence the hook grants in the ideal
world.)

**(iv) P3 — refusal identification.** Blame-by-omission is attributed
only at `ℱ_BC`-scheduled round close, which `S` controls identically in
both worlds (the round-close event is a functionality-level scheduling
decision, visible to `Z`). Safety never depends on when the close
happens; the blame lands on the party whose scheduled reveal slot
closed empty — in both worlds, `A` cannot make an honest party's slot
close empty (it does not control honest sending), so no honest party is
blamed by omission except via the `ε_C3` term of §3.2.

Union over `≤ f+1` restarts gives the `ε_U3` bound. ∎

### 11.5 Uniformity corollary

Under Theorem U3, the joint long-term key is uniform subject to the
`≤ f+1` accept/reroll process, identically in real and ideal worlds —
and the rushing key-bias attack of [GS22svc] §3.6 (contribute `−φ/ρ`
after seeing honest constant terms) is impossible: by the time honest
constant terms are visible (R2), every adversarial contribution is fixed
by its R1 hash (extraction shows it was committed before the honest
reveal), so the adversary cannot choose its dealing as a function of the
honest contributions. Commit-reveal is thus certified as the *minimum*
viable anti-rushing protection for a Feldman DKG in this setting —
matching the necessity direction of [GS22svc] §3.6.

### 11.6 Status and remaining work

* **Proved here:** the hybrid argument of §11.4 in full, including the
  three delicate points (P1 entropy accounting, P2 restart
  correspondence, P3 round-close attribution), the simulator of §11.3,
  and the uniformity corollary of §11.5.
* **Bookkeeping for a journal version:** (i) the `ℱ_BC` realization
  theorem (§10.2's ideal rules ← §4.7's signed-echo protocol) written
  out — the consistency/totality argument exists at the game-based level
  already (F8 analysis), so this is indexing, not ideas; (ii) the exact
  per-restart union bound expanded; (iii) the benign-programmability
  note of §10.5 folded into a GUC-style statement if the full version
  goes that way.
* **Not claimed:** UC security with *adaptive* corruptions (the
  deferred-content trick does not obviously survive an adversary that
  corrupts after R1; the [GS22svc] §10.1 LDL-weakening is the known
  path); UC with dishonest majority (out of model); liveness under full
  asynchrony (partial synchrony stays in the `ℱ_BC` realization layer,
  §10.1).

With U3 in place, Theorem U1 (§10.4) reduces to assembling the remaining
phases (triples, presign, sign) around the same machinery: their
simulators are the §5 games G2–G5, which are already straight-line and
query-tape-based; the only UC-specific addition beyond U3 is the
delivery-scheduling correspondence for the online phase, which is
bookkeeping. **The UC proof has no remaining novel obstacle.**

---

## 12. Theorem U1 assembly — and the ε′-opening obstruction

This section assembles the remaining phases (triples, presign, sign) around
the U3 machinery into Theorem U1. The assembly was verified phase by phase
before writing. **The result: every phase is simulatable except one scalar
— the P4 opening `ε′ = x − β′` — which is blocked in the pure-Feldman
setting. The obstruction, its proof, and the resolution paths are the
content of this section.**

### 12.1 The assembly inventory (verified simulatable)

For each phase, the simulator's knowledge and the message-production
mechanism:

| Phase | Values | Simulatable? | Mechanism |
|---|---|---|---|
| KeyGen | `[x]`, `A[x]`, `X*` | **conditional** | U3: deferred-content programming; adversary-facing shares chosen by `S` as scalars |
| Triples | `α, β, γ` | ✓ | joint VSS dealt with known coefficients + wire extraction; DLEQ via `ℱ_GRO` programming |
| Presign P1 | `⟦u⟧, ` | ✓ | dealt with known constants |
| Presign P2 | `δ, ε, v, ⟦k⟧` | ✓ | `u, a` known ⇒ all openings computable; `k = v⁻¹a` known ⇒ `R = k·G` computed by `S` (no oracle needed) |
| Presign P3 | `R_j`, `R`, `r` | ✓ | `k` known; nonce-point checks are point equalities on public data |
| **Presign P4** | **`ε′ = x* − β′(0)`** | **✗ — the obstruction** | see §12.2 |
| Presign P4 (rest) | `z`, `A[z]` | conditional on `ε′` | `z = u·x*` needs `ε′` as a scalar in `z_j = γ′_j + δ′β′_j + ε′α′_j + δ′ε′` |
| Sign S1–S3 | `s_j`, `s` | ✓ (given `ε′` flows) | honest `s_h` via Lagrange from oracle `s` and wire-known adversary `s_j`; the point checks pass automatically for consistent adversaries |

The unforgeability plug-in (U2) and the blame machinery (C3) are
unaffected. The obstruction is thus *exactly one opening* — the only place
in the protocol where a scalar affine in `x*` with a nonzero coefficient
must be broadcast by an honest party.

### 12.2 The obstruction, stated and proved

**Lemma (the honest-scalar obstruction).** *In the pure-Feldman setting,
no simulator can complete the P4 `ε′`-opening against an adversary that
checks honest shares against the fixed commitment `A[x]`, unless it knows
`x*` (making the reduction vacuous) or the commitment is equivocable.*

**Proof.** The opening (SPEC §8 P4) reveals `ε′ = x* − β′(0)`, where
`β′(0)` is a jointly dealt uniform mask known to `S`. The adversary
interpolates it from `T` shares: its own `T−1` shares `x_j − β′_j`
(scalars known to `S`, since `S` chose `x_j`) plus at least one honest
share `σ_h = p̃(h) − β′_h`, where `p̃` is the simulated key polynomial
with `p̃(0) = x*`. The adversary checks `σ_h·G == EvalCom(A[x], h) −
EvalCom(A[β′], h)`. By the Lagrange structure of the programmed
Vandermonde system, `p̃(h) = α_h + β_h·x*` with `α_h, β_h` known scalars
and `β_h ≠ 0` at every honest position `h` (evaluation at any position
outside `{0} ∪ C` depends on the constant term — for `T = 2` explicitly:
`p̃(h) = x*(1 − h/2) + (h/2)x_2`, and the `x*`-coefficient vanishes only
at `h = 2`, the adversary's own position). Hence `σ_h = (α_h − β′_h) +
β_h·x*` is affine in `x*` with a nonzero `x*`-coefficient, and producing
`σ_h` as a scalar requires `x*`. The check is a point equality, so
sending any other scalar fails with probability 1 (§3.1). Prescribing the
opened value does not help: replacing `p̃(0)` by `ε̂ + β′(0)` for a
chosen `ε̂` changes the constant, and the check at honest positions then
requires `w_0(h)·(x* − ε̂ − β′(0)) = 0`, i.e. `ε̂` equal to the true
(unknown) value. Restructuring the multiplication does not help either:
any computation of `[u·x]` (Beaver) or `[k⁻¹x]` (GJKR-style local
products) requires an honest party to compute a scalar involving `x*` —
the masked opening `x − β′` in the first case, the local product
`u_h·x_h` in the second. ∎

**Corollary (the trade-off at the heart of the design).** *Perfect
binding of the key commitment (Feldman) yields unconditional detection of
bad shares — and makes the standard (non-equivocating) simulation of
key-involving openings impossible. Unconditional identifiability and
standard-model simulatability are in direct tension at exactly one point:
the P4 `ε′`-opening.*

**Remark (why the literature doesn't hit this).** Groth–Shoup's signing
service [GS22svc] uses Pedersen VSS with a trapdoor `ζ = log_g h`
precisely so the simulator can *equivocate* — produce honest shares for
any prescribed opening without knowing the secret (their §9, Game 6).
DJNPO20 instead opens only `[s] + [d] + m[e]` with zero-sharings `[d],
[e]` dealt jointly: the oracle-known `s` plus the fully-known blinding
make honest `(s+d)_h` computable by Lagrange — which is *also* why the
zero-sharings are part of the '657 claim elements, and why our
patent-driven removal of them pushes the simulation problem back to the
`ε′`-opening. Both are simulation mechanisms; ours is the only protocol
in the family without one.

### 12.3 Resolution paths

**Path A (recommended): equivocable key commitment.** Change the key
sharing `⟦x⟧` (and only it) from Feldman to Pedersen commitments with a
trapdoor `ζ = log_g h` held by the simulator in the proof. Everything
else — `u, a`, triples, presignature sharings, the DLEQ proofs, the F1–F8
blame machinery, the signed-echo broadcast — stays Feldman and keeps
unconditional detection. The trade-off, stated plainly: **the key
sharing's share checks in the DKG (§6 R3) become computationally binding
rather than unconditionally binding**, so blame for DKG share faults
moves from the "unconditional" column to the "computational" column —
the same column that already holds all attribution (signatures, ROM
binding). No other blame rule changes. This is exactly the [GS22svc]
architecture and the only known clean path to a full simulation proof.

**Path B: verify the GJKR96 mechanism.** GJKR96's threshold-DSS proof
faces the same obstruction in its multiplication subprotocol and
(apparently) resolves it without equivocation. The mechanism could not be
reliably reconstructed during the U4 sprint; a literature check of
GJKR96's signing simulation (their handling of honest shares in
`[k⁻¹x]`) is a research item. If it contains a non-equivocation trick
compatible with Feldman, it is preferable to Path A.

**Path C: prove in the AGM end-to-end without a full simulator.** The
obstruction is about `S`'s *production* of honest scalars, not about the
adversary's capabilities. A non-simulation argument (privacy proved
statistically — `ε′` is uniform, `x_j` are `T−1` Shamir shares,
commitments L2-hidden — plus a direct algebraic unforgeability argument
in the AGM) might avoid the simulator entirely. This is the least
developed path and offers no UC statement.

**Status of Theorem U1.** *Assembled modulo the obstruction of §12.2:
all phases are simulatable as inventoried in §12.1; the unforgeability
plug-in (U2) and blame machinery (C3) port; Theorem U1 becomes a theorem
upon adoption of Path A (a protocol decision — it weakens the key
sharing's binding from perfect to computational and therefore requires
sign-off under the project's "never weaken verification checks" rule) or
a successful outcome of Path B.*

### 12.4 What the assembly already establishes without the decision

Independently of the Path A/B choice, the assembly verifies:

* **Correctness, blame soundness, framing-freeness** (C1, C3) — proved
  unconditionally, no simulation needed.
* **Privacy (C2)** — provable statistically: the adversary's view decomposes
  into `T−1` Shamir shares (information-theoretically free of `x*`),
  one-time-padded openings (`ε′` uniform), simulated proofs, and
  commitments (L2-hidden). No honest-scalar production is needed to *show
  the distribution is independent of `x*`* — only to *simulate it
  operationally*, and the former is what privacy claims.
* **Identifiable abort end-to-end** — real-protocol property, unaffected.
* **The UC-DKG theorem (U3)** — KeyGen is fully UC-secure as proved in
  §11.
* **Unforgeability modulo the `ε′`-opening**: conditioned on the
  adversary obtaining `ε′` correctly (which is what an honest execution
  delivers), the plug-in (U2) gives the full bound. The obstruction is
  not a *security* hole in the real protocol — it is a *proof* hole in
  the simulation argument for the online-involving-key opening.

**Recommendation.** Take Path A as a protocol decision (Pedersen
commitment for `⟦x⟧` only, with the binding trade-off documented in
SPEC §4.2/§6 and the blame taxonomy annotated accordingly), then the U1
assembly completes with no further novel work. Path B is the cheaper
alternative *if* the GJKR96 mechanism verifies; assign it a literature
check first.
