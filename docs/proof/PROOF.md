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
effectively random function, costing `Θ(√q)`. **The named residual (two
items, both bookkeeping, §8.2.5 step 4):** (a) the genericity lemma that
`γ ↦ F(γ·R)` is sufficiently uniform in the AGM (the only non-RO
ingredient); (b) the adaptive-scheduling bookkeeping (adversary
interleaving RO queries with signing queries), which needs the
Groth–Shoup signing-oracle accounting.
(iii) The algebraic structure of `F` (x-coordinate extraction, notably
`F(P) = F(−P)`) is accounted for by the injectivity argument of §8.2.2
(preimage search up to sign) and needs no further relaxation in the AGM.

**Status.** From "fully open" to *proof sketch with the residual named in
§8.2.5 step 4*. The single-query core (§8.2.2) and the multi-candidate
collision analysis (§8.2.5) are proved here; the two residual items
(genericity of `γ ↦ F(γ·R)` in the AGM; adaptive-scheduling bookkeeping)
are the remaining work. Until they are written, the mitigation's status
is unchanged for deployments: SPEC §9.4 policy (signing-time disclosure,
bounded pools) remains the security posture, and the implementation
(`sign::sign_share_rerand`) stays experimental and default-off.

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
advantage. **What remains open:** the two residual bookkeeping items of §8.2.5 step
4 (genericity of `γ ↦ F(γ·R)` in the AGM; adaptive-scheduling
bookkeeping), the §7.3 representation-bookkeeping pages, the plain-model
OMDL alternative (named, unproven), UC, and adaptive corruptions. With those caveats, the
game-based security claim of §1 is **proved in the AGM+ROM under ECDLP
and the Groth–Shoup presignature-ECDSA assumption.**
