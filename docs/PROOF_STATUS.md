# Proof Status Ledger — OHM-ECDSA

Reviewer-facing consolidation of every named claim/lemma in
`docs/proof/PROOF.md` and `SPEC.md` §11, with the status label **quoted
verbatim** from the source. Nothing here upgrades a label; where SPEC and
PROOF differ, both labels are shown and the difference is listed under
"Cross-document inconsistencies" at the end (reported, not reconciled —
PROOF.md's v0.2 header states it "supersedes the 'sketch' phrasing of
SPEC §11 for the components marked [proved here]").

## Legend

- **Label vocabulary** (PROOF.md v0.2 header): each lemma is marked
  **[proved here]**, **[proof sketched]**, or **[open]**; some sections
  carry refinements (e.g. "[proved here, ROM]", "with bookkeeping
  note"). Quoted strings below are the exact source phrasing.
- **Assumption base abbreviations.** ROM = random-oracle model; AGM =
  algebraic group model; EC-GGM = elliptic-curve generic group model
  (the model of Groth–Shoup's Theorem 6); ECDLP = discrete-log hardness
  in `𝔾`; GS-EUF = the Groth–Shoup presignature-ECDSA assumption
  [GS21]; `(T−1)`-OMDL = one-more-discrete-log with `T−1` known shares;
  σ-EUF = ECDSA unforgeability of the transport signatures.
- **"What would close it"** lists only what the source itself names as
  remaining.

## Status table

| Claim | Source | Verbatim status label | Assumption base | What would close it |
|---|---|---|---|---|
| C1 — correctness (honest or non-aborting execution outputs the ECDSA signature) | SPEC §11.2; PROOF §2 | "[proved here]" (PROOF §2 header) | None — linear algebra plus C3's verified-opening guarantee | Closed modulo external review |
| C2 — privacy (adversary's view simulatable from public data) | SPEC §11.2 ("Simulator `𝒮` skeleton"); PROOF §12.4, §13.4 | PROOF §12.4: "Privacy (C2) — provable statistically"; §13.4 lists "privacy (C2, statistical)" under "Proved unconditionally (no assumption beyond ECDLP-in-EC-GGM as used by GS21)" | Statistical (Shamir + one-time pads) except Feldman *hiding* of never-opened values = L2; abort-distribution reproduction proved in §8.4 | External review only (L2 written in §7.3; §11.3(4) closed in §8.4) |
| C3 — blame soundness + framing-freeness | SPEC §11.2; PROOF §3 | "[proved here]" (PROOF §3 header) | Detection: unconditional (information-theoretic, §3.1). Attribution: RO binding + σ-EUF, bound `q_H·2^{-λ}` + `ε_sig` (§3.2) | Closed modulo external review |
| C4 — nonce/joint-secret uniformity, with the bias-bounded lemma | SPEC §11.2, §11.5; PROOF §4 | "[proved here]" (PROOF §4 header) | ROM (hash-commit binding) + the §10.3 expulsion policy bounding rejection sampling to `O(log T)` bits | Closed with a flagged caveat: "the exact translation of selection bias into hidden-number-problem instances is out of scope for this lemma" (PROOF §4.2) |
| C5 — unforgeability (reduction to GS presignature-ECDSA) | SPEC §11.2 ("Reduction skeleton"); PROOF §5 (Extraction), §8.3 | PROOF §8.3: "With those caveats, the game-based security claim of §1 is **proved in the AGM+ROM under ECDLP and the Groth–Shoup presignature-ECDSA assumption.**" (caveats = named OMDL alternative, UC roadmap, adaptive corruptions, re-randomization sketch status) | AGM+ROM; ECDLP; GS-EUF; per-session L1/L2 hops | External review |
| C6 — robustness (optional; guaranteed output delivery after blame) | SPEC §11.2, §11.4; PROOF §8.4 | PROOF §8.4 header: "Lemma C6 (robustness) and the abort-distribution lemma — [proved here]". SPEC §11.4: "Robustness (C6) and abort-distribution indistinguishability (§11.3(4)) are **proved in proof §8.4**" | C3 (public commitments) + `n − f ≥ T` honest remainder + `T` points determining a degree-`(T−1)` polynomial | External review; implemented and fault-tested in the reference crates (`tests/blame_matrix.rs` robust variants) |
| L1 — extraction/programming of the commit-reveal DKG (rushing adversary) | SPEC §11.3(1), §11.5; PROOF §6 | PROOF §6 header: "[proved here, ROM]". SPEC §11.5 Status: "This closes L1 for the game-based proof in the ROM" | ROM (query-log extraction + reveal-time programming, no rewinding) | Remaining per SPEC §11.5: "(i) a fully written hybrid lemma with the complaint-round bookkeeping (engineering rigor, not a new idea); (ii) UC — … expected to port to UC-ROM with care … but this is not claimed; (iii) the joint-uniformity lemma for the real protocol under concurrent sessions (§11.3(5))" |
| L2 — Feldman hiding of never-opened values | SPEC §11.3(2), §11.6; PROOF §7 | PROOF §7 header: "[(a) proved here; (b) named assumption; (c) sketched]"; §7.3 header: "[proved here]" (bookkeeping discharged: DLEQ representation extractor, basis induction, simultaneous embedding with no factor-`Q` union loss). SPEC §11.6: "L2's parts are now written in the proof document" | (a) single instance ≡ DL — reduction only; (b) L2-OMDL: "named, not proved" plain-model alternative; (c) AGM form: AGM+ROM, any algebraic distinguisher yields ECDLP | External review; (b) stays a named assumption for the plain-model route only |
| Composition lemma — session hygiene (multi-session, distinct `sid`s) | SPEC §11.3(5); PROOF §8.1 | "[proved here]" (PROOF §8.1 header) | ROM domain separation (`sid` in every RO input) + C4 per session + L2 applied once globally; bound = factor-`Q` union | Closed at the game-based level; in UC the composition theorem replaces it (UC itself is roadmap) |
| Re-randomization lemma (multiplicative `k′ = γk`, §9.4 mitigation) | SPEC §9.4, §11.3(8); PROOF §8.2 | PROOF §8.2 header: "[proof sketch with one named formal gap]"; §8.2.4 Status: "**Proof sketch** — every case of the attack is now analyzed rather than asserted … with one named heuristic remaining before this is a theorem: G1 …, plus the model note that the case-(3) plug-in lives in the GGM"; §8.2.6 closing: "[proof sketch; all cases analyzed; one heuristic and one model note named]". SPEC §9.4 and §11.3(8): "proof sketch" (consistent after the label-drift fix) | Cases (1)–(2) ROM; case (3) plug-in in the GGM via GS21 Thm 6 (entropy-preservation generalization); G1 F-uniformity heuristic. Bound: `O(q_H²/q) + O(q_s·q_H/q) + Adv_GS21-Thm6` | G1 closed (proof of F-uniformity, or its explicit acceptance as the lineage-standard heuristic — meanwhile empirically probed, `analysis/g1_probe.sage`); external review. Implementation stays "experimental and default-off" meanwhile |
| G1 — F-uniformity heuristic (x-coordinate map uniform enough to model `Φ` as random) | PROOF §8.2.4, §8.2.6; `analysis/README.md` | PROOF §8.2.6: "Named heuristic (the one assumption in this lemma)" — heuristically assumed, **not proved**; also required by the GS21 attack being mitigated. Probe results: "Small-scale empirical support for G1 — cited as such, not as a proof" (`analysis/README.md`) | Heuristic over ECDLP + ROM | A proof (or formal acceptance) of the F-uniformity bound; larger-scale empirical work. Empirical probe: `analysis/g1_probe.sage` (SageMath; fitted exponents birthday 0.47–0.53 / preimage 0.97–1.00 across eight adversarial strategies; Wagner 4-sum positive control recovers 0.305 vs predicted 0.33; full log `analysis/g1_probe_results.txt`) |
| UC port (overall) | PROOF §9 | Section title: "UC: a porting roadmap (not a proof)"; §9.5: "This section is the porting plan; nothing here blocks the current paper, the audit, or deployment review." | Would be Canetti UC with `ℱ_GRO`, `ℱ_AUTH`, `ℱ_BC` (PROOF §10); GS22svc as template | The two hard spots of §9.3: UC-DKG (now U3, below) and a UC presignature-ECDSA result, which "does not exist" — "a research item, not a port" |
| Theorem U1 — UC/game-based realization of `ℱ_TECDSA` | PROOF §10.4, §12, §13.4 | §10.4: "Status: **framework set (this section); simulator construction pending (U3)**" — superseded by §12–§13. §13.4 (updated): "**Theorem U1 (game-based):** *OHM-ECDSA realizes `ℱ_TECDSA` (static corruptions, honest majority) in the EC-GGM+ROM, under the Groth–Shoup presignature-ECDSA assumption.* … the §7.3 representation bookkeeping is now written …, so its only named debt is the external-review pass." "**Theorem U1 (UC):** unchanged — the roadmap of §9–§11 plus the same trapdoor mechanism …; the ε′-obstruction was the last novel obstacle, and §13.2 is the candidate answer." | EC-GGM+ROM; GS-EUF; §13.3 simulator trapdoor | External review; for UC: the §9–§11 roadmap plus re-verifying the trapdoor simulation in the UC model |
| Theorem U2 — unforgeability plug-in | PROOF §10.4 | "Status: **proof sketch (§8.2.4), gaps G1/G2 named**" (note: only "G1" is defined in §8.2.4; no "G2" is defined anywhere — see inconsistencies below) | GS-EUF + the re-randomization analysis §8.2 (ROM cases + GGM plug-in) | Same closure items as the re-randomization lemma (G1, external review) |
| Theorem U3 — UC security of the commit-reveal DKG against rushing | PROOF §10.4, §11 | §10.4: "Status: **proved in §11 at the level of the hybrid argument** (delicate points P1–P3 explicit; realization bookkeeping for `ℱ_BC` and the per-restart union-bound expansion remain as indexing work, §11.6)". §11.6: "**Proved here:** the hybrid argument of §11.4 in full … **Not claimed:** UC security with *adaptive* corruptions …; UC with dishonest majority …; liveness under full asynchrony" | UC `ℱ_GRO`-hybrid; deferred-content programming (no rewinding); §4.2 expulsion budget | Bookkeeping only: the `ℱ_BC` realization theorem written out, the per-restart union bound expanded, the benign-programmability note folded into a GUC-style statement (§11.6) |
| ε′-opening obstruction + simulator-trapdoor resolution (SPEC §13-ref; PROOF §12–§13) | PROOF §12.2, §13 | Obstruction lemma §12.2: "stated and proved" (header: "The obstruction, stated and proved"). Resolution §13: earlier formulation "stated the assumption incorrectly … trivially false" — retracted and corrected (§13.3); §13.4: the trapdoor mechanism resolves the obstruction with its "only named debt … the external-review pass"; Path A (Pedersen for `⟦x⟧`) "remains the fallback if a reviewer finds a defect in the trapdoor simulation" | EC-GGM+ROM (reduction samples `x*` in challenger role; no new hardness assumption — "the trapdoor is not an assumption at all; it is simulator state", §13.3) | External review of the §13.2 perfect-fidelity simulation |
| §11.3(3) — presignature-consumption invariant | SPEC §11.3(3); PROOF §1 | "This is an *implementation* assumption, not a cryptographic one — state it explicitly in any deployment's security policy." In PROOF §1 the state machine (`fresh → consumed/poisoned`) is folded into `ℱ_TECDSA` itself | Implementation: atomic consume, key-binding, secure erase (SPEC §8.6) | Nothing cryptographic; deployment policy must carry it |
| §11.3(4) — abort-leakage accounting | SPEC §11.3(4); PROOF §8.4 | SPEC §11.3(4): "~~Abort-leakage accounting~~ — **closed in proof §8.4**"; PROOF §8.4: "abort-distribution indistinguishability … [proved here]" — every abort trigger is a boolean predicate over public verification outcomes, so no separate leakage term | Public verifiability of all blame rules (C3) | External review |
| §11.3(7) — GS21 parameter accounting for §9.4 HD tweaks | SPEC §11.3(7) | Open policy choice: "A full proof must either restate C5 in the AKD model with the §9.4 pool-bounding constraints as explicit assumptions, or restrict the theorem to the no-tweak case and treat tweaks as a deployment-layer feature" | GS21 AKD model (cube-root generic bound) | The stated either/or: AKD-model restatement, or theorem restricted to no-tweak; outstanding-records-per-key treated as a security parameter |

## Explicit non-claims (verbatim anchors)

- Static corruptions only — "this spec claims **static** only" (SPEC
  §11.3(6)); "Not claimed: UC security with *adaptive* corruptions …;
  UC with dishonest majority …; liveness under full asynchrony" (PROOF
  §11.6).
- UC overall: "a porting roadmap (not a proof)" (PROOF §9 header).
- UC porting of L1: "expected to port to UC-ROM with care … but this is
  not claimed" (SPEC §11.5).
- The C4 bias lemma's lattice-attack translation: "We do not claim more
  than this" (PROOF §4.2).
- L2 plain-model route: "named, not proved" (PROOF §7.2).
- Re-randomization: "Until G1 closes, the mitigation remains
  experimental and default-off in the implementation" (PROOF §8.2.4).
- "The UC proof has no remaining novel obstacle" (PROOF §11.6) is a
  statement about obstacles, not a completed UC proof.
- Whole-directory store rollback "stays undetectable"; prevention
  "remains a deployment concern" (SPEC §13.3).
- "§11 is a security *sketch*, not a proof" and the code is unaudited
  (SPEC §13.6).

## Cross-document inconsistencies (first-pass findings — all reconciled)

The first version of this document reported six SPEC-vs-PROOF
inconsistencies without touching the sources. All six have since been
fixed at the source; recorded here so the audit trail survives:

1. **Re-randomization label** — SPEC §9.4's "Status: proved" outran
   SPEC §11 and PROOF §8.2 ("proof sketch"). Fixed: SPEC §9.4 now reads
   "proof sketch … modulo one named heuristic (G1) and a GGM model note".
2. **Dangling "G2"** — PROOF §8.2.6/§10.4 referenced "gaps G1/G2" with
   G2 never defined. Fixed: both now read "gap G1 and the model note".
3. **Assembled-claim model label** — the v0.2 header said plain ROM
   while §8.3 says AGM+ROM and §13.4 says EC-GGM+ROM. Fixed: the header
   now states the assumption base per component.
4. **L2 status drift** — SPEC §11.6 said the hiding lemma "still has to
   be written". Fixed: SPEC §11.6 now points at proof §7's written parts.
5. **Probe ratio** — PROOF §8.2.6 quoted 1.0001 vs the archived run's
   1.0000. Fixed to match `analysis/g1_probe_results.txt`.
6. **Stale Path A/B recommendation** — PROOF §12.4 recommended a Path B
   literature check that §12.3 already recorded as DONE (negative).
   Fixed: §12.4's recommendation now records the §13 resolution and
   Path A's fallback status.
7. **Commit-title labels outrunning the page (git history, immutable).**
   Two commit titles dropped the qualifier the document carried at the
   same commit: `eb3d612` ("Theorem U3 proved: commit-reveal DKG is
   UC-secure against rushing" — the page then, as now, read "proved in
   §11 **at the level of the hybrid argument**" with `ℱ_BC`-realization
   and union-bound indexing remaining), and `bbc6890` ("Re-randomization
   lemma PROVED (modulo F-uniformity)" — walked back in `b8415ca`'s
   honest relabeling). Public history is deliberately **not** rewritten:
   the qualifier on the page is the status, and this entry is the
   reconciliation. Current status labels are the ones in the table above.

## How to verify

Tests corroborate behavior; they do not discharge proof obligations.

- **Core suite** — `cargo test -p ohm-ecdsa`: unit tests plus
  `tests/e2e.rs` (end-to-end 2-of-3 / 3-of-5, every signature verified
  with k256 and low-`s` checked, fault-injection tests asserting the
  blamed party via `Error::Abort` for keygen/triples/presign/sign,
  §10.4 robust variants, §10.3 expel-and-restart, §8.7 KI mode, §9.4 HD
  tweak) and `tests/examples.rs`.
- **Node suite** — `cargo test -p ohm-ecdsa-node`: wire-level blame
  consistency (`node/tests/party_mesh.rs`, `party_offline.rs`,
  `party_robust.rs`), §4.7 echo-consistency / F8 equivocation
  (`echo_consistency.rs`), process-level full arcs and cheats
  (`process_demo.rs`), store rollback detection (`persist.rs`), network
  resilience (`resilience.rs`).
- **Blame matrix** — `tests/blame_matrix.rs`: the consolidated SPEC §10
  F1–F8 fault-injection suite (each fault class injected via the tamper
  hooks, exact `phase` + `blamed` asserted, §10.4 robust
  blame-and-continue variants, framing-freeness control; the header's
  mapping table documents F7 as unreachable by construction and F8 as
  wire-level, covered in `node/tests/echo_consistency.rs`).
- **Property tests** — `tests/properties.rs` (proptest): the algebraic
  invariants (Shamir reconstruction, VSS homomorphism, verified openings,
  DLEQ, triple multiplicativity, presign/sign invariants) under
  randomized inputs.
- **Test vectors** — `tests/vectors.rs` + `tests/vectors/*.vec`:
  byte-pinned deterministic keygen/presign/sign outputs (regenerate with
  `OHM_BLESS_VECTORS=1`); each sign vector re-parsed and k256-verified.
- **Wire decoders** — `fuzz/` (cargo-fuzz/libFuzzer, dev tool): the
  canonical `Decode` implementations fuzzed for panic-freedom and
  canonical-input handling; see `fuzz/README.md`.
- **G1 probe** — `sage analysis/g1_probe.sage` (deterministic, a few
  minutes): small-scale empirical pressure-test of the F-uniformity
  heuristic behind the re-randomization lemma; results and
  interpretation in `analysis/README.md`, full log in
  `analysis/g1_probe_results.txt`. Small-scale evidence, not a proof.
