# FTO Briefing Package — OHM-ECDSA

**Prepared for patent counsel reviewing freedom to operate.**
This package is engineering analysis prepared for legal review. It is not
legal advice and does not itself constitute an FTO opinion. All primary
materials referenced below are in this repository or publicly available.

**Author of the work:** Alp Guneysel (GitHub: ungaro)
**Date:** 2026-07-31
**Repository:** https://github.com/ungaro/ohm-ecdsa (specification:
`SPEC.md`; paper: `docs/paper/`; reference implementation: `src/`)

---

## 1. What the work is

OHM-ECDSA is an open, honest-majority (`n ≥ 2T−1`) threshold ECDSA
protocol over secp256k1, with one-round online signing and identifiable
abort at every broadcast, built exclusively from public-domain components
published 1989–2007 (Shamir sharing, Feldman VSS, commit-then-reveal
Pedersen DKG, Beaver triples, Chaum–Pedersen DLEQ proofs) plus openly
published presignature algebra (Groth–Shoup 2021; Katz, NIST MPTS 2023).
It was designed specifically to avoid the claim elements of two
encumbered protocols and is published as defensive prior art.

## 2. The patents in question

### 2.1 US Patent 11,757,657 B2 ("the '657 patent")

- Title: *Method for providing a digital signature to a message*
- Inventors: Jakobsen, Damgård, Østergaard, Nielsen
- Original assignee Sepior ApS; **current assignee Blockdaemon ApS**
  (change of name recorded 2023-12-14; Blockdaemon acquired Sepior in
  July 2022)
- Granted 2023-09-12; adjusted expiration **2040-08-16**; WO 2020/177977,
  EP priority 2019-03-05 (the family extends beyond the US)
- 10 claims: one independent method claim, nine dependents
- Verbatim granted claim 1 and the element-by-element mapping are in
  `SPEC.md` §12.2 (quoted from the granted text for claim-chart purposes)
- This is the patent covering DJNPO20 (*Fast Threshold ECDSA with Honest
  Majority*, IACR ePrint 2020/501), per Jonathan Katz's NIST MPTS-2023
  presentation ("appears covered by US Patent 11,757,657 assigned to
  Sepior ApS")

### 2.2 The KU24 / Dfns protocol

- Katz & Urban, *Honest-Majority Threshold ECDSA with Batch Generation of
  Key-Independent Presignatures*, IACR ePrint 2024/2011
- Described by the authors' employer **Dfns** on its own blog as "this
  patented protocol"; Dfns has stated intent to open-source it and lift
  the patent via LF Decentralized Trust (their `cggmp21` crate was moved
  to the LFDT "Lockness" organization, consistent with that intent)
- The distinction analysis is in `SPEC.md` §12.3

## 3. The design-around, in one paragraph

Claim 1 of the '657 patent is a conjunctive combination whose core
elements are: computing a masked product `[w] = [a][k]`; an authenticator
`W = R^a` with the check `g^w == W`; deriving the nonce inverse as
`[k⁻¹] = [a]·w⁻¹`; and computing `[s] = m·w⁻¹[a] + r·w⁻¹[a][x] + [d]`
with `[d]` a random sharing of zero. **OHM-ECDSA contains none of these:**
the inverse is dealt directly as a random sharing `[u] = [k⁻¹]` (no
inversion protocol exists); all products are computed by Beaver triples
over degree-`T−1` sharings (no zero-sharings exist anywhere in the
protocol); and correctness is ensured by point equality against public
Feldman commitments (a different mechanism with a different result — it
identifies the cheater, while the claimed procedure's own three-party
example "can not determine which of the parties is dishonest").

## 4. Evidence artifacts for counsel

| Artifact | Location | What it shows |
|---|---|---|
| Claim chart (verbatim claim 1, 9 elements E1–E9 mapped) | `SPEC.md` §12.2 | Literal-infringement analysis |
| Surface-similarities subsection | `SPEC.md` §12.2.1 | Candor on shared prior-art elements |
| Dependent claims 2–10 table | `SPEC.md` §12.2 | Zero-sharings, degree-2t, preprocessing set, Paillier embodiment |
| KU24 distinction + key-independence prior art | `SPEC.md` §12.3 | DJNPO20 (2020) and cait-sith (2022) predate KU24's priority |
| Prior-art wall (1989–2023) | `SPEC.md` §12.5 | Defensive-publication framing |
| Absence of claim elements in code | `src/` (verifiable by inspection) | No `w`, no `W`, no authenticator, no zero-sharing types exist |
| Reference implementation behavior | `tests/e2e.rs`, `examples/` | Beaver-triple multiplication, direct inverse dealing, point-equality checks |

## 5. Questions for counsel

1. **Literal infringement.** Do you concur that omission of elements E3
   (`[w]=[a][k]`), E5 (honest-share-counting correctness check), E6–E8
   (the `W` authenticator and `g^w==W` check), and the specific
   derivation `[k⁻¹]=[a]·w⁻¹` with zero-sharing `[d]` in E9 defeats
   literal infringement of claim 1 under the all-elements rule — and that
   dependent claims 2–10 fall with it (or read on admitted prior art)?
2. **Doctrine of equivalents.** Please assess DoE risk for the two
   substitution points: (a) direct dealing of the inverse vs. masked-product
   inversion; (b) Feldman point-equality correctness vs. honest-share
   counting — both of which we argue differ in *way* and (for (b)) in
   *result* (identification vs. mere detection).
3. **KU24 posture.** Our default presignatures are key-dependent (bound
   at generation). The optional key-independent mode (SPEC §8.7) defers
   binding to signing time using ordinary commit-reveal machinery — not
   KU24's batch pipeline (no coordinator, no KU24 packing). Please
   evaluate our prior-art argument (key-independence per DJNPO20 2020
   and cait-sith 2022, before KU24's priority date) against Dfns's
   claimed scope, and advise whether the optional mode should be
   documented, feature-flagged, or removed before public release.
4. **Jurisdictions.** The '657 family extends to WO 2020/177977 with EP
   priority 2019-03-05. Please advise on EP (and other jurisdiction)
   exposure for a commercial custody deployment.
5. **Defensive publication.** The spec, paper, and code are public with
   git history; archiving (ePrint/arXiv/timestamping services) has been
   discussed but not yet executed. Please advise on the evidentiary form
   you would want for establishing prior-art dates (and whether the
   existing git history suffices for your purposes).
6. **Trade-secret/clean-room posture.** The protocol was designed from
   public papers and the granted patent text; no confidential Sepior/
   Blockdaemon or Dfns material was used. Please confirm this posture
   suffices, or advise what additional documentation of independent
   development you would want.

## 6. Disclaimers

This briefing and the referenced §12 analysis are engineering documents.
Claim construction and infringement are legal questions for qualified
counsel in the relevant jurisdictions. Nothing here is legal advice.
