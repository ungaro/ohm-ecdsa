# Threat Model — OHM-ECDSA

Reviewer-facing consolidation of the security model. Every statement is
cited to its source; nothing here strengthens what the source says.
`SPEC.md` is the authoritative specification; `docs/proof/PROOF.md` is
the proof working document; `docs/runbook.md` is the operator runbook.
Per-claim proof status lives in `docs/PROOF_STATUS.md`.

**Scope note.** OHM-ECDSA is an unreviewed protocol draft with an
unaudited reference implementation — research artifacts, not for
securing real assets (SPEC §13.6).

## 1. The security model in scope

- **Honest majority.** `n` servers, signing threshold `T`, `n ≥ 2T−1`;
  the adversary controls up to `T−1` servers (SPEC §2.1; enforced by
  `Params::new` in `src/lib.rs`).
- **Static, malicious, rushing corruptions.** The corruption set is
  chosen before the protocol starts; the adversary is active and rushing
  within each round (SPEC §2.1; PROOF §1, §10.1).
- **Timing.** Rounds are logical; **liveness** assumes partial
  synchrony; **safety** (no key/signature leakage, no forgery) does not
  depend on timing (SPEC §2.2). In the proof architecture the timing
  assumption lives only in the realization of the broadcast
  functionality `ℱ_BC`, not in the protocol layer (SPEC §11.1; PROOF §1,
  §10.5).
- **Channels.** Authenticated point-to-point channels; all protocol
  messages are signed by their sender over `(sid, phase, round,
  payload)` for non-repudiation (SPEC §2.2, §10.2, §13.1). The reference
  node adds an OPTIONAL committee-pinned mTLS layer (TLS 1.3, no PKI, a
  development stand-in for a deployment's own PKI); envelope signatures
  stay on regardless (SPEC §13.1).
- **Broadcast.** Signed-echo consistent broadcast (SPEC §4.7): accept
  `m` from `i` on `i`'s valid signature plus echoes from `T−1` distinct
  parties other than `i`, with no conflicting sender-signed value seen;
  a conflicting pair forces `⊥` and blames the sender (fault class F8).
  Consistency of accepted sets rests on the §2.2 partial-synchrony
  assumption (conflicting evidence propagates within the round wait).
- **Identifiable abort.** Every broadcast value is verified against
  public Feldman commitments by point equality; any deviation at a
  broadcast step is detected and attributed to specific parties (SPEC
  §2.3, §4.6, §10; detection is information-theoretic, attribution is
  computational — PROOF §3). A malicious party can always force an
  abort, but never anonymously (SPEC §2.3, §10).
- **Presignatures.** Single-use and key-equivalent: `T` shares of the
  same presignature yield the long-term key `x`. Implementations MUST
  consume atomically, store shares with key-share-grade protection,
  securely erase after use or expiry, and never use a record across keys
  (SPEC §2.4, §8.6 MUSTs 1–4). The consumption invariant is an
  *implementation* obligation, stated as such in the proof obligations
  (SPEC §11.3(3)).
- **Storage posture (reference node, §13.3).** Secrets erased on `Drop`
  via `zeroize`; long-lived secrets wrapped in `mlock` buffers at the
  node boundary — **fail-open with a loud warning** when the OS refuses,
  so swap protection is an ops duty, not a guarantee. Secret files are
  sealed with ChaCha20-Poly1305 under a per-node storage key (`0600`;
  legacy cleartext rejected fail-closed). Store rollback (un-consuming
  spent presignatures by restoring an old directory) is **detected and
  refused** via the hash-chained journal plus sign-transcript
  cross-check; a *whole-directory* restore stays undetectable (startup
  warning) — rollback **prevention** needs state outside the directory
  (HSM monotonic counter or peer attestation) and remains a deployment
  concern.

## 2. Explicitly out of scope / not claimed

- **Adaptive/mobile corruptions** — static only (SPEC §1.3, §11.3(6);
  PROOF §11.6 "Not claimed": UC with adaptive corruptions, where the
  deferred-content trick does not obviously survive).
- **Dishonest majority** — different regime, not addressed (SPEC §1.3;
  PROOF §11.6).
- **UC security** — a porting roadmap, not a claim (PROOF §9, titled "a
  porting roadmap (not a proof)"). Theorem U3 (UC-DKG against rushing)
  is proved **at the level of the hybrid argument** with `ℱ_BC`
  realization bookkeeping remaining (PROOF §10.4, §11.6); Theorem U1
  (UC) is "unchanged — the roadmap of §9–§11 plus the same trapdoor
  mechanism … §13.2 is the candidate answer" (PROOF §13.4). UC with
  dishonest majority and liveness under full asynchrony are explicitly
  not claimed (PROOF §11.6).
- **The re-randomization mitigation (SPEC §9.4)** — a proof sketch with
  all attack cases analyzed, resting on the named F-uniformity heuristic
  **G1** and a model note (the case-(3) plug-in is in the GGM while
  cases (1)–(2) are ROM) (SPEC §11.3(8); PROOF §8.2.4, §8.2.6). G1 is
  empirically probed, not proved — small-scale evidence only
  (`analysis/g1_probe.sage`; results and "cited as such, not as a proof"
  caveat in `analysis/README.md`). The mitigation is EXPERIMENTAL and
  default-off in the implementation.
- **Idealized-model reach.** The game-based claim is assembled in the
  AGM+ROM under ECDLP plus the Groth–Shoup presignature-ECDSA assumption
  (PROOF §8.3); the §13.4 U1 statement is in the EC-GGM+ROM; the L2
  hiding hop's plain-model alternative is a *named, not proved*
  `(T−1)`-OMDL assumption (PROOF §7.2). No plain-model result is
  claimed.
- **Side channels** — `H(M)`, tweak handling, and network timing are out
  of scope; constant-time arithmetic comes from `k256` (SPEC §1.3,
  §13.3). HSM-backed share storage is a deployment concern (SPEC §13.3).
- **DoS beyond the documented guards** — the node crate's guards
  (frame-rate windows, size bounds, accept-rate windows, handshake caps,
  bounded mailboxes) only drop/delay; verification is never weakened
  (SPEC §13.3). No broader liveness-under-attack claim is made.
- **Fairness of signature release ordering** — abort is always possible;
  fairness of delivery only via the optional §10.4 robustness variant
  (SPEC §1.3, §9.5).
- **Production readiness** — §11 is a security *sketch*; §12 is
  engineering analysis, not legal advice; a full game-based or UC
  treatment plus independent implementation review are prerequisites to
  production use (SPEC §11 header, §13.6).

## 3. Trust assumptions a deployment actually makes

- **A fixed, vetted committee.** Honest majority is the model for
  key-management networks — a fixed, vetted set of servers (SPEC §1.1).
  Vetting is ops, not code.
- **The ceremony's out-of-band step is the trust root.** Real committees
  use the distributed H3 ceremony: each party runs `init` on its OWN
  machine, `.pub` bundles are exchanged over an authenticated channel,
  and EVERY party's fingerprint is confirmed on a second channel — "this
  step is the trust root — ops, not code" (`docs/runbook.md` §2). The
  one-process `setup`/`spawn-demo` ceremony is DEMO-ONLY. Nodes fail
  closed at startup when their own key/cert does not match the registry.
- **An OS CSPRNG per party.** The deterministic `sim::make_rngs` seeds
  are tests-only; production must use an OS CSPRNG per party (SPEC
  §13.2). Nonce uniformity is security-critical (SPEC §4.3).
- **Transport authentication as deployed.** The node's committee-pinned
  mTLS is a development stand-in for the deployment's own PKI; envelope
  signatures are always on (SPEC §13.1). Runbook §8 requires mTLS on
  every link, no plaintext reachability.
- **Storage-key custody.** The `OHM_STORAGE_KEY_CMD` helper is "the KMS
  plug-in point — not a KMS": key custody and rotation remain deployment
  concerns; a configured-but-failing helper fails closed, never silently
  generates (SPEC §13.3; runbook §3, §8).
- **Rollback-detection independence.** The detection cross-check is only
  as independent as its evidence: runbook §8 requires shipping
  `transcript.log` off-box; prevention itself needs an HSM monotonic
  counter or peer attestation (SPEC §13.3; runbook §7–§8).
- **Presignature-pool policy.** Pools are query-protected: nonces/ids
  disclosed to external requesters only at signing time; outstanding
  records per key are bounded and consumed under exactly one
  `(key, tweak)` pair — a documented **security parameter**, not a
  performance knob (SPEC §9.4, §11.3(7)). With committee insiders, the
  honest security level of HD-tweak signing is the GS21 generic bound
  (~85 bits), not 128 (SPEC §9.4).
