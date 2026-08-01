# Traceability — claims → code → tests

A reviewer-facing map from every security-relevant assertion in `SPEC.md`,
`docs/THREATMODEL.md`, and `docs/PROOF_STATUS.md` to (a) the code that
discharges it and (b) the tests that exercise it — including the
**negative/fault test** that proves each check actually FIRES. The goal: full
coverage verification in an afternoon.

Conventions:

- Every pointer was verified against the tree (function names grepped, test
  names taken from `cargo test -- --list`). If a row's test name does not
  exist, that is a bug in this document, not in the suite.
- **GAP** marks a claim with no direct test. A GAP is a finding about the
  suite, not about the code.
- **Structural** marks a claim enforced by construction (no runtime check
  exists to fire) or unreachable by design — no negative test is possible;
  the row cites the code/argument instead.
- Tests corroborate behavior; they do not discharge proof obligations
  (`docs/PROOF_STATUS.md` "How to verify"). Proof-level claims with no
  possible code test are collected in §13.
- Test counts: core `cargo test -p ohm-ecdsa` = 30 unit + 49 e2e +
  20 blame-matrix + 12 proptest + 6 vectors + 5 example smoke tests; node
  `cargo test -p ohm-ecdsa-node` = 109 (see `AGENTS.md` for the per-file
  breakdown).

## 1. Identifiable abort — the F1–F8 blame matrix (SPEC §10.1, §11.2 C3)

The systematic index lives in `tests/blame_matrix.rs` (its doc-comment table
is the class → hook → test mapping; duplicated here with the implementation
pointers added). Every matrix test asserts the EXACT blame set via
`assert_abort` (`tests/blame_matrix.rs:66`) — the cheater, and only the
cheater.

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| F1 — reveal hash ≠ committed hash blames the dealer (KeyGen/Triples/Presign P1) | `src/protocol/dkg.rs::DkgInstance::finalize` (R1 commit vs R2 reveal) | `protocol::dkg::tests::dkg_consistency` | `tests/blame_matrix.rs::f1_reveal_hash_mismatch_blames_dealer` (message-level decoy reveal; no sim hook exists — noted in the test) |
| F2 — dealt share fails `v_j·G == EvalCom(A, j)`; §6.1 complaint blames the dealer | `src/primitives/vss.rs::FeldmanCommitment::verify_share`; `src/protocol/dkg.rs::resolve_complaint` | `primitives::vss::tests::commit_and_verify`; `tests/properties.rs::vss_verify_accepts_dealt_rejects_perturbed` | `tests/blame_matrix.rs::f2_keygen_bad_deal_blames_dealer` (`DkgTamper::bad_deal`); wire-level: `node/tests/party_mesh.rs::party_keygen_blames_cheating_dealer_via_wire_complaints`, `node/tests/mesh_keygen.rs::mesh_keygen_blames_cheating_dealer`, `node/tests/process_demo.rs::process_demo_dkg_cheater_named_by_all_via_wire_complaints` |
| F2 — §6.1 false accusation blames the ACCUSER (defense verifies) | same path (`resolve_complaint` — dealer's defense share checked publicly) | — (the accusation path is the negative test of F2) | `tests/blame_matrix.rs::f2_keygen_false_accusation_blames_accuser` (`DkgTamper::corrupt_share`); `node/tests/party_mesh.rs::party_keygen_blames_false_accuser`, `node/tests/party_offline.rs::party_triples_blames_false_accuser`, `node/tests/process_demo.rs::process_demo_false_accuser_named_by_all` |
| F2 — wrong re-shared share (Triples T2/T3) | `src/protocol/triples.rs` T3 re-share check (`verify_share` against the re-sharing commitment) | `protocol::triples::tests::triple_is_multiplicative`; `tests/properties.rs::triples_are_multiplicative` | `tests/blame_matrix.rs::f2_triples_bad_reshare_blames_dealer`, `f2_presign_triple_session_fault_blames_dealer` (`TripleTamper::bad_reshare`); `node/tests/party_offline.rs::party_triples_blames_bad_reshare_via_wire_complaints`, `node/tests/process_demo.rs::process_demo_triples_bad_reshare_named_by_all` |
| F2 — §13.4 refresh/re-share faults (bad deal; commitment not bound to the old share) | `src/protocol/refresh.rs::refresh` / `reshare` (zero-constant check; `C_j.points[0] == EvalCom(A[x], j)`) | `tests/e2e.rs::refresh_preserves_key_and_enables_signing`, `reshare_to_new_committee_signs` | `tests/blame_matrix.rs::f2_refresh_bad_deal_blames_dealer`, `f2_reshare_bad_deal_blames_dealer`, `f2_reshare_bad_commitment_blames_dealer` (`ReshareTamper`); `tests/e2e.rs::refresh_cheating_dealer_is_blamed`, `reshare_cheating_dealer_is_blamed` |
| F3 — invalid DLEQ product proof blames the prover (Triples T2; §7.3 batch) | `src/primitives/dleq.rs::verify` / `verify_batch` (aggregate check + per-proof fallback) | `primitives::dleq::tests::dleq_roundtrip`, `batch_verify_matches_individual`; `tests/properties.rs::dleq_prove_verify_roundtrip` | `tests/blame_matrix.rs::f3_triples_bad_product_proof_blames_prover`, `f3_batch_triples_bad_proof_blames_prover` (`TripleTamper::bad_product_proof_at`); `tests/e2e.rs::triples_bad_product_proof_is_blamed`, `batch_triples_one_bad_proof_blames_prover`; `tests/properties.rs::dleq_rejects_tampered_proof_and_wrong_statement`; `node/tests/party_offline.rs::party_triples_blames_bad_product_proof` |
| F4 — opening share fails the commitment check blames the sender (Presign P2/P4; §4.6) | `src/primitives/open.rs::open` (THE verified-opening subprotocol — all openings route here) | `primitives::open::tests::open_ok_and_blame`; `tests/properties.rs::open_reconstructs_from_honest_shares` | `tests/blame_matrix.rs::f4_presign_bad_open_share_blames_sender` (`PresignTamper::bad_open_share`); `tests/properties.rs::open_blames_single_wrong_share`; `node/tests/party_offline.rs::party_presign_blames_bad_open_share`, `node/tests/process_demo.rs::process_demo_presign_bad_open_share_named_by_all` |
| F5 — nonce point `R_j ≠ EvalCom(A[k], j)` blames the sender (Presign P3) | `node/src/party/party.rs` presign driver P3 + `src/protocol/presign.rs` (point-equality nonce check) | `tests/e2e.rs::presign_sign_end_to_end_invariants` (proptest) | `tests/blame_matrix.rs::f5_presign_bad_nonce_point_blames_sender` (`PresignTamper::bad_nonce_point`); `node/tests/party_offline.rs::party_presign_blames_bad_nonce_point`, `node/tests/process_demo.rs::process_demo_presign_bad_nonce_point_named_by_all` |
| F6 — sign share `s_j·G ≠ EvalCom(m·A[u]+r·A[z], j)` blames the sender (Sign S2) | `src/protocol/sign.rs::combine` / `combine_robust` (per-share point equality before interpolation) | `tests/e2e.rs::e2e_2_of_3` (and every `assert_valid`) | `tests/blame_matrix.rs::f6_sign_bad_share_blames_sender`; `tests/e2e.rs::sign_cheater_is_identified`; `tests/e2e.rs::robust_sign_fails_without_t_valid_shares`; `node/tests/party_robust.rs::party_sign_robust_names_cheater_and_delivers`, `node/tests/process_demo.rs::process_demo_sign_cheater_named_and_signature_delivered` |
| F7 — final `(r,s)` fails ECDSA verification (Sign S3) | **Structural — unreachable by construction.** Every share is point-verified against `m·A[u]+r·A[z]` before interpolation (`sign.rs::combine`), so a combine that passed S2 cannot yield a failing signature; neither crate has a final-verify-then-blame path. No reachable injection point (documented in the `tests/blame_matrix.rs` header table). | indirectly witnessed by every `assert_valid` in `tests/e2e.rs` / `tests/blame_matrix.rs` / `tests/vectors.rs` | none possible |
| F8 — broadcast equivocation: two conflicting sender-signed values in one slot (§4.7 rule (3)) | `node/src/net/transport.rs` `Acceptor::process` (signed-echo rule: `T−1` echoes from parties OTHER than the sender; a conflicting sender-signed pair poisons the slot to `⊥` and is held as evidence) | `node/tests/echo_consistency.rs::echo_of_unsigned_value_is_dropped_and_honest_keygen_completes` | `node/tests/echo_consistency.rs::equivocating_sender_never_splits_honest_acceptance` (honest acceptance never splits; the constructed blame token audits VALID); quorum-rule units: `net::transport::tests::sender_self_echo_does_not_count_toward_quorum`, `party::party::tests::sender_self_echo_does_not_count_toward_quorum`. Not expressible in the core `SimTransport` (delivers identical accepted sets) — wire-level only, as the matrix header states |
| Framing-freeness (C3 second clause): an honest party is NEVER blamed | the blame checks themselves (every check fires only on a publicly verifiable deviation) | `tests/blame_matrix.rs::honest_robust_drivers_blame_nobody` (positive control: honest run through the blame-reporting drivers reports zero blame) | every matrix test asserts the EXACT blame set (an extra blamed party fails `assert_abort`); the false-accusation tests above are the dedicated framing attempts |
| §10.4 robustness: blame-and-continue delivers the signature (GOD) despite up to `t−1` cheaters | `src/primitives/open.rs::open_robust`, `src/protocol/sign.rs::combine_robust`, `src/protocol/triples.rs::generate_robust`, `src/protocol/presign.rs::presign_robust`; `node/src/party/party.rs` robust drivers | `tests/e2e.rs::robust_sign_excludes_cheater_and_delivers`, `robust_sign_tolerates_t_minus_1_cheaters`, `robust_presign_bad_open_share_completes`, `robust_presign_bad_nonce_point_completes`, `robust_triples_bad_reshare_recovers` | `tests/blame_matrix.rs::robust_f6_sign_completes_and_blames`, `robust_f6_sign_tolerates_t_minus_1_cheaters`, `robust_f4_presign_completes_and_blames`, `robust_f5_presign_completes_and_blames`, `robust_f2_triples_completes_and_blames`; the non-continuable boundary pinned by `robust_f3_bad_product_proof_still_aborts` / `tests/e2e.rs::robust_triples_bad_product_proof_aborts`; wire: `node/tests/party_robust.rs` (10 tests incl. `party_triples_robust_reconstructs_bad_reshare`, `party_triples_robust_blames_false_requester`) |

## 2. Presignature single-use (SPEC §8.6 MUSTs; §11.3(3) implementation obligation)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| §8.6(1) atomic consume, exactly-once (in-memory) | `src/runtime/store.rs::PresigStore::consume` (transactional delete) | `tests/e2e.rs::presig_store_enforces_single_use` (first sign succeeds) | same test: second `run_sign_stored` with the consumed id fails `Error::PresigStore`; `tests/e2e.rs::presig_store_unknown_id` |
| §8.6(1) duplicate-id rejection (nonce-reuse guard) | `src/runtime/store.rs::PresigStore::insert`; `node/src/store/persist.rs::DiskPresigStore::insert` | — | `tests/e2e.rs::presig_store_rejects_duplicate_insert`; `node/tests/persist.rs::disk_store_rejects_duplicate_insert_after_reopen` (live, consumed, and across reopen) |
| §8.6/§13.4 epoch-change invalidation (`clear`) | `src/runtime/store.rs::PresigStore::clear` | `tests/e2e.rs::refresh_preserves_key_and_enables_signing` | `tests/e2e.rs::refresh_invalidates_presignatures` (stale-id signing fails `Error::PresigStore` after refresh) |
| §8.6(1) durable single-use: tombstone fsync'd BEFORE the record is handed out (crash can never double-sign) | `node/src/store/persist.rs::DiskPresigStore::consume` | `node/tests/persist.rs::disk_store_survives_reopen` | `node/tests/persist.rs::disk_store_consumed_stays_consumed_across_restart` (sign → "restart" → second sign with the same id fails), `crash_mid_consume_heals_at_open` (crash between tombstone fsync and journal append heals consumed), `party_arc_restart_keeps_consumed_ids` |
| A7 durable burn of a failed production id (never re-issued) | `node/src/store/persist.rs::DiskPresigStore::burn` (`OP_BURN` journal op + `<id>.expired` tombstone, covered by `max_seen_id`) | `node/tests/pool.rs::pool_restart_counts_persisted_records_toward_target` (ids resume above the persisted max) | `node/tests/persist.rs::disk_store_burn_never_inserted_id` (burn survives reopen; live-id burn refused) |
| §8.6(3) secure erase on expiry (pool TTL) | `node/src/party/pool.rs::PoolManager` + `node/src/store/persist.rs::DiskPresigStore::expire` (sealed file removed, `<id>.expired` tombstone, id burned) | `node/tests/pool.rs::pool_refills_to_target_under_drain`, `pool_ttl_zero_never_expires` | `node/tests/pool.rs::pool_expires_records_and_never_serves` (expired record erased and burned: consume/re-insert rejected), `legacy_sealed_v1_record_accepted_with_mtime_fallback` |
| §8.6(4) no cross-key use | **Structural**: one `PresigStore` per key; binding cannot be re-verified from commitments (`z = u·x` has no linear public relation — `src/runtime/store.rs` module docs), so the binding is by construction. The durable store pins the key on disk. | `node/tests/persist.rs::disk_store_survives_reopen` | `node/tests/persist.rs::disk_store_rejects_wrong_key` (reopen under a different key rejected). In-memory binding: no check exists to fire — by construction |

## 3. Key-independent pool (SPEC §8.7)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| §8.7 single-use remains mandatory for key-free records | `src/runtime/store.rs::KiPool::consume` / `insert` (same §8.6(1) discipline, no key binding) | `tests/e2e.rs::ki_pool_signs_for_two_different_keys` (ONE pool signs for TWO independent keys, each signature verifying under its own `X`) | `tests/e2e.rs::ki_sign_single_use_enforced` (atomic consume + duplicate-id rejection); `node/tests/party_ki.rs::party_ki_pool_signs_for_two_different_keys` (pool single-use enforced over the wire) |
| §8.7 KI records are NOT key-equivalent (P1–P3 verbatim, P4 omitted) | `src/protocol/presign.rs::presign_ki`; `node/src/party/party.rs::presign_ki` (shared `presign_p1_p3` helper) | `node/tests/party_ki.rs::party_ki_full_arc_signs_under_own_key`; `node/tests/process_demo.rs::process_demo_ki_full_arc` | (no fault class unique to key-freeness — the P1–P3 classes are F1–F5 above) |
| §8.7 online binding preserves identifiable abort (K1 openings, K2 shares) | `src/protocol/sign.rs::ki_z_share` / `ki_z_com` / `sign_share_ki` / `combine_ki` / `combine_ki_robust` | as above (full KI arcs) | `tests/e2e.rs::ki_sign_cheater_is_identified` (bad R1 opening share and bad R2 share — `Error::Abort`, `Phase::Sign`); `node/tests/party_ki.rs::party_ki_sign_blames_bad_open_share`; `node/tests/party_robust.rs::party_sign_ki_robust_continues_bad_open_share`, `party_sign_ki_robust_blames_bad_sign_share_and_delivers` |

## 4. Store rollback detection (A4; SPEC §13.3 — detection, not prevention)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| A4: a spent id showing LIVE again is refused at startup as ROLLBACK DETECTED | `node/src/store/persist.rs::DiskPresigStore::open` — hash-chained `journal.log` (`entry_hash = H(tag ‖ seq ‖ op ‖ id ‖ prev_hash ‖ payload_hash)`) cross-checked against the sign transcript | `node/tests/persist.rs::disk_store_survives_reopen` | `node/tests/persist.rs::store_rollback_is_detected_and_refused` (store backup restored over an intact transcript → refused, naming the spent id; downgraded to a warning by `open_unverified`) |
| A4: journal/record/tombstone tampering fails closed | same (`open` verifies the chain against the directory) | — | `node/tests/persist.rs::journal_tampering_fails_closed` (`PersistError::Integrity`) |
| A4: crash windows heal in the safe direction | same (tombstone-before-journal ordering) | — | `node/tests/persist.rs::crash_mid_consume_heals_at_open` |
| Whole-directory rollback stays undetectable — startup WARNING, not refusal (documented residual risk; prevention needs state outside the directory) | `node/src/store/persist.rs::open_unverified` / the unverifiable-integrity warning path | — | `node/tests/persist.rs::whole_dir_rollback_passes_with_startup_warning` (pins the WARNING behavior and demonstrates the re-issuable spent id — this test documents the non-claim, it does not close it) |

## 5. Blame tokens and non-repudiation (SPEC §10.2, §A.4)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| §10.2 every protocol message is sender-signed over `(sid, phase, round, payload)`; forgery/tampering blames the claimed sender | `src/runtime/transport.rs::SignedEnvelope` / `SigningTransport` (domain-separated under `tags::TRANSPORT_SIGN`) | `runtime::transport::tests::signing_transport_roundtrip`, `drive_dkg_signed_honest_run` | `runtime::transport::tests::signing_transport_rejects_wrong_key`, `signing_transport_rejects_tampered_payload`; wire-level: `node/tests/mesh_keygen.rs::mesh_drops_forged_frames_and_completes` |
| §A.4 a blame token verifies OFFLINE against the party-key registry | `src/runtime/transport.rs::BlameToken::verify`; `node/src/store/persist.rs::audit_token` (the `auditor` subcommand) | `runtime::transport::tests::drive_dkg_signed_yields_blame_token`; `node/tests/persist.rs::audit_token_verifies_and_rejects_tampered`, `audit_sign_share_token_verifies` (F2/F6 token files); `node/tests/process_demo.rs::process_demo_auditor_verifies_and_rejects_token` (exit 0 = VALID); `node/tests/party_robust.rs::party_sign_robust_blames_cheater_and_archives_token` (archived F6 token verifies offline at every node) | `runtime::transport::tests::blame_token_rejects_forgery_and_wrong_registry` (forgery + wrong registry); the tampered-copy rejections inside the persist/process tests above; `examples/blame_token.rs` (smoke-tested by `tests/examples.rs::example_blame_token` — includes forgery rejection) |

## 6. Signature validity, verification independence, reproducibility

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| Every emitted signature verifies under the joint key with k256's INDEPENDENT verifier, and is low-`s` (BIP-62/EIP-2) | `src/runtime/sim.rs::run_sign*` and `node/src/party/party.rs` sign drivers (`sig.normalize_s().unwrap_or(sig)`); check helper `assert_valid` (`tests/e2e.rs:27`, `tests/blame_matrix.rs:54`) | all 49 e2e tests with signatures; `node/tests/party_mesh.rs::party_sign_produces_valid_low_s_signature`; `tests/vectors.rs::vector_sign_2_of_3_msg1` / `vector_sign_2_of_3_msg2` (each sign vector k256-verified + low-s asserted against the vector's own key) | the F6 row (§1) is the fault side; low-s is asserted unconditionally in `assert_valid` (a high-`s` regression fails every sign test) |
| Deterministic reproducibility: fixed seeds regenerate byte-identical artifacts | `src/runtime/sim.rs::make_rngs` + the canonical `Encode` format; committed vectors under `tests/vectors/` pinned byte-for-byte (incl. per-party secret shares — the strongest regression catch) | `tests/vectors.rs::vector_keygen_2_of_3`, `vector_keygen_3_of_5`, `vector_presign_2_of_3_id1` / `id2`, `vector_sign_2_of_3_msg1` / `msg2`; `tests::session_id_is_deterministic_and_domain_separated`; `tests/e2e.rs::rerand_gamma_is_deterministic_and_domain_separated` | bless mode (`OHM_BLESS_VECTORS=1 cargo test -p ohm-ecdsa --test vectors`) rewrites the files — any silent byte drift fails the comparison runs |
| Algebraic invariants hold for arbitrary inputs (proptest) | the primitives themselves | `tests/properties.rs`: `shamir_any_t_points_reconstruct_secret`, `shamir_interpolate_at_matches_eval_at`, `shamir_reconstruction_is_subset_independent`, `vss_verify_accepts_dealt_rejects_perturbed`, `vss_homomorphic_ops`, `vss_add_sum_zero_pad_mixed_lengths`, `open_reconstructs_from_honest_shares`, `dleq_prove_verify_roundtrip`, `triples_are_multiplicative`, `presign_sign_end_to_end_invariants` | `tests/properties.rs::open_blames_single_wrong_share`, `dleq_rejects_tampered_proof_and_wrong_statement` (the negative sides are properties too: perturbation ⇒ rejection) |

## 7. Secrets at rest (H5; SPEC §8.6(2)/(3), §13.3)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| Secret-holding structs erase their scalars on `Drop` (zeroize, compiler-fenced) | `impl Drop for ShamirPoly` (`src/primitives/shamir.rs:20`), `DkgOutput` (`src/protocol/dkg.rs:76`), `Presignature` (`src/protocol/presign.rs:69`), `KiPresignature` (`src/protocol/presign.rs:111`), `TripleShare` (`src/protocol/triples.rs:51`) | **GAP** — no test observes post-Drop memory (the erasure is a best-effort hardening measure; observation would require reading freed memory). The load-bearing assumption IS pinned: `primitives::shamir::tests::scalar_zeroize_is_native` fails loudly if a k256 upgrade drops `Scalar: Zeroize` | — |
| Long-lived node secrets are `mlock` page-locked — FAIL-OPEN with a loud warning when the OS refuses (the only fail-open path in H5) | `node/src/store/locked.rs::LockedSecret` / `LockedBytes` | `store::locked::tests::locked_secret_roundtrip_contents_intact`, `locked_bytes_roundtrip_contents_intact`, `empty_and_zst_locking_is_a_noop` | `store::locked::tests::mlock_failure_fails_open_with_contents_intact` (pins the documented fail-open policy) |
| Secret files are ChaCha20-Poly1305 AEAD-sealed at rest, versioned, purpose-bound, `0600`; legacy cleartext rejected fail-closed | `node/src/store/seal.rs::StorageKey` / `StorageKeySource` | `store::seal::tests::seal_open_roundtrip`, `generated_storage_key_roundtrips_and_is_0600`, `secret_files_are_written_0600`; `node/tests/persist.rs::keyshare_seal_roundtrip_and_fail_closed` | `store::seal::tests::tampering_and_wrong_purpose_fail_closed`, `wrong_key_is_an_error_not_garbage`, `legacy_cleartext_is_rejected_explicitly` |
| A5 storage-key sourcing: helper-command → env → keyfile → generated; a configured-but-failing source NEVER silently generates | `node/src/store/seal.rs::StorageKeySource` | `store::seal::tests::command_source_valid_hex_resolves`, `source_precedence_command_env_keyfile_generated` | `store::seal::tests::command_source_nonzero_exit_is_a_hard_error`, `command_source_garbage_stdout_is_a_hard_error`, `command_source_timeout_is_a_hard_error`, `failing_command_source_never_falls_back_to_generated` |

## 8. Wire-decode safety on untrusted input (SPEC §13.1; fuzz)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| Canonical decoders never panic, never over-allocate on an untrusted length prefix, and reject non-canonical encodings | `src/runtime/transport.rs` `Decode` impls (length-prefixed, no serde); node size bounds `node/src/net/wire.rs::FrameBound::variant_max` / `max_frame` | `runtime::transport::tests::wire_roundtrip_scalar_and_point` (incl. the identity point), `wire_roundtrip_feldman_commitment`, `wire_roundtrip_dkg_messages`, `wire_roundtrip_envelope_and_signed_envelope` | `runtime::transport::tests::wire_decode_rejects_malformed` (truncation, non-canonical scalars, bad tags), `wire_decode_rejects_oversized_commitment_len`; fuzzed: `fuzz/fuzz_targets/decode_arbitrary.rs`, `decode_dkg_message.rs`, `decode_signed_envelope.rs` (cargo-fuzz/libFuzzer — dev tool, `fuzz/README.md`); wire-level: `node/tests/resilience.rs::garbage_flood_dropped_honest_session_completes` |
| DoS guards only drop/delay; verification is never weakened | `node/src/net/mesh.rs` (frame-rate windows, accept-rate window, handshake caps, bounded mailbox — counted in `MeshMetrics`) | `node/tests/resilience.rs::garbage_flood_dropped_honest_session_completes` (honest keygen completes under garbage), `concurrent_factory_and_signing` | `node/tests/resilience.rs::accept_rate_cap_counts_poke_flood` (raw poke flood counted), `node/tests/mesh_keygen.rs::mesh_drops_forged_frames_and_completes` (forged/unknown-sender/malformed frames dropped) |

## 9. Parameter and policy enforcement

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| Honest majority enforced at construction: `Params`/`Committee` reject `n < 2t−1` (SPEC §2.1) | `src/lib.rs::Params::new` (:56) and `Committee::new` (:92) — `Error::InvalidParams("honest majority requires n >= 2t - 1")` | every test constructs valid params through these constructors | `lib::tests::params_and_committee_enforce_honest_majority` (boundary shape accepted; `Params::new(2,2)`, `t = 0`, id 0, duplicate ids rejected; non-contiguous §10.3 survivor sets accepted). Also `tests/e2e.rs::packed_mode_rejects_undersized_committee` for the §7.4.1 packed-sizing check (`n ≥ 2t+2B−3`) |
| §10.3 expel-and-restart NEVER lowers `t`; zero-slack refusal | `src/runtime/policy.rs::restart_committee`; sim wrappers `sim::run_*_with_restart`; node drivers `party.rs::keygen_with_restart` / `presign_with_restart` | `runtime::policy::tests::restart_committee_with_and_without_slack`; `tests/e2e.rs::keygen_restart_expels_cheater_and_recovers`, `presign_restart_still_restarts_on_dealing_fault` (id poisoned, survivors' original ids), `presign_restart_robust_handles_opening_fault_in_attempt`, `triples_restart_robust_recovers_reshare_fault_in_attempt`; `node/tests/party_robust.rs::party_keygen_restart_completes_over_survivors_original_ids`, `party_presign_restart_completes_3_of_6`; `node/tests/process_demo.rs::process_demo_restart_open_share_cheater_named_and_signature_delivered` | `tests/e2e.rs::presign_restart_refused_without_slack` (2-of-3 — no silent `t`-lowering); `tests/e2e.rs::triples_restart_restarts_on_bad_product_proof`; `node/tests/party_robust.rs::party_presign_restart_refused_zero_slack`; `node/tests/process_demo.rs::process_demo_restart_dealing_cheater_refused_zero_slack` |

## 10. Timing, resilience, fail-closed rounds (SPEC §2.2; H2)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| A silent peer fails its round LOUDLY on the round timeout (no parked threads, fail-closed) | `node/src/net/transport.rs` round collection timeout; `node/src/party/party.rs` drivers | — | `node/tests/resilience.rs::silent_peer_round_timeout_fails_loudly` |
| Reconnection with backoff + journal re-sync completes in-flight sessions | `node/src/net/mesh.rs` reconnect + re-sync | `node/tests/resilience.rs::reconnect_after_drop_completes_keygen` (`reconnects >= 1`) | (the dropped connection IS the fault injection in the same test) |
| Clean shutdown, idle and mid-session (all threads joined) | `node/src/net/mesh.rs::Node::shutdown`, `node/src/party/party.rs::PartyNode::shutdown` | `node/tests/resilience.rs::shutdown_idle_and_inflight` | (mid-session shutdown is the fault side of the same test) |
| A7 soak: continuous operation with per-session fault injection and kill/restart/rejoin — blame lands ONLY on armed parties | `node/src/main.rs::run_soak_node` / `run_soak_demo`; `node/src/party/pool.rs::PoolManager::tick_tolerant` | `node/tests/process_demo.rs::process_demo_soak_fault_injection` (`--fault-rate 0.9`: every sign delivers, blame only on armed parties, exit 0), `process_demo_soak_node_restart` (sealed key-share reload — same `X`, reconnects ≥ 1, end-of-soak A4 audit passes) | both soak tests are fault-injection runs by construction |

## 11. Transport authentication and ceremony trust root (SPEC §13.1; M3c, H3)

| Claim | Implementation | Positive test | Negative/fault test |
|---|---|---|---|
| mTLS pinned to the committee: handshakes accept ONLY pinned certs, no PKI roots, NO plaintext fallback; nodes fail closed on own-key/cert mismatch | `node/src/net/tls.rs::CommitteeTls` (TLS 1.3, ring) | `node/tests/mesh_tls.rs::tls_full_arc_signs_under_own_key`; `node/tests/process_demo.rs::process_demo_tls_full_arc`; `net::tls::tests::pinned_server_verifier_accepts_only_the_pinned_cert`, `pinned_client_verifier_accepts_committee_rejects_strangers` | `node/tests/mesh_tls.rs::tls_rejects_unpinned_peer_cert` (rogue cert rejected in BOTH directions, every node fails closed), `tls_rejects_plaintext_peer`; `net::tls::tests::from_der_rejects_inconsistent_material` |
| H3 distributed ceremony: `assemble` validates bundles; tampered `.pub` bundles fail the node closed at startup | `node/src/setup/ceremony.rs::init` / `assemble` / `fingerprint` | `node/tests/process_demo.rs::process_demo_distributed_ceremony_full_arc`; `setup::ceremony::tests::identity_and_pub_roundtrip` | `node/tests/process_demo.rs::process_ceremony_assemble_rejects_duplicate_id`, `process_ceremony_node_fails_closed_on_tampered_pub` (swapped cert, swapped transport key); `setup::ceremony::tests::assemble_validates_the_committee_shape`, `fingerprint_depends_on_every_field`, `assemble_mixed_tls_posture_rejected` |

## 12. Also covered (not headline claims, listed for completeness)

- §9.4 HD tweak (additive derivation): `tests/e2e.rs::hd_tweak_derivation`; EXPERIMENTAL re-randomization (default-off): `rerand_signature_verifies`, `rerand_with_tweak_verifies_under_child_key`, `rerand_share_commitment_check_catches_cheater`.
- Packed mode (§7.4): `tests/e2e.rs::packed_triples_are_multiplicative`, `packed_presign_and_sign`, `packed_mode_b1_matches_base`, `packed_triples_cheater_is_blamed`, `packed_mode_rejects_undersized_committee`.
- Batching (§7.3/§8.5): `tests/e2e.rs::batch_triples_are_multiplicative`, `batch_presign_sign_distinct_messages`, `batch_presign_cheater_is_identified`.
- §13.4 epoch management beyond the F2 rows: `tests/e2e.rs::reshare_to_overlapping_committee_signs`, `refresh_invalidates_presignatures`.
- Transport-seam consistency (§4.7 model): `runtime::transport::tests::sim_transport_delivers_consistently`, `drive_dkg_reconstructs_joint_key`; `tests/e2e.rs::keygen_via_transport_driver_signs_end_to_end`.
- A6 operability: `node/tests/metrics.rs::snapshot_after_full_arc_has_sane_counters`, `reporter_writes_interval_and_final_blocks`.
- Narrative examples (living documentation, every signature k256-verified): `tests/examples.rs::example_wallet_2_of_3`, `example_consortium_custody`, `example_identifiable_abort`, `example_blame_token`, `example_epoch_refresh`.

## 13. Claims with no possible code test (proof-level / ops-level)

Listed so a reviewer does not mistake their absence from §1–§12 for a GAP.
Status labels are in `docs/PROOF_STATUS.md`; none of these is
code-testable even in principle:

- **C2 privacy, C4 nonce uniformity, C5 unforgeability reduction, L1/L2,
  the composition lemma** — proof obligations (ROM/AGM/EC-GGM); tests can
  only corroborate the underlying mechanics (which §1/§6 do).
- **G1 F-uniformity heuristic** — empirical only: `analysis/g1_probe.sage`
  (results in `analysis/README.md`), cited as small-scale evidence, not a
  proof.
- **§10.5 abort-leakage** — "every abort decision is a function of public
  verification outcomes"; corroborated structurally by the blame matrix
  (all blame derives from public checks), not provable by test.
- **Constant-time / side-channel posture** — inherited from `k256`
  (SPEC §13.3); no test in this repo can establish it.
- **Whole-directory rollback PREVENTION** — an explicit non-claim
  (SPEC §13.3); the startup-warning behavior is pinned by
  `whole_dir_rollback_passes_with_startup_warning` (§4).
- **Ops trust assumptions** (`docs/THREATMODEL.md` §3) — out-of-band
  fingerprint confirmation as the trust root, an OS CSPRNG per party in
  production, storage-key custody/KMS, shipping `transcript.log` off-box.
  These are deployment duties; the code can only fail closed when they are
  violated detectably (which §11 tests).

## Coverage summary

- **46 claims mapped** across §1–§11 (13 identifiable-abort, 7 store
  single-use, 3 KI pool, 4 rollback, 3 non-repudiation, 3 validity/
  reproducibility, 3 secrets-at-rest, 2 wire safety, 2 params/policy,
  4 resilience, 2 transport/ceremony).
- **42 with a dedicated negative/fault test** (the check is proven to
  fire).
- **3 structural / no-negative-test-possible** (F7 unreachable by
  construction; §8.6(4) in-memory key binding; whole-directory rollback
  warning — a documented non-claim pinned by its test).
- **1 GAP** (a claim with no direct test — finding, below; the
  honest-majority enforcement GAP found by this map's first pass was
  closed by `lib::tests::params_and_committee_enforce_honest_majority`).

### GAPs

1. **Zeroize-on-`Drop` erasure** (the five `Drop` impls listed in §7): no
   test observes that dropping a secret-holding struct actually erases its
   memory. The mechanism assumption is pinned
   (`scalar_zeroize_is_native`), but the `Drop` wiring itself is untested
   — hard to test without reading freed memory (which needs `unsafe`, and
   the core crate is `#![forbid(unsafe_code)]`); a `Zeroize`-on-drop
   regression would currently pass the suite silently.

### Minor partials (not full GAPs)

- Node-level per-variant frame size bounds (`FrameBound::variant_max`)
  have no dedicated unit test; they are exercised indirectly by
  `garbage_flood_dropped_honest_session_completes` and the core
  `wire_decode_rejects_oversized_commitment_len`.
- The F7 row is covered only by the construction argument plus universal
  `assert_valid` witnessing — no negative test can exist (see §1).
