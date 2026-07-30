# Fuzzing the canonical wire decoders (H1)

Property under test: the core's canonical `Decode` layer
(`src/runtime/transport.rs` — the decoders the node crate's frame parser
runs on UNTRUSTED network input) **never panics on arbitrary input, never
reads out of bounds, and roundtrips** (`decode(encode(x)) == x`, verified
via byte-identical canonical re-encoding).

## Setup

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer), a dev
tool only — the `fuzz/` crate is its own workspace (`[workspace]` in
`fuzz/Cargo.toml`), so the main workspace never builds it and the MSRV
(1.75) is unaffected. No new dependencies in either shipping crate.

```sh
cargo install cargo-fuzz            # one-time
rustup toolchain install nightly    # one-time
```

## Targets

* `decode_dkg_message` — arbitrary bytes → `DkgMessage::decode`; on
  success the value must re-encode and re-decode byte-identically.
* `decode_signed_envelope` — same for `SignedEnvelope<DkgMessage>`.
* `decode_arbitrary` — EVERY `Decode` impl (`Scalar`, `ProjectivePoint`,
  `Signature`, `FeldmanCommitment`, `DkgBcast1/2`, `DkgP2P`, `DkgMessage`,
  `Envelope<DkgMessage>`, `SignedEnvelope<DkgMessage>`) fed with the
  input AND every prefix of it (split points at every byte offset).

Seed corpora live in `fuzz/corpus/<target>/`: valid encodings of every
message type, truncations at every byte offset, byte flips, oversized
length prefixes (`u64::MAX` / `u32::MAX`), and garbage.

## Run

```sh
cd fuzz
cargo +nightly fuzz run --sanitizer none decode_dkg_message    -- -max_total_time=180 -rss_limit_mb=2048
cargo +nightly fuzz run --sanitizer none decode_signed_envelope -- -max_total_time=180 -rss_limit_mb=2048
cargo +nightly fuzz run --sanitizer none decode_arbitrary      -- -max_total_time=180 -rss_limit_mb=2048
```

Omit `-max_total_time` to run indefinitely; crashes land in
`fuzz/artifacts/<target>/` and the corpus grows in place (re-runs resume
from it). Triage a crash with
`cargo +nightly fuzz run --sanitizer none <target> fuzz/artifacts/<target>/<file>`.

**ASan caveat:** the default `--sanitizer address` build hangs at
startup on this dev machine (rustc 1.91.0-nightly 6c699a372,
macOS 26.5.2 aarch64) — the binary spins before libFuzzer's own `main`.
The Decode layer is 100% safe Rust (no `unsafe` in either crate), so
`--sanitizer none` still covers the stated property: libFuzzer catches
panics, and cargo-fuzz builds with debug assertions and overflow checks
enabled. Re-try ASan on a newer nightly with
`cargo +nightly fuzz run decode_arbitrary` (no `--sanitizer` flag).

## Status

Last run (2026-07-30): all three targets, 180 s each plus a 60 s probe
(`decode_dkg_message` alone: ~779k execs/61 s), corpus as committed.

* **Panics / OOB / roundtrip violations: none found.**
* One issue found BY INSPECTION while preparing the harness and fixed:
  `FeldmanCommitment::decode` looped over the untrusted point count
  without a pre-check; since identity points encode as a single byte,
  a `MAX_FRAME` (4 MiB) frame of `0x00` bytes would decode into a
  ~4M-entry `Vec<ProjectivePoint>` (~100× memory amplification).
  Fix: reject up front when the count exceeds the remaining byte count
  (every point encodes to ≥ 1 byte, so no valid encoding is affected —
  the wire FORMAT is byte-identical). Regression test:
  `wire_decode_rejects_oversized_commitment_len` in
  `src/runtime/transport.rs`.
