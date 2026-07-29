# ohm-ecdsa-node — transport companion (reference code)

**Unaudited research code. Do NOT secure real assets with it.** See
`SPEC.md` §13 (and §13.6) for the full disclaimers; everything the core
crate says about being a reference implementation of an unreviewed
protocol draft applies here doubly — this crate adds a *network* to it.

This crate is the SPEC §13.1/§13.2 path "from the reference orchestrator
to production", driven over **real TCP** on `std::net` with blocking
threads and **no external async runtime** (tokio/rustls remain future
work). Milestones:

* **M1** — the orchestrator substrate: full-mesh TCP, length-prefixed
  framing of the core's canonical `Encode`/`Decode` wire format, §10.2
  signed envelopes verified on receipt, §4.7 echo broadcast
  (`MeshTransport` implementing the core `Transport` trait), keygen
  through `drive_dkg_signed`. One process holds every party's key.
* **M2** — per-party node drivers (`src/party.rs`): the orchestrator
  model is gone. A `PartyNode` holds ONLY its own material — its own
  transport secret key, its own party id, the peers' verifying keys, its
  own mesh connections — and runs only its own protocol logic. Each
  party runs as its own OS process (see the demo below).

## What M2 is

* **Key separation by construction.** `PartyNode::bind` takes exactly
  one `SecretKey` (this node's) plus the public registry; no `PartyNode`
  API accepts another party's secret material. A node process reads
  exactly its own seed file plus the public committee file
  (`src/seed.rs`).
* **Per-node keygen (SPEC §6)** over the mesh: commit → reveal + P2P
  shares → **§6.1 complaint subprotocol on the wire** — round 3 carries
  signed `Complaints` broadcasts, round 4 signed `Defenses` broadcasts,
  and every node adjudicates `EvalCom(A_d, j)` against the defense over
  its own echo-consistent accepted sets, so all honest nodes reach the
  SAME blame verdict: a verifying defense means a false accusation
  (accuser blamed); a failing or missing defense means a cheating
  dealer. The M1 shortcut (defenses read from dealer state in one
  process) is gone.
* **Per-node online signing (SPEC §9, §10.4)**: each node computes
  `sign_share` locally, broadcasts it (signed + echo), verifies every
  received share against `m·A[u] + r·A[z]` by point equality (bad shares
  are blamed and excluded), interpolates from the first `t` valid
  shares, low-`s` normalizes. A cheating signer is named by every node
  and the signature is still delivered.
* **Presignature distribution: seeded shortcut (documented).** Per-node
  presign through the mesh is **M3** — it needs the triple factory (§7)
  and the presign openings (§8) ported onto the wire the same way the
  DKG was, and M2 stops at keygen+sign rather than shipping something
  half-verified. For demos and tests, presignatures come from a prior
  orchestrated run — a "ceremony" (`seed::ceremony`) that writes one
  SECRET seed file per party (its transport key, its key share, its
  presignature records) and one PUBLIC committee file. Seed files are
  secret material on disk; retention/zeroization of files is a
  deployment concern (SPEC §13.3).
* **Process separation**: `spawn-demo` launches three child processes,
  each running `node` with only its own seed file; keygen and signing
  run across real OS processes on localhost TCP.
* **Liveness**: rounds complete when the accepted sets are complete or
  the round timeout fires — then the PARTIAL set is returned, logged
  loudly, and the drivers fail closed ("incomplete message sets"). Same
  policy as M1; timeout values are a deployment concern (SPEC §13.1).

## What M2 is still NOT

* **No TLS / mTLS.** Channels are authenticated only by the per-message
  ECDSA signatures (SPEC §13.1's mutually-authenticated-transport item).
* **No per-node presign** (M3, see above) — the demo's sign phase runs
  over the seeded ceremony key, not over the key the same processes just
  generated.
* **No blame-token persistence.** A §6.1 dealer fault leaves its signed
  share envelope (P2P) and signed defense (broadcast) on the wire —
  offline-verifiable evidence in the §10.2 sense — but archiving it is
  not implemented (M1's in-process `BlameToken` path still works for the
  orchestrator driver).
* **No persistence** of accepted-message sets, no reconnection after
  startup, no clean thread shutdown, no rate limiting, no DoS hardening
  beyond the 4 MiB frame cap and drop-on-bad-signature.
* **Not audited, not production anything.** localhost-scale demo and
  test scaffolding only.

## Demo

```sh
cargo run -p ohm-ecdsa-node -- spawn-demo           # 3 child processes: keygen + sign
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-sign-share
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-deal:1
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 3 --cheat false-accuse:1
cargo run -p ohm-ecdsa-node -- spawn-demo --delay-ms 50   # simulated WAN links
cargo run -p ohm-ecdsa-node -- m1-demo              # the M1 orchestrator demo
```

`spawn-demo` writes a ceremony committee to a temp dir (`--dir` to
override), launches the three child `node` processes, and prints
per-process logs, the joint key `X` (all three agree), the final
signature (verified), and any blame. With `bad-sign-share`, the other
two processes both name the cheater and all three still deliver the
signature; with `bad-deal`/`false-accuse`, keygen aborts consistently
naming the cheater (the seeded sign phase is independent and still
delivers).

To run parties by hand (separate terminals or machines):

```sh
cargo run -p ohm-ecdsa-node -- setup --dir /tmp/ohm-demo
cargo run -p ohm-ecdsa-node -- node --seed /tmp/ohm-demo/party-1.seed \
    --committee /tmp/ohm-demo/committee.hex --bind 127.0.0.1:7700 \
    --peers 1@127.0.0.1:7700,2@127.0.0.1:7701,3@127.0.0.1:7702
# ... party 2 on :7701, party 3 on :7702
```

## Benchmark

```sh
cargo run --release -p ohm-ecdsa-node --example mesh_perf
# [--iters K] [--delays 0,50,100]
```

Wall-clock keygen and online-sign times over the real mesh for 2-of-3
and 3-of-5, on localhost and with a configurable per-link artificial
send delay (send-side delay wrapper in the mesh) simulating a WAN;
reports medians in a small table. Presignatures are ceremony-seeded (the
documented M2 shortcut).

## Tests

```sh
cargo test -p ohm-ecdsa-node
```

* `node/tests/mesh_keygen.rs` (M1, 3 tests): orchestrated keygen over
  `MeshTransport`, a cheating dealer blamed with a verifying
  `BlameToken`, forged/unknown-sender/malformed frames dropped.
* `node/tests/party_mesh.rs` (M2, 6 tests, thread-level with strict
  per-node key separation): per-node keygen reconstructs the joint key
  (2-of-3 and 3-of-5); a cheating dealer is named by every node via the
  wire complaint/defense rounds; a false accuser is named by every node;
  per-node signing produces a valid low-`s` signature; a wrong signature
  share is blamed by every node and the signature is still delivered.
* `node/tests/process_demo.rs` (M2, 4 tests, REAL CHILD PROCESSES via
  `spawn-demo`): honest keygen+sign across 3 processes; a sign-share
  cheater named by the other two processes with the signature still
  delivered; a DKG cheater and a false accuser each named by all three
  processes via the wire complaint subprotocol.

## Layout

| Module | Role |
|---|---|
| `src/wire.rs` | `WireMessage<M>` (original / signed echo), canonical framing, signature validation — generic over the payload |
| `src/mesh.rs` | `Node<M>`: listener + full-mesh connections + reader threads, first-echo rule, verified-only mailbox, self-echo loopback (M2 per-node acceptor), config-driven send delay (benchmarks) |
| `src/transport.rs` | `MeshTransport` (M1): echo-broadcast acceptor + the core `Transport` trait impl over `DkgMessage` |
| `src/party.rs` | `PartyNode` + `NodePayload` (M2): per-node keygen driver with §6.1 complaints/defenses on the wire, per-node §9/§10.4 sign driver, per-node echo-broadcast acceptor, `Cheat` fault injection |
| `src/seed.rs` | the ceremony + seed/committee files (the documented M2 presignature-distribution shortcut) |
| `src/main.rs` | `node` / `setup` / `spawn-demo` / `m1-demo` subcommands |
| `examples/mesh_perf.rs` | the latency benchmark described above |
