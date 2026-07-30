# ohm-ecdsa-node — transport companion (reference code)

**Unaudited research code. Do NOT secure real assets with it.** See
`SPEC.md` §13 (and §13.6) for the full disclaimers; everything the core
crate says about being a reference implementation of an unreviewed
protocol draft applies here doubly — this crate adds a *network* to it.

This crate is the SPEC §13.1/§13.2 path "from the reference orchestrator
to production", driven over **real TCP** on `std::net` with blocking
threads and **no external async runtime** (rustls for the optional M3c
mTLS layer). Milestones:

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
* **M3a** — the per-node OFFLINE FACTORY over the wire (`src/party.rs`):
  per-node triple generation (SPEC §7.2) and per-node presign (SPEC §8)
  as `PartyNode` drivers, with every share verified and every cheater
  named consistently at every node. The demo's full arc — keygen →
  presign → sign — now runs under the key each process's OWN keygen
  produced; ceremony-seeded presignatures remain as a `--seeded`
  fallback.
* **M3b** — persistence + blame-token archiving (`src/persist.rs`): a
  durable, crash-safe single-use presignature store per node per key
  (SPEC §8.6), an append-only transcript of every accepted signed
  envelope (§4.7), blame-token files for the fault classes that leave
  cryptographic evidence on the wire (§10.2), and an offline `auditor`
  subcommand re-verifying a token against the committee's public keys
  (§A.4). Everything on disk is the core's canonical `Encode`/`Decode`
  wire format; std only.
* **M3c** — OPTIONAL mTLS on the mesh (`src/tls.rs`): every connection
  wrapped in mutually-authenticated TLS 1.3 (rustls + ring, blocking
  streams) with certificates **pinned to the committee** — no PKI, no
  system roots. Plain TCP remains the default for localhost dev; any
  non-localhost deployment MUST run TLS (see below).

## What M2/M3a is

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
  process) is gone. The same machinery is factored out as
  `PartyNode::joint_vss` — one ephemeral joint random sharing over the
  wire — and reused by the offline factory.
* **Per-node triple generation (SPEC §7.2, M3a)**: T1 deals joint random
  ⟦α⟧, ⟦β⟧ through two `joint_vss` instances; T2 broadcasts
  `FeldCommit(g_j)` + ONE DLEQ product proof and sends the re-shares
  `g_j(i)` P2P; T3 verifies every proof (F3 ⇒ blame the prover — the
  same check everywhere, no complaint round) and every received re-share
  (F2 ⇒ the same wire §6.1 complaint/defense rounds as keygen), then
  combines with Lagrange weights. A bad DLEQ proof, a bad re-shared
  share, and a false accusation are each named consistently by every
  node.
* **Per-node presign (SPEC §8, M3a)**: two triple sessions plus two
  `joint_vss` instances (⟦u⟧, ⟦a⟧), then the Beaver openings δ/ε, v,
  δ′/ε′ and the nonce points `R_j` as broadcast rounds — every opening
  share checked against its public commitment by point equality, every
  nonce point against `EvalCom(A[k], j)` (F5 ⇒ blame the sender). ε′
  masks this node's OWN long-term key share. Openings are FAIL-FAST
  identifiable aborts: robust blame-and-continue (§10.4) stays with the
  core's sim and is deliberately NOT re-implemented at the wire level —
  the driver fails closed. `v = 0` / `r = 0` return `Error::ZeroValue`;
  the caller retries with a fresh presignature id (the demo treats it as
  fatal — probability ~2⁻¹²⁸ per session). Records are held in memory, or
  persisted by the M3b durable store when the node runs with
  `--data-dir` (below).
* **Per-node online signing (SPEC §9, §10.4)**: each node computes
  `sign_share` locally, broadcasts it (signed + echo), verifies every
  received share against `m·A[u] + r·A[z]` by point equality (bad shares
  are blamed and excluded), interpolates from the first `t` valid
  shares, low-`s` normalizes. A cheating signer is named by every node
  and the signature is still delivered.
* **Presignature distribution: self-produced by default; ceremony
  fallback.** With M3a the default demo presigns through the mesh under
  the key its own keygen produced. The M2 ceremony (`seed::ceremony`)
  remains as a fallback (`--seeded`): a prior orchestrated run writing
  one SECRET seed file per party (its transport key, its key share, its
  presignature records) and one PUBLIC committee file. Note the
  transport keys themselves still come from the seed files in both modes
  (the demo's §13.1 deployment-PKI stand-in). Seed files are secret
  material on disk; retention/zeroization of files is a deployment
  concern (SPEC §13.3).
* **Process separation**: `spawn-demo` launches three child processes,
  each running `node` with only its own seed file; keygen, presign, and
  signing run across real OS processes on localhost TCP.
* **Liveness**: rounds complete when the accepted sets are complete or
  the round timeout fires — then the PARTIAL set is returned, logged
  loudly, and the drivers fail closed ("incomplete message sets"). Same
  policy as M1; timeout values are a deployment concern (SPEC §13.1).

## What M3b adds (persistence + evidence)

A node run with `--data-dir DIR` (`spawn-demo --persist` gives each
child `DIR/node-i`) gets three artifacts, all in the core's canonical
`Encode`/`Decode` wire format (std only, no serde):

* **Durable presignature store (SPEC §8.6)** at `DIR/store`: one file
  per record (`<id>.presig`), a `key.bin` binding the directory to ONE
  long-term key (§8.6(4) — reopening under a different key is
  rejected). `insert` writes `<id>.tmp`, fsyncs the file, renames,
  fsyncs the directory. `consume(id)` reads the record, renames
  `<id>.presig` → `<id>.consumed`, fsyncs the directory, and only THEN
  returns the record: the tombstone is durable before the nonce can be
  used, so a killed-and-restarted node can never sign twice with the
  same presignature (§8.6(1) atomic consume across a crash). A crash
  between the rename and the return loses the record — the safe
  direction. Duplicate inserts (live OR consumed ids) are rejected with
  the core store's error semantics; stray `.tmp` files (crash
  mid-insert, never acknowledged) are deleted on open. The presign
  driver persists every record it produces; the sign driver consumes
  from the store.
* **Transcript archive (SPEC §4.7)** at `DIR/archive/transcript.log`:
  every ACCEPTED signed envelope appended as `u32 BE length ‖ canonical
  SignedEnvelope bytes`, fsync'd per entry. Append-only, deduped per
  `(sid, phase, round, from, to)` slot in memory (at-least-once across
  a restart).
* **Blame tokens (SPEC §10.2, §A.4)** at `DIR/archive/*.tok` +
  `aborts.log`: on an identifiable abort, a token file is written where
  the fault leaves cryptographic evidence on the wire — F2 dealt-share
  faults (the dealer's signed P2P share envelope + its revealed
  commitment; only the ACCUSER holds the P2P envelope, so only it
  produces the token) and F6 sign-share faults (the signed share +
  message, `r`, `A[u]`, `A[z]`). Other classes (false accusations, bad
  DLEQ proofs, bad nonce points, bad opening shares, bad re-shares) are
  logged to `aborts.log` with `token: none` — documented in
  `src/persist.rs`. The `auditor` subcommand verifies a token OFFLINE
  against the public committee file (see below).

Durability model, honestly: this survives process kill and — on a
cooperating filesystem/OS — machine crash at exactly the fsync points
above. It is NOT `mlock`/HSM-backed secret storage (presignatures are
key-equivalent, §8.6/§13.3), does no wear leveling, and does not defend
against a malicious host rolling back the directory.

## What M3c adds (optional mTLS)

Plain TCP (M1–M3b) authenticates every message with the §10.2 envelope
signatures, but nothing is encrypted in transit and there is no
transport-level peer authentication — anyone can open a TCP connection
to a node (its frames are dropped, but the endpoint is exposed). With
`--tls CERT KEY --pinned DIR` every mesh connection is wrapped in
**mutually-authenticated TLS 1.3** (rustls + ring, blocking streams —
still no async runtime):

* **Committee-pinned certificates, no PKI, no system roots.** Each
  party has a self-signed certificate (rcgen in the demo/tests); every
  node pins the EXACT certificate of every committee member
  (`--pinned DIR` reads the public `party-<id>.crt.pem` set). Outgoing
  connections accept only the pinned certificate of the party they
  connect to — the TLS peer identity IS the expected `PartyId`, so the
  transport-level and message-level (signed-envelope) identities are
  the same party. Incoming connections must present a pinned committee
  certificate; anything else (a stranger's cert, a plaintext peer) is
  rejected during the handshake with a loud log. There is NO fallback
  to plaintext once TLS is configured.
* **Threat-model delta.** TLS adds: confidentiality in transit (the
  protocol messages are commitments, masked openings and public
  points — leaks are not key-compromising per §10.5, but traffic
  analysis and metadata are) and transport-level peer authentication
  (only committee members can even complete a handshake). TLS does NOT
  add end-to-end accountability: that already comes from the §10.2
  per-message ECDSA signatures, which stay ON regardless — envelope
  verification is never weakened (defense in depth).
* **The wire format inside the TLS stream is unchanged** — the same
  length-prefixed canonical `Encode`/`Decode` frames of signed
  envelopes. TLS replaces only the confidentiality/peer-auth layer.
* **Cert guidance.** `setup --tls` / `spawn-demo --tls` generate
  per-party self-signed certs (`party-<id>.crt.pem` public,
  `party-<id>.key.pem` SECRET) — a development ceremony. Real
  deployments substitute their own PKI/certificate issuance and cert
  distribution (SPEC §13.1); the pinning verifiers in `src/tls.rs` are
  the reference. TLS is mandatory for any non-localhost deployment;
  plain TCP is for localhost dev and tests only.
* **MSRV note.** The pinned dependency tree (rustls 0.23.43 + ring,
  rcgen 0.14.7) builds with the workspace MSRV 1.75; the transitive
  pins in `node/Cargo.toml` (`time = "=0.3.36"`) and the lockfile
  (`base64ct 1.6.0`, `zeroize 1.8.2`) keep it that way — newer
  releases of those crates need edition2024 toolchains.

## What M3b/M3c is still NOT

* **No robust continuation at the wire level.** Openings and dealing
  phases are fail-fast: a cheater is named and the session aborts —
  recovery (§10.3 expel-and-restart, §10.4 blame-and-continue) lives in
  the core's sim and is not re-implemented in the per-node drivers.
* **No reconnection after startup**, no clean thread shutdown, no rate
  limiting, no DoS hardening beyond the 4 MiB frame cap,
  drop-on-bad-signature and (M3c) the mTLS handshake gate. The blocking
  TLS handshake has no timeout — a stalled peer parks a reader thread
  (localhost scale; a deployment concern, §13.1).
* **Not audited, not production anything.** localhost-scale demo and
  test scaffolding only.

## Demo

```sh
cargo run -p ohm-ecdsa-node -- spawn-demo           # 3 child processes: keygen → presign → sign
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-sign-share
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-product-proof
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-reshare:1
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-nonce-point
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-open-share
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 2 --cheat bad-deal:1
cargo run -p ohm-ecdsa-node -- spawn-demo --cheat-node 3 --cheat false-accuse:1
cargo run -p ohm-ecdsa-node -- spawn-demo --seeded  # M2 fallback: sign with ceremony presigs
cargo run -p ohm-ecdsa-node -- spawn-demo --delay-ms 50   # simulated WAN links
cargo run -p ohm-ecdsa-node -- spawn-demo --persist # M3b: durable stores + transcript/blame archive
cargo run -p ohm-ecdsa-node -- spawn-demo --tls     # M3c: the full arc over mTLS (rcgen certs, committee-pinned)
cargo run -p ohm-ecdsa-node -- spawn-demo --tls --persist --cheat-node 2 --cheat bad-sign-share
cargo run -p ohm-ecdsa-node -- spawn-demo --persist --cheat-node 2 --cheat bad-deal:1 --dir /tmp/ohm-demo
cargo run -p ohm-ecdsa-node -- auditor /tmp/ohm-demo/node-1/archive/blame-keygen-2.tok \
    /tmp/ohm-demo/committee.hex                 # offline §A.4 verification (exit 0 = VALID)
cargo run -p ohm-ecdsa-node -- m1-demo              # the M1 orchestrator demo
```

`spawn-demo` writes a ceremony committee to a temp dir (`--dir` to
override; in the default mode only the transport keys and the public
registry are used — the arc runs under the fresh key), launches the
three child `node` processes, and prints per-process logs with
per-phase timings, the joint key `X` (all three agree), the
self-produced presignature, the final signature (verified under the
FRESH X), and any blame. With `bad-sign-share`, the other two processes
both name the cheater and all three still deliver the signature; with
`bad-deal`/`false-accuse`, keygen aborts consistently naming the cheater
(presign/sign skipped); with `bad-product-proof`/`bad-reshare`, the
triple factory aborts consistently (`BLAME triples K`); with
`bad-nonce-point`/`bad-open-share`, presign aborts consistently
(`BLAME presign K`). With `--persist`, each child runs with a per-node
`--data-dir` (durable presignature store + transcript/blame archive,
M3b) — a cheater run leaves a `blame-*.tok` file in the accuser's
archive, which the `auditor` subcommand verifies offline.

To run parties by hand (separate terminals or machines — TLS mandatory
off localhost):

```sh
cargo run -p ohm-ecdsa-node -- setup --dir /tmp/ohm-demo --tls   # seeds + per-party certs
cargo run -p ohm-ecdsa-node -- node --seed /tmp/ohm-demo/party-1.seed \
    --committee /tmp/ohm-demo/committee.hex --bind 127.0.0.1:7700 \
    --peers 1@127.0.0.1:7700,2@127.0.0.1:7701,3@127.0.0.1:7702 \
    --tls /tmp/ohm-demo/party-1.crt.pem /tmp/ohm-demo/party-1.key.pem \
    --pinned /tmp/ohm-demo
# ... party 2 on :7701, party 3 on :7702 (each with its own cert/key)
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
* `node/tests/party_offline.rs` (M3a, 8 tests, thread-level with strict
  per-node key separation): per-node triples are multiplicative at the
  public commitments (2-of-3 and 3-of-5); a bad DLEQ product proof, a
  bad re-shared share (via the wire §6.1 rounds), and a false accusation
  are each named consistently by every node; a bad nonce point and a bad
  opening share are named in presign; the full arc keygen → presign →
  sign signs under the key the nodes' own keygen produced (valid low-`s`
  signature, all nodes agree).
* `node/tests/process_demo.rs` (M2/M3a/M3b/M3c, 12 tests, REAL CHILD
  PROCESSES via `spawn-demo`): honest full arc across 3 processes; a
  sign-share cheater named by the other two processes with the signature
  still delivered; a DKG cheater and a false accuser each named by all
  three processes (full arc and `--seeded` fallback); a bad DLEQ proof
  and a bad re-share named as `BLAME triples` by every process; a bad
  nonce point and a bad opening share named as `BLAME presign` by every
  process; the `--persist` full arc leaving fsync'd consume tombstones
  and decodable transcripts; a `bad-deal` token file verified by the
  `auditor` subcommand (exit 0, `VERDICT: VALID`) and a tampered copy
  rejected; the `--tls` full arc over mTLS (M3c).
* `node/tests/persist.rs` (M3b, 9 tests): the durable store survives
  drop/reopen, a consumed id stays consumed across a simulated crash,
  duplicate inserts are rejected (live and consumed ids, on reopen),
  wrong-key reopen is rejected, stray `.tmp` files are dropped; the
  transcript archive dedups and decodes; the F2 dealt-share and F6
  sign-share tokens verify offline and reject tampering and a wrong
  registry; crash-recovery integration — a node signs (consuming the
  record), "restarts" (a fresh store instance on the same directory),
  and a second sign with the same id fails.
* `node/tests/mesh_tls.rs` (M3c, 3 tests, thread-level) plus 3 unit
  tests in `src/tls.rs` and 1 process-level test in
  `node/tests/process_demo.rs`: the full arc keygen → presign → sign
  over mTLS (thread-level AND across child processes via
  `spawn-demo --tls`); an unpinned/rogue peer cert is rejected in both
  handshake directions and every node fails closed (no plaintext
  fallback, keygen cannot complete); a plaintext peer poking a TLS
  listener is dropped and the node still completes keygen with its
  real TLS peers; the pinning verifiers accept exactly the pinned cert
  and reject any other (unit level).

## Layout

| Module | Role |
|---|---|
| `src/wire.rs` | `WireMessage<M>` (original / signed echo), canonical framing, signature validation — generic over the payload |
| `src/mesh.rs` | `Node<M>`: listener + full-mesh connections + reader threads, first-echo rule, verified-only mailbox, self-echo loopback (M2 per-node acceptor), config-driven send delay (benchmarks), optional M3c mTLS wrapping (`bind_tls`) |
| `src/tls.rs` | M3c: `CommitteeTls` (own cert/key + the pinned committee cert set), committee-pinned TLS 1.3 client/server configs and blocking handshakes (rustls + ring), rcgen cert generation for tests/demos, the PEM file layout (`party-<id>.crt.pem` / `.key.pem`) |
| `src/transport.rs` | `MeshTransport` (M1): echo-broadcast acceptor + the core `Transport` trait impl over `DkgMessage` |
| `src/party.rs` | `PartyNode` + `NodePayload` (M2/M3a): per-node keygen driver with §6.1 complaints/defenses on the wire (factored as `joint_vss` + the wire complaint subprotocol), per-node §7.2 triple and §8 presign drivers (the M3a offline factory), per-node §9/§10.4 sign driver, per-node echo-broadcast acceptor, `Cheat` fault injection; M3b store/archive wiring (`presign_stored`, `sign_stored`, `store_offer`); M3c `bind_with_tls` |
| `src/persist.rs` | M3b: `DiskPresigStore` (§8.6 durable single-use store, write-tmp-rename + fsync, consume tombstone fsync'd before the record is handed out), `Archive` (§4.7 accepted-envelope transcript + `aborts.log`), `BlameEvidence` token files (F2 dealt-share, F6 sign-share; other classes `token: none`), `audit_token` offline verifier (§A.4) |
| `src/seed.rs` | the ceremony + seed/committee files (the `--seeded` fallback for presignature distribution; transport keys come from the seed files in both modes) |
| `src/main.rs` | `node` / `setup` / `spawn-demo` / `auditor` / `m1-demo` subcommands (`--tls` on `setup`/`node`/`spawn-demo` for M3c) |
| `examples/mesh_perf.rs` | the latency benchmark described above |
