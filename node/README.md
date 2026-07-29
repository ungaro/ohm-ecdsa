# ohm-ecdsa-node — M1 transport companion (reference code)

**Unaudited research code. Do NOT secure real assets with it.** See
`SPEC.md` §13 (and §13.6) for the full disclaimers; everything the core
crate says about being a reference implementation of an unreviewed
protocol draft applies here doubly — this crate adds a *network* to it.

M1 is the first milestone of the SPEC §13.1/§13.2 path "from the
reference orchestrator to production": the core crate's transport seam
(`Envelope` / `Transport` / `SignedEnvelope` / `drive_dkg_signed`) driven
over **real TCP** instead of the in-process `SimTransport`.

## What M1 is

* **Full-mesh TCP** on `std::net` with blocking threads and **no external
  async runtime** (tokio/rustls are deliberately M2). Each node listens
  on a port and opens one outgoing connection to every peer
  (config-driven `Vec<(PartyId, SocketAddr)>`; startup connect retries
  with backoff until the mesh is up, localhost scale).
* **Length-prefixed framing** (`u32` BE length + payload) of the core's
  canonical `Encode`/`Decode` wire format — no serde anywhere.
* **Signed envelopes on the wire** (SPEC §10.2): every protocol message
  is the core's `SignedEnvelope<DkgMessage>`, verified against the party
  key registry on receipt. Unknown sender or bad signature → drop + log;
  nothing unverified reaches the acceptor.
* **Echo broadcast** (SPEC §4.7): the sender broadcasts; every receiver
  echoes the first valid value per `(sid, phase, round, from)` slot to
  all (echoes are themselves signed by the echoer, so they are
  attributable); a value is *accepted* for sender `i` in a round once
  `⌈(n+1)/2⌉` **distinct parties other than `i`** echoed it. This yields
  consistency (no two honest parties accept different values for the same
  slot) and validity (an accepted value carries the sender's verified
  signature). The sender's own copy is never counted — counting it would
  let an equivocating sender reach the majority for two values at n = 3.
* **`MeshTransport`** implements the core
  `Transport<SignedEnvelope<DkgMessage>>` trait: `broadcast`/`send_p2p`
  push to the wire, `accepted_broadcasts`/`accepted_p2p` block on the
  mailbox until every committee member has an accepted value for the
  round. A generous timeout (default 30 s) returns the *partial* accepted
  set and logs loudly; the DKG then fails closed ("incomplete message
  sets") — a wrong key can never result. Timeout policy is a deployment
  concern (SPEC §13.1).

## What M1 is NOT

* **No TLS / mTLS.** Channels are authenticated only by the per-message
  ECDSA signatures. The §13.1 checklist (mutually authenticated
  transport) is M2.
* **No per-party process separation.** M1 is the reference-orchestration
  pattern: one process holds every party's transport key and drives all
  parties through `drive_dkg_signed`, exactly as the core drives
  `SimTransport`; the TCP separation is at the wire level. A per-node
  driver (each process holding only its own key, defenses carried as
  ordinary signed round-3 broadcasts) is M2.
* **No persistence** of accepted-message sets (blame-evidence retention,
  §13.1), no reconnection after startup, no clean thread shutdown
  (listener/reader threads exit with the process), no rate limiting, no
  DoS hardening beyond a 4 MiB frame cap and drop-on-bad-signature.
* **Not audited, not production anything.** localhost-scale demo and
  test scaffolding only.

## Demo

```sh
cargo run -p ohm-ecdsa-node            # ephemeral ports
cargo run -p ohm-ecdsa-node -- 7700    # party i on 127.0.0.1:7700+i-1
```

Spawns a 3-node committee on localhost, runs a 2-of-3 keygen through
`drive_dkg_signed` over `MeshTransport`, prints the joint public key `X`
and each party's id, exits 0.

## Tests

```sh
cargo test -p ohm-ecdsa-node
```

`node/tests/mesh_keygen.rs`: 3 nodes on ephemeral ports — keygen over
`MeshTransport` reconstructs the joint key; a cheating dealer
(`DkgTamper::bad_deal`) is named by the abort and yields a
`BlameToken` that verifies offline; forged/unknown-sender/malformed
frames are dropped while the honest keygen completes.

## Layout

| Module | Role |
|---|---|
| `src/wire.rs` | `WireMessage` (original / signed echo), canonical framing (`write_frame`/`read_frame`), signature validation |
| `src/mesh.rs` | `Node`: listener + full-mesh connections + reader threads, first-echo rule, verified-only mailbox |
| `src/transport.rs` | `MeshTransport`: echo-broadcast acceptor + the core `Transport` trait impl |
| `src/main.rs` | the demo binary described above |
