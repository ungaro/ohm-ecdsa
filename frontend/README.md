# frontend/ — OHM-ECDSA explainer site

A **no-build** static site: plain HTML + ES-module JavaScript, no npm
project, no framework, no bundler. The only build step is the wasm
module — the protocol's real Rust code, compiled once and vendored into
`pkg/` (gitignored).

## Build the wasm module

Requires a Rust toolchain with the `wasm32-unknown-unknown` target and
`wasm-pack`:

```sh
rustup target add wasm32-unknown-unknown   # once
npm install -g wasm-pack                   # once (this machine: wasm-pack 0.15.0 via npm)

cd frontend/wasm
wasm-pack build --target web --out-dir ../pkg
```

Rebuild after any change to `frontend/wasm/src/lib.rs` (or the core).

## Serve

From `frontend/`:

```sh
cd frontend
python3 -m http.server 8000
# open http://localhost:8000
```

(Any static file server works; ES modules just require http(s), not
`file://`.)

## Verify without a browser

```sh
cd frontend
node smoke.mjs     # imports pkg/ and asserts the F1 protocol surface
```

## Layout

```
frontend/
├── index.html      F1 page: Shamir + Feldman VSS interactive + 2-of-3 keygen card
├── arc.html        F2 page: the full protocol arc + sabotage mode (identifiable abort)
├── shamir.js       F1 page logic (ES module, imports pkg/)
├── arc.js          F2 page logic (ES module, imports pkg/)
├── style.css       dark theme, self-contained (no external fonts/CDNs)
├── smoke.mjs       node smoke test of the wasm exports
├── pkg/            wasm-pack output (gitignored)
└── wasm/           ohm-ecdsa-wasm — tiny wasm-bindgen wrapper over the core
```

## What the wasm wrapper exposes (all REAL protocol values)

- `keygen(seed) -> { x, commitment, parties }` — the 2-of-3 DKG
  (`sim::run_keygen`, SPEC §6) under a deterministic seed.
- `shamir_demo(secret_hex, t, n, seed) -> { secret, coeffs, coeffsNum,
  commitment, shares }` — Shamir dealing + Feldman commitment (§4.1–4.2).
  The non-constant coefficients are dealt SMALL so the polynomial is
  drawable over the reals (plot projection, documented on the page);
  verification and reconstruction run over the full field.
- `verify_share(commitment, id, share_hex) -> bool` — the §4.2 point
  equality, in Rust/k256. The page never re-implements secp256k1.
- `reconstruct(t, ids, shares_hex) -> secret_hex` — Lagrange at 0 (§4.1);
  errors below `t`.
- `full_arc(seed) -> { keygen, triples, presign, sign }` — the honest
  2-of-3 arc (§6→§9) via the sim drivers: X + shares + commitments, the
  triple (per-party a/b/c, multiplicativity + DLEQ-verified booleans),
  the presignature (id, R, r, u/z shares + commitments), and the
  signature (m, per-party s_j, (r, s), k256-verified + low-s booleans).
- `arc_with_tamper(seed, fault, party) -> { fault, faultClass, check,
  phase, blamed, detail }` — one injected fault (`bad-deal` F2,
  `bad-product-proof` F3, `bad-open-share` F4, `bad-nonce-point` F5,
  `bad-sign-share` F6); the blamed ids mirror `tests/blame_matrix.rs`.

Note for porters: the wrapper enables `getrandom`'s `js` backend because
the core's k256/ff tree pulls `rand_core` with default features (see
`frontend/wasm/Cargo.toml`) — it is never called; every RNG is a seeded
`StdRng`.

**Unaudited research code — not for securing real assets (SPEC §13).**
