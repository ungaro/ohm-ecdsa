# ohm-ecdsa-demo-evm

> **UNAUDITED RESEARCH CODE — TESTNET / FAKE FUNDS ONLY.**
> The OHM-ECDSA protocol is an unreviewed draft (see `SPEC.md` §13 at the
> repo root); this demo exists to prove the "threshold signature →
> on-chain-verifiable EVM signature" path end to end. **Never** point it
> at mainnet, **never** use it with real assets, **never** reuse its
> deterministic committee seed anywhere value lives.

A 2-of-3 OHM-ECDSA committee signs a real EIP-1559 transfer and
broadcasts it to an EVM testnet. The signature is verified before
sending by an `ecrecover` simulation: recovering the signer from
`(sighash, y_parity, r, s)` must return the committee's joint key `X`,
and the derived Ethereum address must be the committee address.

- **M1 (local)**: keygen → presign → sign → ecrecover assert. No network.
- **M2 (testnet)**: live nonce/fees from a JSON-RPC endpoint, broadcast
  on explicit flag, bounded receipt polling, explorer link.

## Setup

The endpoint URL comes from an environment variable **only** — it is
never a flag, never a default, never written to any file:

```sh
export OHM_DEMO_RPC_URL="https://<your-sepolia-endpoint>"
```

Any Sepolia JSON-RPC endpoint works (Alchemy, Infura, QuickNode, a
public one). Nothing else to configure: the committee is derived
deterministically (fixed seed — demo reproducibility, NOT security).

## Workflow: dry run first, broadcast second

```sh
# 1. Dry run (default): chain-id sanity, balance check, live nonce +
#    fees, prints the UNSIGNED tx and its sighash. SENDS NOTHING and —
#    by design since the k-reuse incident below — SIGNS NOTHING.
cd demo-evm
cargo run

# 2. If the committee address is unfunded the run stops at the faucet
#    gate and prints the address. Fund it with testnet ETH:
#      https://sepoliafaucet.com
#      https://cloud.google.com/application/web3/faucet/ethereum/sepolia
#      https://faucet.quicknode.com/ethereum/sepolia

# 3. Broadcast for real (testnet ETH only):
cargo run -- --broadcast
```

On broadcast the demo polls `eth_getTransactionReceipt` (bounded, ~120 s)
and prints status (1 = success, 0 = reverted), block number, gas used,
and the explorer link.

## Flags

```
--chain-id N     default 11155111 (Sepolia)
--to 0xADDR      recipient (default 0x3535…3535)
--value-wei N    value (default 10000000000000000 = 0.01 ETH)
--broadcast      actually send (default: dry run)
```

The endpoint's `eth_chainId` must match `--chain-id` or the run refuses
before doing anything else.

## The k-reuse incident (2026-08-01)

**This section is the demo's most valuable teaching artifact. Read it
before reusing any of this code.**

The M2 demo originally seeded *both* keygen and presign
deterministically — a convenience for reproducible output. That made
every process run derive the **same presignature**: same nonce `k`,
same `R`, same `r`. On 2026-08-01 a dry run computed and printed a full
signature over sighash `m1`; the `--broadcast` run minutes later signed
a **different** sighash `m2` (the base fee had moved, changing the fee
fields) with the **same `k`**. Two public signatures under one `k` is
textbook ECDSA nonce reuse:

```
k = (m1 − m2) / (s1 − s2)     x = (s1·k − m1) / r
```

— the committee's secret key `x` is recoverable by anyone with both
transcripts. This is *precisely* the failure SPEC §8.6's single-use
discipline exists to prevent, and it was caused by an innocent
convenience, not by a protocol flaw: the protocol never reuses a
presignature; the *driver* did, across process runs.

It was harmless here: a throwaway testnet committee key holding faucet
ETH. The broadcast itself succeeded (status 1, block 11398872):
<https://sepolia.etherscan.io/tx/0x96914c199b8efee5d4e5376e110330ea2808651830210444a6b985ad9e1b9fb9>

**The M2-era committee key (`0x729BB22d46A1790708a3cfB2AAe7F74dE8c9e970`)
is BURNED — educational only.** It stays on testnet for continuity
(the faucet-funded address does not change); any production deployment
would rotate the key and consider every wei under it gone.

Two fixes, both structural:

1. **Dry runs never sign.** The dry-run report type has no signature
   fields at all, and `Committee::sign` is reachable only from the
   broadcast branch of `run_demo`. A signature "computed but not sent"
   is still a public transcript over `k`; not computing it is the only
   safe option.
2. **Fresh presignature per broadcast attempt.** Keygen stays
   deterministic (stable funded address), but the broadcast path draws
   a `u64` seed from `OsRng` on every run (`Committee::presign_fresh`),
   so each attempt uses a new `k`. The deterministic presign
   (`presign_deterministic`) survives **test-only** — reproducibility
   is a test property, never a runtime one.

The general lesson: in threshold ECDSA, determinism is safe exactly
where the output is meant to be public and permanent (the joint key),
and fatal exactly where the output must be secret and single-use (the
signing nonce). If you add a "reproducible mode" to any signing driver,
gate it behind test-only APIs.

### Plume testnet example

```sh
export OHM_DEMO_RPC_URL="https://<your-plume-testnet-endpoint>"
cargo run -- --chain-id 98899            # dry run
cargo run -- --chain-id 98899 --broadcast
```

Explorer links are picked by chain id: `sepolia.etherscan.io` for
11155111, `testnet-explorer.plume.org` for 98899.

## Fee policy

`max_fee = priority + 2 × base`, where the priority fee comes from
`eth_maxPriorityFeePerGas` (falling back to `eth_gasPrice` when the
method is unsupported, `-32601`) and the base fee from `eth_feeHistory`
(falling back to `eth_gasPrice` as an approximation). Plain-transfer gas
limit 21 000, empty access list.

## Development

```sh
cargo test           # unit + mock-RPC end-to-end (no external network)
cargo fmt
```

The mock-RPC tests (`tests/mock_rpc.rs`) spin a local `std::net`
`TcpListener` that answers canned JSON-RPC responses — tests never touch
a live endpoint. The receipt fixture in that file is CONSTRUCTED
(field-for-field the geth receipt shape).

The crate is workspace-excluded (own `[workspace]`, like `fuzz/`) and
pinned to build with the repo MSRV (`cargo +1.75.0 check`); the lockfile
holds the MSRV-compatible dep tree (`base64ct 1.6.0`, `zeroize 1.8.2`,
`idna_adapter 1.2.0` + icu 1.5, `litemap 0.7.4`) — regenerate pins with
care, the same way `Cargo.lock` at the root documents for the node crate.
