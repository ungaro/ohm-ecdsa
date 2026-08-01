//! OHM-ECDSA → EVM demo: a 2-of-3 OHM-ECDSA committee signs Sepolia
//! EIP-1559 transfers and (M2) broadcasts them through a JSON-RPC
//! endpoint.
//!
//! The protocol side is exactly the core crate's reference arc — SPEC
//! §6 keygen, §8 presign, §9 one-round online sign — run through the
//! deterministic `sim` orchestrator with fixed seeds (never OS
//! randomness). The EVM side is EIP-1559 encoding (`tx.rs`), RLP
//! (`rlp.rs`), Keccak-256 (`keccak.rs`), minimal JSON (`json.rs`), and
//! a blocking JSON-RPC client (`rpc.rs`).
//!
//! The M1 guarantee stands: `ecrecover(sighash, y_parity, r, s)` must
//! recover the committee's joint key `X` before anything is sent.
//!
//! Single-use rule (SPEC §8.6): one presignature signs exactly one
//! transaction; every [`Committee::sign`] call mints a fresh one.

#![forbid(unsafe_code)]

pub mod json;
pub mod keccak;
pub mod rlp;
pub mod rpc;
pub mod tx;

use std::time::Duration;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;

use ohm_ecdsa::presign::{KeyShare, Presignature};
use ohm_ecdsa::{scalar_from_digest, sign, sim, Params};

use rpc::{FeeHistory, Fees, Receipt, RpcError};
use tx::Eip1559Tx;

/// Deterministic seed for the whole demo (tests / reproducible runs —
/// an OS CSPRNG per party in any real deployment).
pub const DEMO_SEED: u64 = 0xE1559;

/// Sepolia chain id (the default; Plume testnet is 98899, selected via
/// the `--chain-id` flag only).
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

/// The demo recipient and value when no flags override them.
pub const DEFAULT_TO: &str = "3535353535353535353535353535353535353535";
pub const DEFAULT_VALUE_WEI: u128 = 10_000_000_000_000_000; // 0.01 ETH

/// The 2-of-3 committee: deterministic keygen output + derived address.
/// Holds key shares — single-process DEMO material, exactly what the
/// core's `sim` orchestrator hands back; erased on Drop by the core's
/// own `zeroize` impls.
#[derive(Debug)]
pub struct Committee {
    params: Params,
    keys: Vec<KeyShare>,
    joint_vk: VerifyingKey,
    address: String,
}

impl Committee {
    /// Deterministic 2-of-3 keygen (SPEC §6) under [`DEMO_SEED`].
    pub fn deterministic() -> Result<Committee, DemoError> {
        let params = Params::new(3, 2)?;
        let mut rngs = sim::make_rngs(3, DEMO_SEED);
        // NOTE: the sid string is frozen — changing it would change the
        // committee's joint key and hence its address (faucet funding).
        let keys = sim::run_keygen(&params, b"demo-evm/m1/keygen", &mut rngs)?;
        let x = keys[0].com.points[0].to_affine(); // the joint public key
        let joint_vk = VerifyingKey::from_sec1_bytes(x.to_encoded_point(false).as_bytes())
            .expect("the joint key is a valid curve point");
        let address = tx::eip55(&tx::address_of(&x));
        Ok(Committee {
            params,
            keys,
            joint_vk,
            address,
        })
    }

    /// EIP-55 checksummed committee address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// One fresh presignature per party (SPEC §8) from DETERMINISTIC
    /// per-party RNGs — TESTS ONLY. A deterministic presign means every
    /// process run derives the same `k` (same `R`, same `r`): signing
    /// two different messages with it across runs is the classic ECDSA
    /// nonce-reuse key recovery (`k = (m1−m2)/(s1−s2)`, then
    /// `x = (s1·k − m1)/r`) — exactly what SPEC §8.6 single-use forbids.
    /// The binary's broadcast path uses [`Committee::presign_fresh`].
    ///
    /// (Deterministic KEYGEN is fine and intended — it keeps the funded
    /// demo address stable; only the per-transaction nonce must be
    /// fresh.)
    #[cfg(test)]
    pub fn presign_deterministic(&self) -> Result<Vec<Presignature>, DemoError> {
        let mut rngs = sim::make_rngs(3, DEMO_SEED.wrapping_add(1));
        Ok(sim::run_presign(
            &self.params,
            &self.keys,
            1,
            &mut rngs,
            None,
        )?)
    }

    /// One fresh presignature per party (SPEC §8) from OS entropy: a
    /// `u64` seed sampled from `OsRng`, expanded to per-party RNGs via
    /// `sim::make_rngs`. Every call draws a new `k` — the SPEC §8.6
    /// single-use discipline holds across process runs.
    pub fn presign_fresh(&self) -> Result<Vec<Presignature>, DemoError> {
        use rand::RngCore;
        let seed = rand::rngs::OsRng.next_u64();
        let mut rngs = sim::make_rngs(3, seed);
        Ok(sim::run_presign(
            &self.params,
            &self.keys,
            1,
            &mut rngs,
            None,
        )?)
    }

    /// Sign `tx` with `presigs` (SPEC §9): parties 1 + 2 online in one
    /// round, low-`s` normalization (EIP-2), y_parity from the nonce
    /// point `R`, and the ASSERTED ecrecover simulation — recovery from
    /// the sighash must return the joint key `X`.
    ///
    /// The caller supplies the presignature so that the choice of
    /// entropy (deterministic for tests, fresh for broadcast) is
    /// explicit at the call site — signing itself never mints one.
    pub fn sign(&self, tx: &Eip1559Tx, presigs: &[Presignature]) -> Result<ArcOutput, DemoError> {
        // The message is the EIP-1559 sighash, reduced to a scalar
        // exactly as the core does for any 32-byte digest.
        let sighash = tx.sighash();
        let m = scalar_from_digest(&sighash);

        // Online: parties 1 + 2 (any 2 of 3) sign in one round.
        let shares: Vec<sign::SignShare> = presigs[..2]
            .iter()
            .map(|p| sign::sign_share(p, &m))
            .collect();
        let (r, s) = sign::combine(&self.params, &presigs[0], &m, &shares)?;
        let sig = Signature::from_scalars(r.to_bytes(), s.to_bytes())?;

        // EIP-2 low-`s`: normalize, remembering the flip — the parity
        // below must flip with it or ecrecover lands on a different key.
        let (sig, flipped) = match sig.normalize_s() {
            Some(normalized) => (normalized, true),
            None => (sig, false),
        };
        debug_assert!(!bool::from(sig.s().is_high()), "normalize_s yields low-s");

        // y_parity = parity of R's y-coordinate (odd = 1), flipped iff
        // `s` was normalized. `RecoveryId` is NOT x-reduced: for
        // secp256k1 `r` is reduced mod q from a curve x-coordinate, and
        // x ≥ q is cryptographically negligible; the recovery assertion
        // below would catch it if it ever happened.
        let r_encoded = presigs[0].big_r.to_encoded_point(false);
        let r_y_odd = r_encoded.as_bytes()[64] & 1 == 1;
        let y_parity = r_y_odd ^ flipped;
        let recid = RecoveryId::new(y_parity, false);

        // The ecrecover simulation IS the demo's guarantee.
        let recovered = VerifyingKey::recover_from_prehash(&sighash, &sig, recid)?;
        if recovered != self.joint_vk {
            return Err(DemoError::RecoveryMismatch);
        }

        let signed_tx = tx.signed_tx(
            y_parity,
            &sig.r().to_bytes().into(),
            &sig.s().to_bytes().into(),
        );
        Ok(ArcOutput {
            address: self.address.clone(),
            sighash,
            signature: sig,
            y_parity,
            signed_tx,
        })
    }
}

/// Everything a signing run produces.
#[derive(Debug)]
pub struct ArcOutput {
    /// EIP-55 checksummed committee address (from the joint key X).
    pub address: String,
    /// `keccak256(0x02 ‖ rlp(unsigned_tx))`.
    pub sighash: [u8; 32],
    /// Low-`s` normalized (EIP-2) signature scalars.
    pub signature: Signature,
    /// EIP-1559 `y_parity` (0/1, NOT the legacy chain-id `v`).
    pub y_parity: bool,
    /// `0x02 ‖ rlp(payload + [y_parity, r, s])`.
    pub signed_tx: Vec<u8>,
}

/// M1 convenience (tests): deterministic committee + deterministic
/// presign + sign in one call. See [`Committee::presign_deterministic`]
/// for why this is test-only.
#[cfg(test)]
pub fn run_arc(tx: &Eip1559Tx) -> Result<ArcOutput, DemoError> {
    let committee = Committee::deterministic()?;
    let presigs = committee.presign_deterministic()?;
    committee.sign(tx, &presigs)
}

/// Configuration for one M2 run.
#[derive(Clone, Debug)]
pub struct DemoConfig {
    /// JSON-RPC endpoint (from `OHM_DEMO_RPC_URL` — never hardcoded).
    pub rpc_url: String,
    pub chain_id: u64,
    pub to: [u8; 20],
    pub value_wei: u128,
    /// Broadcast only when true; false is the dry-run safety gate.
    pub broadcast: bool,
    /// Receipt polling (production default: 3 s / 120 s; tests shrink).
    pub receipt_interval: Duration,
    pub receipt_timeout: Duration,
}

/// What one M2 run did. The DRY-RUN variant has NO signature fields by
/// construction: a dry run must never produce (or print) `r`/`s` — a
/// signature computed but "not sent" is still a public transcript over
/// the presignature's `k`, and a later broadcast with a fresh-looking
/// but equal `k` is the ECDSA nonce-reuse key-recovery scenario
/// (SPEC §8.6). Signing is reachable only from the broadcast branch of
/// [`run_demo`], with a freshly-drawn presignature.
#[derive(Debug)]
pub enum DemoReport {
    /// Funding gate: the committee address holds 0 wei (exit 0).
    Unfunded { address: String },
    /// Dry run: everything EXCEPT a signature.
    DryRun(DryRunReport),
    /// Broadcast: the signature, the tx hash, the mined receipt.
    Broadcast(BroadcastReport),
}

/// Dry-run output — deliberately signature-free.
#[derive(Debug)]
pub struct DryRunReport {
    pub address: String,
    pub balance_wei: u128,
    pub nonce: u64,
    pub fees: Fees,
    /// The unsigned transaction (fields only — no `y_parity`/`r`/`s`).
    pub tx: Eip1559Tx,
    /// `keccak256(0x02 ‖ rlp(unsigned_tx))` — public data, useful for
    /// eyeballing what WOULD be signed.
    pub unsigned_sighash: [u8; 32],
}

/// Broadcast output.
#[derive(Debug)]
pub struct BroadcastReport {
    pub address: String,
    pub balance_wei: u128,
    pub nonce: u64,
    pub fees: Fees,
    pub arc: ArcOutput,
    pub tx_hash: [u8; 32],
    pub receipt: Receipt,
}

/// Demo failures.
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ohm_ecdsa::Error),
    #[error("ecdsa error: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError),
    #[error("ecrecover recovered a key that is NOT the committee's joint key")]
    RecoveryMismatch,
    #[error("chain id mismatch: endpoint is on {got}, --chain-id says {expected}")]
    ChainIdMismatch { expected: u64, got: u64 },
}

/// The M2 flow, shared by `main.rs` and the mock-RPC test:
/// chain-id sanity → balance gate → live nonce/fees → tx assembly.
/// Then, and ONLY then:
/// - dry run: report the unsigned tx; NO presign, NO sign;
/// - `--broadcast`: mint a FRESH presignature ([`Committee::presign_fresh`]),
///   sign, send, poll the receipt (bounded).
pub fn run_demo(cfg: &DemoConfig) -> Result<DemoReport, DemoError> {
    let committee = Committee::deterministic()?;
    let mut client = rpc::Client::new(&cfg.rpc_url);

    // Sanity: the endpoint must be on the chain we think it is.
    let got = client.chain_id()?;
    if got != cfg.chain_id {
        return Err(DemoError::ChainIdMismatch {
            expected: cfg.chain_id,
            got,
        });
    }

    // Funding gate: an unfunded committee address cannot send — say so
    // and exit successfully (the faucet step is manual).
    let balance = client.get_balance(committee.address())?;
    if balance == 0 {
        return Ok(DemoReport::Unfunded {
            address: committee.address().to_string(),
        });
    }

    // Live nonce (pending pool) and fees.
    let nonce = client.get_transaction_count(committee.address())?;
    let priority = client.max_priority_fee_per_gas()?;
    let gas_price = client.gas_price()?;
    let history: Option<FeeHistory> = client.fee_history()?;
    let fees = rpc::suggest_fees(priority, gas_price, history.as_ref());

    // The unsigned transaction — as far as a dry run ever gets.
    let tx = Eip1559Tx {
        chain_id: cfg.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: 21_000,
        to: cfg.to,
        value: cfg.value_wei,
        data: Vec::new(),
    };

    if !cfg.broadcast {
        return Ok(DemoReport::DryRun(DryRunReport {
            address: committee.address().to_string(),
            balance_wei: balance,
            nonce,
            fees,
            unsigned_sighash: tx.sighash(),
            tx,
        }));
    }

    // --broadcast: fresh presignature per attempt (SPEC §8.6 — a new `k`
    // every run), then sign locally and send.
    let presigs = committee.presign_fresh()?;
    let arc = committee.sign(&tx, &presigs)?;
    let tx_hash = client.send_raw_transaction(&arc.signed_tx)?;
    let receipt = client.wait_for_receipt(&tx_hash, cfg.receipt_interval, cfg.receipt_timeout)?;
    Ok(DemoReport::Broadcast(BroadcastReport {
        address: committee.address().to_string(),
        balance_wei: balance,
        nonce,
        fees,
        arc,
        tx_hash,
        receipt,
    }))
}

/// The M1 fixed demo transaction (tests).
#[cfg(test)]
pub fn demo_tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: SEPOLIA_CHAIN_ID,
        nonce: 0,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: tx::hex_decode(DEFAULT_TO)
            .expect("fixed recipient hex")
            .try_into()
            .expect("20-byte address"),
        value: DEFAULT_VALUE_WEI,
        data: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlp;

    /// The full M1 arc as a test: recovery round-trips to X, the address
    /// matches, `s` is low, and the signed tx re-parses to the same
    /// fields at the RLP level.
    #[test]
    fn full_local_arc() {
        let tx = demo_tx();
        let out = run_arc(&tx).unwrap();

        assert!(!bool::from(out.signature.s().is_high()));

        let items = decode_signed_tx(&out.signed_tx);
        assert_eq!(items.len(), 12);
        assert_eq!(
            rlp::encode_bytes(&items[0]),
            rlp::encode_uint(tx.chain_id as u128)
        );
        assert_eq!(
            rlp::encode_bytes(&items[1]),
            rlp::encode_uint(tx.nonce as u128)
        );
        assert_eq!(
            rlp::encode_bytes(&items[2]),
            rlp::encode_uint(tx.max_priority_fee_per_gas)
        );
        assert_eq!(
            rlp::encode_bytes(&items[3]),
            rlp::encode_uint(tx.max_fee_per_gas)
        );
        assert_eq!(
            rlp::encode_bytes(&items[4]),
            rlp::encode_uint(tx.gas_limit as u128)
        );
        assert_eq!(items[5], tx.to);
        assert_eq!(rlp::encode_bytes(&items[6]), rlp::encode_uint(tx.value));
        assert_eq!(items[7], tx.data);
        assert!(items[8].is_empty(), "empty access list");
        assert_eq!(
            items[9],
            if out.y_parity { vec![1u8] } else { vec![] },
            "y_parity as a canonical RLP integer"
        );
        let r_bytes: [u8; 32] = out.signature.r().to_bytes().into();
        let s_bytes: [u8; 32] = out.signature.s().to_bytes().into();
        assert_eq!(items[10], r_bytes);
        assert_eq!(items[11], s_bytes);
    }

    /// Negative test: flipping y_parity must recover a DIFFERENT address
    /// (that is what makes the parity bit security-relevant on-chain).
    #[test]
    fn flipped_parity_recovers_a_different_address() {
        let tx = demo_tx();
        let out = run_arc(&tx).unwrap();
        let wrong = VerifyingKey::recover_from_prehash(
            &out.sighash,
            &out.signature,
            RecoveryId::new(!out.y_parity, false),
        )
        .unwrap();
        let wrong_ep = wrong.to_encoded_point(false);
        let wrong_hash = crate::keccak::keccak256(&wrong_ep.as_bytes()[1..]);
        let mut wrong_raw = [0u8; 20];
        wrong_raw.copy_from_slice(&wrong_hash[12..]);
        let wrong_addr = tx::eip55(&wrong_raw);
        assert_ne!(wrong_addr, out.address);
    }

    /// The deterministic committee is stable across calls (the M2 flow
    /// depends on keygen being reproducible).
    #[test]
    fn committee_is_deterministic() {
        let a = Committee::deterministic().unwrap();
        let b = Committee::deterministic().unwrap();
        assert_eq!(a.address(), b.address());
    }

    /// `presign_fresh` draws a new `k` every call (SPEC §8.6): two
    /// invocations must produce different nonce points `R`. (Deterministic
    /// keygen keeps the ADDRESS stable; only the per-tx nonce is fresh.)
    #[test]
    fn presign_fresh_draws_fresh_nonces() {
        let committee = Committee::deterministic().unwrap();
        let a = committee.presign_fresh().unwrap();
        let b = committee.presign_fresh().unwrap();
        assert_ne!(
            a[0].big_r.to_encoded_point(false),
            b[0].big_r.to_encoded_point(false),
            "two fresh presignatures must not share k (SPEC §8.6)"
        );
        // And the deterministic test path is the reproducible one.
        let d1 = committee.presign_deterministic().unwrap();
        let d2 = committee.presign_deterministic().unwrap();
        assert_eq!(
            d1[0].big_r.to_encoded_point(false),
            d2[0].big_r.to_encoded_point(false)
        );
    }

    /// The dry-run report is signature-free BY TYPE: it has no
    /// `ArcOutput`/`signature`/`signed_tx` fields — there is nothing to
    /// assert against because no such data can exist. What we CAN assert
    /// here is the API surface itself: `DryRunReport` exposes the
    /// unsigned tx and sighash, and `ArcOutput` (which carries `r`/`s`)
    /// is only constructible via `Committee::sign`, which `run_demo`
    /// reaches only in the broadcast branch (read `run_demo` — the rest
    /// is by construction).
    #[test]
    fn dry_run_report_is_signature_free_by_construction() {
        let report = DryRunReport {
            address: "0x0".into(),
            balance_wei: 1,
            nonce: 0,
            fees: Fees {
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 2,
            },
            tx: demo_tx(),
            unsigned_sighash: [0u8; 32],
        };
        let _ = &report.unsigned_sighash;
        let _ = &report.tx;
        // Compile-time guarantee: `DemoReport::DryRun` cannot carry an
        // `ArcOutput` — the enum simply has no such field.
        let report = DemoReport::DryRun(report);
        assert!(matches!(report, DemoReport::DryRun(_)));
    }

    /// Sighash cross-check: an independent, item-based RLP encoding
    /// (written separately from `rlp.rs`) must produce the same digest.
    #[test]
    fn sighash_cross_check_independent_encoding() {
        let tx = demo_tx();
        let expected = tx.sighash();

        enum Item {
            Bytes(Vec<u8>),
            List(Vec<Item>),
        }
        fn enc(item: &Item) -> Vec<u8> {
            fn header(base: u8, len: usize) -> Vec<u8> {
                if len <= 55 {
                    vec![base + len as u8]
                } else {
                    let mut l = len.to_be_bytes().to_vec();
                    let first = l.iter().position(|b| *b != 0).unwrap();
                    l.drain(..first);
                    let mut out = vec![base + 55 + l.len() as u8];
                    out.extend_from_slice(&l);
                    out
                }
            }
            match item {
                Item::Bytes(b) if b.len() == 1 && b[0] <= 0x7f => vec![b[0]],
                Item::Bytes(b) => [header(0x80, b.len()), b.clone()].concat(),
                Item::List(items) => {
                    let payload: Vec<u8> = items.iter().flat_map(enc).collect();
                    [header(0xc0, payload.len()), payload].concat()
                }
            }
        }
        fn uint(v: u128) -> Item {
            if v == 0 {
                return Item::Bytes(vec![]);
            }
            let bytes = v.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap();
            Item::Bytes(bytes[first..].to_vec())
        }
        let payload = Item::List(vec![
            uint(tx.chain_id as u128),
            uint(tx.nonce as u128),
            uint(tx.max_priority_fee_per_gas),
            uint(tx.max_fee_per_gas),
            uint(tx.gas_limit as u128),
            Item::Bytes(tx.to.to_vec()),
            uint(tx.value),
            Item::Bytes(tx.data.clone()),
            Item::List(vec![]),
        ]);
        let mut preimage = vec![0x02u8];
        preimage.extend_from_slice(&enc(&payload));
        assert_eq!(crate::keccak::keccak256(&preimage), expected);
    }

    /// Minimal test-only RLP reader: splits `0x02 ‖ rlp(list)` into the
    /// list's items (strings returned as their content bytes; the empty
    /// access list as an empty vec). Enough to verify the signed tx.
    fn decode_signed_tx(bytes: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(bytes[0], 0x02, "EIP-1559 type byte");
        let (payload, used) = read_item(&bytes[1..]);
        assert_eq!(used, bytes.len() - 1, "outer list covers the whole tx");
        let mut items = Vec::new();
        let mut rest = &payload[..];
        while !rest.is_empty() {
            let (content, used) = read_item(rest);
            items.push(content);
            rest = &rest[used..];
        }
        items
    }

    /// Read one RLP item; returns (content bytes, bytes consumed).
    fn read_item(input: &[u8]) -> (Vec<u8>, usize) {
        let b0 = input[0];
        if b0 <= 0x7f {
            return (vec![b0], 1);
        }
        let (content_offset, content_len) = if b0 <= 0xb7 {
            (1, (b0 - 0x80) as usize)
        } else if b0 <= 0xbf {
            let ll = (b0 - 0xb7) as usize;
            (1 + ll, be_len(&input[1..1 + ll]))
        } else if b0 <= 0xf7 {
            (1, (b0 - 0xc0) as usize)
        } else {
            let ll = (b0 - 0xf7) as usize;
            (1 + ll, be_len(&input[1..1 + ll]))
        };
        let content = input[content_offset..content_offset + content_len].to_vec();
        (content, content_offset + content_len)
    }

    fn be_len(bytes: &[u8]) -> usize {
        bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize)
    }
}
