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

use ohm_ecdsa::presign::KeyShare;
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

    /// Sign `tx` end to end: one fresh presignature (SPEC §8), parties
    /// 1 + 2 online (SPEC §9), low-`s` normalization (EIP-2), y_parity
    /// from the nonce point `R`, and the ASSERTED ecrecover simulation —
    /// recovery from the sighash must return the joint key `X`.
    pub fn sign(&self, tx: &Eip1559Tx) -> Result<ArcOutput, DemoError> {
        // Offline: one fresh presignature, deterministic seed distinct
        // from keygen's.
        let mut rngs = sim::make_rngs(3, DEMO_SEED.wrapping_add(1));
        let presigs = sim::run_presign(&self.params, &self.keys, 1, &mut rngs, None)?;

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

/// M1 convenience: deterministic committee + sign in one call.
pub fn run_arc(tx: &Eip1559Tx) -> Result<ArcOutput, DemoError> {
    Committee::deterministic()?.sign(tx)
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

/// What one M2 run did — structured so tests can assert, `main` prints.
#[derive(Debug)]
pub struct DemoReport {
    pub address: String,
    pub balance_wei: u128,
    /// False when the committee address is unfunded (early exit).
    pub funded: bool,
    pub nonce: Option<u64>,
    pub fees: Option<Fees>,
    pub arc: Option<ArcOutput>,
    pub tx_hash: Option<[u8; 32]>,
    pub receipt: Option<Receipt>,
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
/// chain-id sanity → balance gate → live nonce/fees → local threshold
/// sign → dry-run report, or broadcast + bounded receipt polling.
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
        return Ok(DemoReport {
            address: committee.address().to_string(),
            balance_wei: 0,
            funded: false,
            nonce: None,
            fees: None,
            arc: None,
            tx_hash: None,
            receipt: None,
        });
    }

    // Live nonce (pending pool) and fees.
    let nonce = client.get_transaction_count(committee.address())?;
    let priority = client.max_priority_fee_per_gas()?;
    let gas_price = client.gas_price()?;
    let history: Option<FeeHistory> = client.fee_history()?;
    let fees = rpc::suggest_fees(priority, gas_price, history.as_ref());

    // Sign locally — the threshold arc never touches the network.
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
    let arc = committee.sign(&tx)?;

    if !cfg.broadcast {
        return Ok(DemoReport {
            address: committee.address().to_string(),
            balance_wei: balance,
            funded: true,
            nonce: Some(nonce),
            fees: Some(fees),
            arc: Some(arc),
            tx_hash: None,
            receipt: None,
        });
    }

    // --broadcast: send and wait for inclusion.
    let tx_hash = client.send_raw_transaction(&arc.signed_tx)?;
    let receipt = client.wait_for_receipt(&tx_hash, cfg.receipt_interval, cfg.receipt_timeout)?;
    Ok(DemoReport {
        address: committee.address().to_string(),
        balance_wei: balance,
        funded: true,
        nonce: Some(nonce),
        fees: Some(fees),
        arc: Some(arc),
        tx_hash: Some(tx_hash),
        receipt: Some(receipt),
    })
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
