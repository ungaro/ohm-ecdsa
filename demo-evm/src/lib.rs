//! M1 of the EVM testnet demo: a 2-of-3 OHM-ECDSA committee signs a
//! Sepolia EIP-1559 transfer LOCALLY (no RPC, no network) and the
//! signature is proven on-chain-shaped by ecrecover-style verification:
//! `ecrecover(sighash, y_parity, r, s)` must recover the committee's
//! joint key `X`, and its derived Ethereum address must match the
//! committee address.
//!
//! The protocol side is exactly the core crate's reference arc — SPEC
//! §6 keygen, §8 presign, §9 one-round online sign — run through the
//! deterministic `sim` orchestrator with fixed seeds (never OS
//! randomness). The EVM side is EIP-1559 encoding (`tx.rs`), RLP
//! (`rlp.rs`), and Keccak-256 (`keccak.rs`).
//!
//! Single-use rule (SPEC §8.6) applies to the demo too: one presignature
//! signs exactly one transaction. M1 mints a fresh one per `run_arc`
//! call.

#![forbid(unsafe_code)]

pub mod keccak;
pub mod rlp;
pub mod tx;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::ToEncodedPoint;

use ohm_ecdsa::{scalar_from_digest, sign, sim, Params};

use tx::Eip1559Tx;

/// Deterministic seed for the whole arc (tests / reproducible runs —
/// an OS CSPRNG per party in any real deployment).
pub const DEMO_SEED: u64 = 0xE1559;

/// Sepolia chain id.
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

/// Everything the M1 arc produces: the committee address, the sighash
/// that was signed, the normalized signature + parity, and the
/// broadcast-ready signed transaction bytes.
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

/// M1 demo failures.
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ohm_ecdsa::Error),
    #[error("ecdsa error: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
    #[error("ecrecover recovered a key that is NOT the committee's joint key")]
    RecoveryMismatch,
}

/// Run the full local arc over `tx`:
///
/// 1. 2-of-3 keygen (SPEC §6) + one presignature (SPEC §8), fixed seeds.
/// 2. EIP-1559 sighash of `tx` → scalar `m`.
/// 3. Parties 1 and 2 sign: `sign::sign_share` + `sign::combine` (SPEC §9).
/// 4. Low-`s` normalization (EIP-2), remembering whether `s` flipped.
/// 5. `y_parity` = parity of the presignature nonce point `R`,
///    flipped iff `s` was — then ASSERT the ecrecover simulation:
///    `recover_from_prehash(sighash, sig, y_parity)` must return exactly
///    the joint key `X`, and its address the committee address.
pub fn run_arc(tx: &Eip1559Tx) -> Result<ArcOutput, DemoError> {
    // (1) Offline: committee keygen + one presignature.
    let params = Params::new(3, 2)?;
    let mut rngs = sim::make_rngs(3, DEMO_SEED);
    let keys = sim::run_keygen(&params, b"demo-evm/m1/keygen", &mut rngs)?;
    let x = keys[0].com.points[0].to_affine(); // the joint public key
    let joint_vk = VerifyingKey::from_sec1_bytes(x.to_encoded_point(false).as_bytes())
        .expect("the joint key is a valid curve point");
    let address = tx::eip55(&tx::address_of(&x));
    let presigs = sim::run_presign(&params, &keys, 1, &mut rngs, None)?;

    // (2) The message is the EIP-1559 sighash, reduced to a scalar
    // exactly as the core does for any 32-byte digest.
    let sighash = tx.sighash();
    let m = scalar_from_digest(&sighash);

    // (3) Online: parties 1 + 2 (any 2 of 3) sign in one round.
    let shares: Vec<sign::SignShare> = presigs[..2]
        .iter()
        .map(|p| sign::sign_share(p, &m))
        .collect();
    let (r, s) = sign::combine(&params, &presigs[0], &m, &shares)?;
    let sig = Signature::from_scalars(r.to_bytes(), s.to_bytes())?;

    // (4) EIP-2 low-`s`: normalize, remembering the flip — the parity
    // below must flip with it or ecrecover lands on a different key.
    let (sig, flipped) = match sig.normalize_s() {
        Some(normalized) => (normalized, true),
        None => (sig, false),
    };
    debug_assert!(!bool::from(sig.s().is_high()), "normalize_s yields low-s");

    // (5) y_parity = parity of R's y-coordinate (odd = 1), flipped iff
    // `s` was normalized. `RecoveryId` is NOT x-reduced: for secp256k1
    // `r` is reduced mod q from a curve x-coordinate, and x ≥ q is
    // cryptographically negligible; the recovery assertion below would
    // catch it if it ever happened.
    let r_encoded = presigs[0].big_r.to_encoded_point(false);
    let r_y_odd = r_encoded.as_bytes()[64] & 1 == 1;
    let y_parity = r_y_odd ^ flipped;
    let recid = RecoveryId::new(y_parity, false);

    // The ecrecover simulation IS the M1 guarantee: recovery from the
    // sighash must return the committee's joint key, hence its address.
    let recovered = VerifyingKey::recover_from_prehash(&sighash, &sig, recid)?;
    if recovered != joint_vk {
        return Err(DemoError::RecoveryMismatch);
    }

    let signed_tx = tx.signed_tx(
        y_parity,
        &sig.r().to_bytes().into(),
        &sig.s().to_bytes().into(),
    );
    Ok(ArcOutput {
        address,
        sighash,
        signature: sig,
        y_parity,
        signed_tx,
    })
}

/// The demo transaction: a 0.01 ETH transfer on Sepolia with plausible
/// fees (1.5 gwei priority / 30 gwei max, plain-transfer gas limit).
pub fn demo_tx() -> Eip1559Tx {
    Eip1559Tx {
        chain_id: SEPOLIA_CHAIN_ID,
        nonce: 0,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: tx::hex_decode("3535353535353535353535353535353535353535")
            .expect("fixed recipient hex")
            .try_into()
            .expect("20-byte address"),
        value: 10_000_000_000_000_000, // 0.01 ETH in wei
        data: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlp;
    use k256::elliptic_curve::scalar::IsHigh;

    /// The full M1 arc as a test: recovery round-trips to X, the address
    /// matches, `s` is low, and the signed tx re-parses to the same
    /// fields at the RLP level.
    #[test]
    fn full_local_arc() {
        let tx = demo_tx();
        let out = run_arc(&tx).unwrap();

        // Low-s (EIP-2).
        assert!(!bool::from(out.signature.s().is_high()));

        // The re-parsed signed tx must carry exactly the fields we put
        // in — including y_parity/r/s appended after the 9 payload items.
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

    /// Sighash cross-check: an independent, item-based RLP encoding
    /// (written separately from `rlp.rs`) must produce the same digest.
    #[test]
    fn sighash_cross_check_independent_encoding() {
        let tx = demo_tx();
        let expected = tx.sighash();

        // Independent encoder: recursive over a tiny item tree, no code
        // shared with `rlp.rs`.
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
