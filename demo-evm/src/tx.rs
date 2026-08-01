//! EIP-1559 (type `0x02`) transaction encoding, sighash, and Ethereum
//! address derivation — local only, no RPC (M1).
//!
//! Field encoding follows EIP-1559 ("Fee market change for ETH 1.0
//! chain") and the yellow paper: every numeric field is a canonical
//! RLP integer (minimal big-endian, zero = empty string), the access
//! list is a list of `[address, [storage_keys...]]` pairs (empty here),
//! and the signed payload appends `[y_parity, r, s]` where `y_parity`
//! is `0`/`1` — NOT the legacy EIP-155 `v = 2·chain_id + 35 + parity`.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::AffinePoint;

use crate::keccak::keccak256;
use crate::rlp;

/// EIP-1559 transaction type byte.
pub const TX_TYPE: u8 = 0x02;

/// An unsigned EIP-1559 transaction (M1: empty access list).
#[derive(Clone, Debug)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

impl Eip1559Tx {
    /// The 9 unsigned payload fields, each already RLP-encoded
    /// (EIP-1559: `[chain_id, nonce, max_priority_fee_per_gas,
    /// max_fee_per_gas, gas_limit, destination, amount, data,
    /// access_list]`).
    fn unsigned_fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp::encode_uint(self.chain_id as u128),
            rlp::encode_uint(self.nonce as u128),
            rlp::encode_uint(self.max_priority_fee_per_gas),
            rlp::encode_uint(self.max_fee_per_gas),
            rlp::encode_uint(self.gas_limit as u128),
            rlp::encode_bytes(&self.to),
            rlp::encode_uint(self.value),
            rlp::encode_bytes(&self.data),
            rlp::encode_list(&[]), // empty access list
        ]
    }

    /// EIP-1559 sighash: `keccak256(0x02 ‖ rlp(unsigned_payload))` —
    /// the digest an EOA signs with secp256k1 ECDSA.
    pub fn sighash(&self) -> [u8; 32] {
        let mut preimage = vec![TX_TYPE];
        preimage.extend_from_slice(&rlp::encode_list(&self.unsigned_fields()));
        keccak256(&preimage)
    }

    /// The broadcast-ready signed transaction:
    /// `0x02 ‖ rlp(payload + [y_parity, r, s])`. `y_parity` is `0`/`1`
    /// (EIP-1559 drops the legacy chain-id-mixed `v`); `r`/`s` are the
    /// 32-byte big-endian signature scalars.
    pub fn signed_tx(&self, y_parity: bool, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut fields = self.unsigned_fields();
        fields.push(rlp::encode_uint(y_parity as u128));
        fields.push(rlp::encode_bytes(r));
        fields.push(rlp::encode_bytes(s));
        let mut out = vec![TX_TYPE];
        out.extend_from_slice(&rlp::encode_list(&fields));
        out
    }
}

/// Ethereum address of a secp256k1 public key (yellow paper, §4.3.1 /
/// Appendix F): `keccak256(x ‖ y)[12..]` over the 64-byte uncompressed
/// coordinates — WITHOUT the `0x04` SEC1 prefix.
pub fn address_of(x: &AffinePoint) -> [u8; 20] {
    let enc = x.to_encoded_point(false);
    let coords = &enc.as_bytes()[1..]; // strip 0x04, leaving x ‖ y (64 bytes)
    let hash = keccak256(coords);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 checksummed hex address: hex letters are uppercased where the
/// corresponding nibble of `keccak256(lowercase_hex_address)` is ≥ 8.
pub fn eip55(addr: &[u8; 20]) -> String {
    let lower = hex_encode(addr);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_alphabetic() && (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 }) & 0x0f) >= 8
        {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Lowercase hex encoding (no `0x` prefix).
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Hex decoding; accepts an optional `0x` prefix. Errors on odd length
/// or non-hex characters.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let hi = nibble(s.as_bytes()[i])?;
            let lo = nibble(s.as_bytes()[i + 1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::BadCharacter(c as char)),
    }
}

/// Hex decoding failures.
#[derive(Debug, thiserror::Error)]
pub enum HexError {
    #[error("odd-length hex string")]
    OddLength,
    #[error("non-hex character {0:?}")]
    BadCharacter(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_errors() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_decode("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(matches!(hex_decode("abc"), Err(HexError::OddLength)));
        assert!(matches!(hex_decode("zz"), Err(HexError::BadCharacter('z'))));
    }

    #[test]
    fn eip55_known_answers() {
        // EIP-55's own test vectors (all-lowercase input → checksummed);
        // the checksummed column was verified with `cast
        // to-check-sum-address`.
        let cases = [
            (
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];
        for (lower, checksummed) in cases {
            let raw = hex_decode(lower).unwrap();
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&raw);
            assert_eq!(eip55(&addr), format!("0x{checksummed}"));
        }
    }

    #[test]
    fn address_derivation_known_answer() {
        // Yellow-paper-style check: the all-known test key with secret 1
        // (G itself) — keccak256(x(G) ‖ y(G))[12..]. Cross-checked
        // against any Ethereum tool (e.g. `cast wallet address --private-key 1`).
        use k256::{ProjectivePoint, SecretKey};
        let g = ProjectivePoint::GENERATOR.to_affine();
        assert_eq!(
            eip55(&address_of(&g)),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        // Same via k256's SecretKey path to make sure the point handling
        // matches the standard library encoding.
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1; // scalar 1 → public key G
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let ep = sk.public_key().to_encoded_point(false);
        let hash = keccak256(&ep.as_bytes()[1..]);
        assert_eq!(&hash[12..], &address_of(&g));
    }
}
