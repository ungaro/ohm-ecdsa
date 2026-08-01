//! Keccak-256 (Ethereum's hash — NOT the finalized SHA3-256).
//!
//! Thin wrapper over `tiny-keccak` so the rest of the demo never names
//! the hasher directly.

use tiny_keccak::{Hasher, Keccak};

/// `keccak256(data)` as defined in the Ethereum yellow paper (Appendix F).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::hex_encode;

    // Known answers from the Ethereum specification / keccak.team test
    // vectors (Keccak-256, not SHA3-256).
    #[test]
    fn keccak_known_answers() {
        assert_eq!(
            hex_encode(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex_encode(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
