//! Hand-rolled RLP ENCODER (Ethereum yellow paper, Appendix B).
//!
//! Encoder only — the demo never parses RLP outside its own tests (a
//! minimal test-only decoder lives in `lib.rs`'s test module).
//!
//! API shape: byte strings are encoded by [`encode_bytes`]; lists are
//! built from ALREADY-ENCODED items by [`encode_list`], which only adds
//! the list header around their concatenation. This keeps the encoder
//! total (no recursion, no allocation beyond the output) and matches how
//! transaction payloads are assembled field-by-field in `tx.rs`.

/// RLP-encode a byte string (yellow paper, Appendix B):
///
/// - a single byte in `0x00..=0x7f` is its own encoding;
/// - a string of `0..=55` bytes gets the header `0x80 + len`;
/// - a longer string gets `0xb7 + len(len)` followed by the big-endian
///   length and then the string.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] <= 0x7f {
        return vec![data[0]];
    }
    let mut out = Vec::with_capacity(data.len() + 9);
    if data.len() <= 55 {
        out.push(0x80 + data.len() as u8);
    } else {
        let len = minimal_be(data.len() as u64);
        out.push(0xb7 + len.len() as u8);
        out.extend_from_slice(&len);
    }
    out.extend_from_slice(data);
    out
}

/// RLP-encode an unsigned integer: canonical minimal big-endian, where
/// `0` is the EMPTY string (encodes as `0x80`). This is the Ethereum
/// convention for every numeric transaction field (yellow paper,
/// Appendix B: "positive integers must be represented in big-endian
/// binary form with no leading zeroes").
pub fn encode_uint(v: u128) -> Vec<u8> {
    if v == 0 {
        return encode_bytes(&[]);
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap();
    encode_bytes(&bytes[first..])
}

/// RLP-encode a list whose items are already RLP-encoded: concatenate
/// the items and add the list header — `0xc0 + len` for a payload of
/// `0..=55` bytes, else `0xf7 + len(len)` with the big-endian length.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    if payload_len <= 55 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let len = minimal_be(payload_len as u64);
        out.push(0xf7 + len.len() as u8);
        out.extend_from_slice(&len);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Minimal big-endian encoding of a nonzero length (no leading zeroes).
fn minimal_be(v: u64) -> Vec<u8> {
    debug_assert!(v > 0);
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap();
    bytes[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::hex_encode;

    // Known answers from the Ethereum RLP documentation
    // (ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
    // and the yellow paper, Appendix B).
    #[test]
    fn rlp_known_answers() {
        // "dog" → 0x83646f67
        assert_eq!(hex_encode(&encode_bytes(b"dog")), "83646f67");
        // empty string → 0x80
        assert_eq!(hex_encode(&encode_bytes(b"")), "80");
        // empty list → 0xc0
        assert_eq!(hex_encode(&encode_list(&[])), "c0");
        // the byte 0x00 → 0x00 (single byte < 0x80 is its own encoding)
        assert_eq!(hex_encode(&encode_bytes(&[0x00])), "00");
        // 15 → 0x0f
        assert_eq!(hex_encode(&encode_uint(15)), "0f");
        // 1024 → 0x820400
        assert_eq!(hex_encode(&encode_uint(1024)), "820400");
        // 0 → empty string → 0x80
        assert_eq!(hex_encode(&encode_uint(0)), "80");
        // [[], [[]], [[], [[]]]] → 0xc7c0c1c0c3c0c1c0
        let empty = encode_list(&[]);
        let one_empty = encode_list(&[empty.clone()]);
        let nested = encode_list(&[
            empty.clone(),
            one_empty.clone(),
            encode_list(&[empty, one_empty]),
        ]);
        assert_eq!(hex_encode(&nested), "c7c0c1c0c3c0c1c0");
    }

    #[test]
    fn rlp_long_form_string() {
        // >55-byte string uses the long form: 0xb8 0x38 ‖ bytes.
        // "Lorem ipsum ..." is 56 bytes (Ethereum RLP docs example).
        let s = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        assert_eq!(s.len(), 56);
        let enc = encode_bytes(s);
        assert_eq!(&enc[..2], &[0xb8, 0x38]);
        assert_eq!(&enc[2..], &s[..]);
        assert_eq!(enc.len(), 58);
    }

    #[test]
    fn rlp_long_form_list() {
        // A list whose payload exceeds 55 bytes: 0xf8 ‖ len ‖ payload.
        // 60 one-byte items (all < 0x80, each its own encoding).
        let items: Vec<Vec<u8>> = (0u8..60).map(|b| encode_bytes(&[b])).collect();
        let enc = encode_list(&items);
        assert_eq!(&enc[..2], &[0xf8, 0x3c]); // 60-byte payload
        assert_eq!(enc.len(), 2 + 60);
    }
}
