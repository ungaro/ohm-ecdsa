#![no_main]

use libfuzzer_sys::fuzz_target;
use ohm_ecdsa::transport::{Decode, DkgMessage, Encode, SignedEnvelope};

// Decode must never panic on arbitrary bytes; a successful decode must
// re-encode to a canonical form that re-decodes byte-identically.
fuzz_target!(|data: &[u8]| {
    if let Some((signed, used)) = SignedEnvelope::<DkgMessage>::decode(data) {
        assert!(used <= data.len(), "decoder over-reported consumption");
        let mut buf = Vec::new();
        signed.encode(&mut buf);
        let (signed2, used2) =
            SignedEnvelope::<DkgMessage>::decode(&buf).expect("re-encoded value must decode");
        assert_eq!(used2, buf.len(), "re-encoded value must decode exactly");
        let mut buf2 = Vec::new();
        signed2.encode(&mut buf2);
        assert_eq!(buf, buf2, "canonical encoding must be stable");
    }
});
