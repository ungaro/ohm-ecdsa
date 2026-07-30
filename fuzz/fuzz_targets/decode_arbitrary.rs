#![no_main]

use k256::ecdsa::Signature;
use k256::{ProjectivePoint, Scalar};
use libfuzzer_sys::fuzz_target;
use ohm_ecdsa::dkg::{DkgBcast1, DkgBcast2, DkgP2P};
use ohm_ecdsa::transport::{Decode, DkgMessage, Encode, Envelope, SignedEnvelope};
use ohm_ecdsa::vss::FeldmanCommitment;

// Every Decode impl fed with the input AND every prefix of it (split
// points at every byte offset): no panic, no out-of-bounds read, and a
// successful decode must re-encode to a canonical form that re-decodes
// byte-identically.
fn check<T: Encode + Decode>(data: &[u8]) {
    for cut in 0..=data.len() {
        let data = &data[..cut];
        if let Some((v, used)) = T::decode(data) {
            assert!(used <= data.len(), "decoder over-reported consumption");
            let mut buf = Vec::new();
            v.encode(&mut buf);
            let (v2, used2) = T::decode(&buf).expect("re-encoded value must decode");
            assert_eq!(used2, buf.len(), "re-encoded value must decode exactly");
            let mut buf2 = Vec::new();
            v2.encode(&mut buf2);
            assert_eq!(buf, buf2, "canonical encoding must be stable");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The all-prefixes loop is quadratic for large inputs; the decoders
    // see unbounded lengths via the length prefixes anyway, so cap the
    // raw input (libFuzzer's default max_len is far below this).
    let data = if data.len() > 4096 { &data[..4096] } else { data };
    check::<Scalar>(data);
    check::<ProjectivePoint>(data);
    check::<Signature>(data);
    check::<FeldmanCommitment>(data);
    check::<DkgBcast1>(data);
    check::<DkgBcast2>(data);
    check::<DkgP2P>(data);
    check::<DkgMessage>(data);
    check::<Envelope<DkgMessage>>(data);
    check::<SignedEnvelope<DkgMessage>>(data);
});
