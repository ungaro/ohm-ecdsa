//! Blame tokens (SPEC §10.2, §A.4) — identifiable abort you can take to
//! court. Every transport envelope is signed by its sender, so when a
//! cheating dealer is caught, the abort plus the offending signed message
//! plus the public commitment vector form a BLAME TOKEN: any auditor can
//! re-verify it offline, with no secret material.
//!
//! Run: `cargo run --example blame_token`

use k256::SecretKey;

use ohm_ecdsa::dkg::DkgTamper;
use ohm_ecdsa::transport::{drive_dkg_signed, DkgMessage, SigningTransport, SimTransport};
use ohm_ecdsa::{sim, Error, Params, Phase};

fn main() {
    println!("== Blame token: 2-of-3 keygen over a signing transport ==");
    let params = Params::new(3, 2).unwrap();
    let mut rngs = sim::make_rngs(3, 0xB7A2E); // deterministic; tests only

    // Transport signing keys (the deployment PKI of SPEC §13.1): one
    // ECDSA keypair per party, registered with the signing transport.
    let signers: Vec<(usize, SecretKey)> = (1..=3)
        .map(|i| (i, SecretKey::random(&mut rngs[i - 1])))
        .collect();
    let mut transport = SigningTransport::new(SimTransport::new(), &signers);
    let registry = transport.verifying_keys(); // all an auditor ever needs
    println!("  transport keys registered for parties 1..=3; every envelope is signed");

    // Keygen is driven through the signing transport; dealer 2 deals a
    // bad share to party 1 (fault class F2 of SPEC §10.1).
    let sid = b"blame-token/keygen";
    let tamper = DkgTamper {
        bad_deal: Some((2, 1)),
        ..Default::default()
    };
    let err = drive_dkg_signed(
        &params,
        sid,
        b"blame-token/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        Some(&tamper),
    )
    .unwrap_err();
    match &err.error {
        Error::Abort { abort } => println!(
            "  Error::Abort — phase: {}, blamed: {:?} ({})",
            abort.phase, abort.blamed, abort.detail
        ),
        other => panic!("expected identifiable abort, got {other:?}"),
    }
    let token = err.token.expect("a dealer fault leaves a blame token");
    println!("  the offending share was signed by party 2: blame token captured");

    // The auditor: no shares, no secrets — only the party transport
    // public keys and the token (SPEC §A.4 step 3).
    println!();
    println!("== Auditor: offline verification (SPEC §A.4) ==");
    let DkgMessage::Share(share) = &token.envelope.envelope.payload else {
        unreachable!()
    };
    let dealer_key = registry.iter().find(|(p, _)| p == &share.from).unwrap().1;
    let (a, b, c) = (
        token.envelope.verify_signature(&dealer_key),
        !token.com.verify_share(share.to, &share.share),
        token.abort.blamed == [share.from],
    );
    println!("  (a) envelope signature verifies under party 2's key: {a}");
    println!("  (b) the share really fails the EvalCom check: {b}");
    println!("  (c) the abort names the envelope's sender: {c}");
    assert!(a && b && c);
    assert!(token.verify(&registry));
    println!("  auditor verifies the blame token: true");

    // Forgery attempt: flip a byte in the envelope and re-present the
    // token — the signature no longer verifies and the auditor rejects.
    println!();
    println!("== Forgery attempt: one flipped byte ==");
    let mut forged = token.clone();
    let DkgMessage::Share(s) = &mut forged.envelope.envelope.payload else {
        unreachable!()
    };
    s.share += k256::Scalar::ONE;
    assert!(!forged.verify(&registry));
    println!("  forgery rejected by the auditor: true");

    // Sanity: the same transport delivers an honest keygen too.
    let mut rngs = sim::make_rngs(3, 0xB7A2E);
    let signers: Vec<(usize, SecretKey)> = (1..=3)
        .map(|i| (i, SecretKey::random(&mut rngs[i - 1])))
        .collect();
    let mut transport = SigningTransport::new(SimTransport::new(), &signers);
    let keys = drive_dkg_signed(
        &params,
        b"blame-token/honest",
        b"blame-token/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    )
    .unwrap();
    assert_eq!(keys.len(), 3);
    println!();
    println!("  honest keygen over the signed transport: 3 key shares, no abort");

    println!();
    println!("Lesson: blame is a cryptographic fact, not a log claim —");
    println!("any third party can re-verify it from public data alone.");
}
