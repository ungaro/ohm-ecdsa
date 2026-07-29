//! M1 integration tests: keygen over real TCP through `MeshTransport`
//! (SPEC §4.7, §10.2, §13.1/§13.2), patterning after the core's
//! `transport` tests but with the wire in between.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use k256::ecdsa::SigningKey;
use k256::{ProjectivePoint, Scalar, SecretKey};
use ohm_ecdsa::dkg::{DkgBcast1, DkgTamper};
use ohm_ecdsa::shamir::interpolate_at_zero;
use ohm_ecdsa::sim::make_rngs;
use ohm_ecdsa::transport::{
    drive_dkg_signed, DkgMessage, Envelope, SignedEnvelope, SigningTransport,
};
use ohm_ecdsa::{Error, Params, Phase};
use ohm_ecdsa_node::wire::write_frame;
use ohm_ecdsa_node::{MeshTransport, WireMessage};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ROUND_TIMEOUT: Duration = Duration::from_secs(30);

type Committee = (
    Params,
    Vec<(usize, SecretKey)>,
    SigningTransport<MeshTransport>,
    Vec<StdRng>,
);

/// A 2-of-3 committee on localhost ephemeral ports, deterministic keys
/// and RNGs (tests never use OS randomness, per the repo convention).
fn start_committee(seed: u64) -> Committee {
    let params = Params::new(3, 2).unwrap();
    let mut key_rng = StdRng::seed_from_u64(seed);
    let signers: Vec<(usize, SecretKey)> = (1..=3)
        .map(|i| (i, SecretKey::random(&mut key_rng)))
        .collect();
    let parties: Vec<(usize, SocketAddr)> = (1..=3)
        .map(|i| (i, SocketAddr::from(([127, 0, 0, 1], 0))))
        .collect();
    let mesh = MeshTransport::start(&parties, &signers, ROUND_TIMEOUT).unwrap();
    let transport = SigningTransport::new(mesh, &signers);
    let rngs = make_rngs(3, seed + 1);
    (params, signers, transport, rngs)
}

#[test]
fn mesh_keygen_reconstructs_joint_key() {
    let (params, _signers, mut transport, mut rngs) = start_committee(101);
    let outs = drive_dkg_signed(
        &params,
        b"sid/mesh-keygen",
        b"mesh-test/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    )
    .unwrap();
    assert_eq!(outs.len(), 3);
    // Any t = 2 shares reconstruct the joint secret under the public key.
    let parties = vec![1, 2];
    let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1].share).collect();
    let x = interpolate_at_zero(&parties, &shares);
    assert_eq!(ProjectivePoint::GENERATOR * x, outs[0].com.points[0]);
    // Three distinct shares came back over the wire.
    assert_ne!(outs[0].share, outs[1].share);
    assert_ne!(outs[1].share, outs[2].share);
}

#[test]
fn mesh_keygen_blames_cheating_dealer() {
    let (params, _signers, mut transport, mut rngs) = start_committee(102);
    let registry = transport.verifying_keys();
    // Dealer 2 deals a bad share to party 1 (fault class F2, §10.1): the
    // bad share travels over the wire inside party 2's signed envelope.
    let tamper = DkgTamper {
        bad_deal: Some((2, 1)),
        ..Default::default()
    };
    let err = drive_dkg_signed(
        &params,
        b"sid/mesh-blame",
        b"mesh-test/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        Some(&tamper),
    )
    .unwrap_err();
    let Error::Abort { abort } = &err.error else {
        panic!("expected identifiable abort, got {:?}", err.error)
    };
    assert_eq!(abort.blamed, vec![2]);
    let token = err.token.expect("a dealer fault leaves a blame token");
    assert_eq!(token.abort.blamed, vec![2]);
    assert!(token.verify(&registry));
}

#[test]
fn mesh_drops_forged_frames_and_completes() {
    let (params, signers, mut transport, mut rngs, victim_addr) = {
        let params = Params::new(3, 2).unwrap();
        let mut key_rng = StdRng::seed_from_u64(103);
        let signers: Vec<(usize, SecretKey)> = (1..=3)
            .map(|i| (i, SecretKey::random(&mut key_rng)))
            .collect();
        let parties: Vec<(usize, SocketAddr)> = (1..=3)
            .map(|i| (i, SocketAddr::from(([127, 0, 0, 1], 0))))
            .collect();
        let mesh = MeshTransport::start(&parties, &signers, ROUND_TIMEOUT).unwrap();
        // Node 1's address, before the mesh is wrapped.
        let victim_addr = mesh.local_addrs()[0].1;
        let transport = SigningTransport::new(mesh, &signers);
        let rngs = make_rngs(3, 104);
        (params, signers, transport, rngs, victim_addr)
    };

    // Spam node 1's listener with junk that must all be dropped:
    let mut sock = TcpStream::connect(victim_addr).unwrap();
    // (a) a well-formed envelope claiming to be from party 1 but signed
    //     with party 2's key (bad signature → drop + log);
    let forged = SignedEnvelope::sign(
        Envelope::broadcast(
            b"sid/mesh-forge",
            Phase::KeyGen,
            1,
            1,
            DkgMessage::Commit(DkgBcast1 {
                from: 1,
                hash: [0; 32],
            }),
        ),
        &SigningKey::from(&signers[1].1),
    );
    write_frame(&mut sock, &WireMessage::Original(forged)).unwrap();
    // (b) a well-formed envelope from an UNREGISTERED sender id 99
    //     (unknown sender → drop + log);
    let unknown = SignedEnvelope::sign(
        Envelope::broadcast(
            b"sid/mesh-forge",
            Phase::KeyGen,
            1,
            99,
            DkgMessage::Commit(DkgBcast1 {
                from: 99,
                hash: [1; 32],
            }),
        ),
        &SigningKey::from(&signers[0].1),
    );
    write_frame(&mut sock, &WireMessage::Original(unknown)).unwrap();
    // (c) a syntactically malformed frame (reader drops the connection).
    sock.write_all(&10u32.to_be_bytes()).unwrap();
    sock.write_all(&[0xAA; 10]).unwrap();

    // None of it poisons the session: the honest keygen completes.
    let outs = drive_dkg_signed(
        &params,
        b"sid/mesh-forge",
        b"mesh-test/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    )
    .unwrap();
    assert_eq!(outs.len(), 3);
    let parties = vec![2, 3];
    let shares: Vec<Scalar> = parties.iter().map(|&p| outs[p - 1].share).collect();
    let x = interpolate_at_zero(&parties, &shares);
    assert_eq!(ProjectivePoint::GENERATOR * x, outs[0].com.points[0]);
}
