//! M1 demo: a 2-of-3 keygen committee over real TCP on localhost,
//! driven through `drive_dkg_signed` over `MeshTransport`.
//!
//! Run: `cargo run -p ohm-ecdsa-node [-- PORT_BASE]`
//! `PORT_BASE` 0 (default) = ephemeral ports; otherwise party `i` binds
//! `127.0.0.1:PORT_BASE + i - 1`.

use std::net::SocketAddr;
use std::process::ExitCode;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ohm_ecdsa::transport::{drive_dkg_signed, SigningTransport};
use ohm_ecdsa::{session_id, Params, Phase};
use ohm_ecdsa_node::{MeshTransport, DEFAULT_ROUND_TIMEOUT};
use rand::rngs::OsRng;

fn main() -> ExitCode {
    let port_base: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    println!("== ohm-ecdsa-node M1 demo: 2-of-3 keygen over real TCP ==");
    let params = Params::new(3, 2).expect("valid params");

    // Transport keys (the deployment PKI of SPEC §13.1), one per party;
    // M1 is the reference-orchestration pattern, so this one process
    // holds all three.
    let signers: Vec<(usize, SecretKey)> = (1..=3)
        .map(|i| (i, SecretKey::random(&mut OsRng)))
        .collect();

    let parties: Vec<(usize, SocketAddr)> = (1..=3usize)
        .map(|i| {
            let port = if port_base == 0 {
                0
            } else {
                port_base + i as u16 - 1
            };
            (i, SocketAddr::from(([127, 0, 0, 1], port)))
        })
        .collect();
    let mesh = match MeshTransport::start(&parties, &signers, DEFAULT_ROUND_TIMEOUT) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mesh setup failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    for (id, addr) in mesh.local_addrs() {
        println!("  node {id} listening on {addr}");
    }
    println!("  full mesh up; echo broadcast accepts on 2-of-3 consistent echoes");
    println!("  every envelope is signed by its sender and verified on receipt");

    let mut transport = SigningTransport::new(mesh, &signers);
    let sid = session_id(b"ohm-ecdsa-node/demo", b"demo-key", None, b"keygen");
    let mut rngs: Vec<_> = (0..3).map(|_| OsRng).collect();
    let outs = match drive_dkg_signed(
        &params,
        &sid,
        b"ohm-ecdsa-node/dkg",
        Phase::KeyGen,
        &mut rngs,
        &mut transport,
        None,
    ) {
        Ok(outs) => outs,
        Err(e) => {
            eprintln!("keygen aborted: {e}");
            return ExitCode::FAILURE;
        }
    };
    for out in &outs {
        println!("  party {} holds key share x_{}", out.index, out.index);
    }
    let x = outs[0].com.points[0].to_affine().to_encoded_point(true);
    println!("  joint public key X = {}", hex(x.as_bytes()));
    println!("  keygen complete through drive_dkg_signed over MeshTransport");
    ExitCode::SUCCESS
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
