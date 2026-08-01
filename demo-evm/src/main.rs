//! M1 binary: run the local arc and print the committee address, the
//! EIP-1559 sighash, and the broadcast-ready signed transaction hex.

use ohm_ecdsa_demo_evm::tx::hex_encode;
use ohm_ecdsa_demo_evm::{demo_tx, run_arc};

fn main() {
    let out = run_arc(&demo_tx()).expect("the M1 arc must succeed");
    println!("== OHM-ECDSA → EVM demo (M1, local only) ==");
    println!("committee (2-of-3 Sepolia): {}", out.address);
    println!("sighash:                    0x{}", hex_encode(&out.sighash));
    println!("y_parity:                   {}", out.y_parity as u8);
    println!("signed tx (broadcast-ready):");
    println!("0x{}", hex_encode(&out.signed_tx));
}
