//! M2 binary: sign a Sepolia (or Plume testnet, via `--chain-id`)
//! EIP-1559 transfer with the 2-of-3 OHM-ECDSA committee and broadcast
//! it through a JSON-RPC endpoint.
//!
//! Endpoint: `OHM_DEMO_RPC_URL` env var ONLY — never a flag default,
//! never a hardcoded URL.
//!
//! Default is a DRY RUN (prints everything, sends nothing). Pass
//! `--broadcast` to actually send.

use std::process::ExitCode;
use std::time::Duration;

use ohm_ecdsa_demo_evm::rpc::explorer_tx_url;
use ohm_ecdsa_demo_evm::tx::{hex_decode, hex_encode};
use ohm_ecdsa_demo_evm::{run_demo, DemoConfig, DEFAULT_TO, DEFAULT_VALUE_WEI, SEPOLIA_CHAIN_ID};

const USAGE: &str = "usage: demo-evm [--chain-id N] [--to 0xADDR] [--value-wei N] [--broadcast]
  env: OHM_DEMO_RPC_URL (required) — JSON-RPC endpoint
  default chain: 11155111 (Sepolia); Plume testnet: --chain-id 98899
  default: DRY RUN (nothing is sent); --broadcast sends";

fn main() -> ExitCode {
    let mut chain_id = SEPOLIA_CHAIN_ID;
    let mut to = DEFAULT_TO.to_string();
    let mut value_wei = DEFAULT_VALUE_WEI;
    let mut broadcast = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--broadcast" => broadcast = true,
            "--chain-id" => {
                i += 1;
                chain_id = match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(v) => v,
                    None => return usage("--chain-id needs a u64"),
                };
            }
            "--to" => {
                i += 1;
                match args.get(i) {
                    Some(v) => to = v.trim_start_matches("0x").to_string(),
                    None => return usage("--to needs an address"),
                }
            }
            "--value-wei" => {
                i += 1;
                value_wei = match args.get(i).and_then(|v| v.parse::<u128>().ok()) {
                    Some(v) => v,
                    None => return usage("--value-wei needs a u128"),
                };
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => return usage(&format!("unknown flag {other:?}")),
        }
        i += 1;
    }

    let rpc_url = match std::env::var("OHM_DEMO_RPC_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("error: OHM_DEMO_RPC_URL is not set");
            eprintln!("  export OHM_DEMO_RPC_URL=https://<your-sepolia-endpoint>");
            return ExitCode::from(2);
        }
    };

    let to_bytes: [u8; 20] = match hex_decode(&to).ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => return usage("--to must be 20 bytes of hex"),
    };

    let cfg = DemoConfig {
        rpc_url,
        chain_id,
        to: to_bytes,
        value_wei,
        broadcast,
        receipt_interval: Duration::from_secs(3),
        receipt_timeout: Duration::from_secs(120),
    };

    let report = match run_demo(&cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("== OHM-ECDSA → EVM demo (M2) ==");
    println!("chain id:      {chain_id}");
    println!("committee:     {}", report.address);
    println!("balance:       {} wei", report.balance_wei);

    if !report.funded {
        println!();
        println!("The committee address holds 0 wei. Fund it with testnet ETH");
        println!("and re-run — Sepolia faucets:");
        println!("  https://sepoliafaucet.com");
        println!("  https://cloud.google.com/application/web3/faucet/ethereum/sepolia");
        println!("  https://faucet.quicknode.com/ethereum/sepolia");
        return ExitCode::SUCCESS;
    }

    let arc = report.arc.expect("funded run signs");
    let fees = report.fees.expect("funded run has fees");
    println!(
        "nonce:         {}",
        report.nonce.expect("funded run has a nonce")
    );
    println!(
        "fees:          max {} wei = priority {} + 2×base",
        fees.max_fee_per_gas, fees.max_priority_fee_per_gas
    );
    println!("to:            0x{}", hex_encode(&cfg.to));
    println!("value:         {} wei", cfg.value_wei);
    println!("sighash:       0x{}", hex_encode(&arc.sighash));
    println!("y_parity:      {}", arc.y_parity as u8);
    println!("signed tx:     0x{}", hex_encode(&arc.signed_tx));

    match (report.tx_hash, report.receipt) {
        (Some(hash), Some(receipt)) => {
            println!();
            println!("broadcast:     0x{}", hex_encode(&hash));
            println!(
                "receipt:       status {} ({}), block {}, gas used {}",
                receipt.status as u8,
                if receipt.status {
                    "success"
                } else {
                    "REVERTED"
                },
                receipt.block_number,
                receipt.gas_used
            );
            if let Some(url) = explorer_tx_url(chain_id, &hash) {
                println!("explorer:      {url}");
            }
        }
        _ => {
            println!();
            println!("DRY RUN — nothing was sent. Re-run with --broadcast to send.");
        }
    }
    ExitCode::SUCCESS
}

fn usage(why: &str) -> ExitCode {
    eprintln!("error: {why}");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
