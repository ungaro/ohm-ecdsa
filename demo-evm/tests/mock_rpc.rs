//! M2 end-to-end against a MOCKED JSON-RPC endpoint: a tiny blocking
//! `std::net::TcpListener` answers the canned RPC responses — no
//! external network, no live endpoint in tests.
//!
//! The Sepolia receipt body is a CONSTRUCTED fixture (field-for-field
//! the geth receipt shape: status/blockNumber/gasUsed plus the usual
//! extra fields, which the parser must ignore).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ohm_ecdsa_demo_evm::json::{self, Json};
use ohm_ecdsa_demo_evm::tx::hex_encode;
use ohm_ecdsa_demo_evm::{
    run_demo, DemoConfig, DemoError, DemoReport, Driver, DEFAULT_VALUE_WEI, SEPOLIA_CHAIN_ID,
};

/// CONSTRUCTED Sepolia-shaped receipt (status 1, plain transfer).
const RECEIPT: &str = r#"{
  "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
  "blockNumber": "0x123456",
  "contractAddress": null,
  "cumulativeGasUsed": "0x5208",
  "effectiveGasPrice": "0x147d83300",
  "from": "0x729bb22d46a1790708a3cfb2aae7f74de8c9e970",
  "gasUsed": "0x5208",
  "logs": [],
  "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "status": "0x1",
  "to": "0x3535353535353535353535353535353535353535",
  "transactionHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
  "transactionIndex": "0x0",
  "type": "0x2"
}"#;

/// REAL Sepolia receipt: tx
/// 0x730bc698f3799b09de2ab8ef0ab138ea26bfe8e796a4c9ddea76266ce2acbfa4
/// (block 0xadedb3), fetched 2026-08 from the public endpoint
/// ethereum-sepolia-rpc.publicnode.com. Exercises the parser against
/// nested logs, `removed` booleans, and a legacy (type 0x0) receipt.
const REAL_SEPOLIA_RECEIPT: &str = r#"{
  "blockHash": "0xfd9db4fe6c7112e040d69546bd5a7eef07eef45ea9a01595ad84eec11e119d30",
  "blockNumber": "0xadedb3",
  "contractAddress": null,
  "cumulativeGasUsed": "0x1f331",
  "effectiveGasPrice": "0x2540be400",
  "from": "0xc687faae8f23f9c9d5deb16a69f07a749ddf0952",
  "gasUsed": "0x1f331",
  "logs": [
    {
      "address": "0x956962c34687a954e611a83619abaa37ce6bc78a",
      "topics": [
        "0xb3813568d9991fc951961fcb4c784893574240a28925604d09fc577c55bb7c32",
        "0x000000000000000000000000c687faae8f23f9c9d5deb16a69f07a749ddf0952",
        "0x0000000000000000000000000878daa71980a7fa0eb450e9a4d91ec70cf76b57",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      ],
      "data": "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000490000000000000000000000000000000000000000000000000017ee5b373500000000000000000000000000000000000000000000000000000017ee5b3735000000000000000186a0000000000000000000000000000000000000000000000000",
      "blockNumber": "0xadedb3",
      "transactionHash": "0x730bc698f3799b09de2ab8ef0ab138ea26bfe8e796a4c9ddea76266ce2acbfa4",
      "transactionIndex": "0x0",
      "blockHash": "0xfd9db4fe6c7112e040d69546bd5a7eef07eef45ea9a01595ad84eec11e119d30",
      "blockTimestamp": "0x6a6e4fbc",
      "logIndex": "0x0",
      "removed": false
    }
  ],
  "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000001000000000000000000000020000000000000000000840020000000000000000000100008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000040000000000800000002000000001000000080000000000000000000000",
  "status": "0x1",
  "to": "0x956962c34687a954e611a83619abaa37ce6bc78a",
  "transactionHash": "0x730bc698f3799b09de2ab8ef0ab138ea26bfe8e796a4c9ddea76266ce2acbfa4",
  "transactionIndex": "0x0",
  "type": "0x0"
}"#;

/// A scripted mock endpoint: `responses` maps method → result JSON
/// (string, substituted verbatim into `{"jsonrpc":"2.0","id":N,"result":…}`).
/// Methods not in the map get a `-32601` error. Every request body is
/// recorded for shape assertions.
struct Mock {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn start(responses: Vec<(&'static str, String)>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let body = match read_http_request(&mut stream) {
                    Some(b) => b,
                    None => continue,
                };
                seen2.lock().unwrap().push(body.clone());
                let Ok(req) = json::parse(&body) else {
                    continue;
                };
                let method = req
                    .get("method")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string();
                let id = req.get("id").and_then(Json::as_int).unwrap_or(0);
                let payload = match responses.iter().find(|(m, _)| *m == method) {
                    Some((_, result)) => {
                        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
                    }
                    None => format!(
                        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"the method {method} does not exist/is not available"}}}}"#
                    ),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Mock {
            url: format!("http://{addr}"),
            seen,
        }
    }

    fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter_map(|b| {
                json::parse(b)
                    .ok()
                    .and_then(|v| v.get("method").and_then(Json::as_str).map(str::to_string))
            })
            .collect()
    }
}

/// Read one HTTP request (headers + content-length body).
fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = std::str::from_utf8(&buf[..header_end]).ok()?;
    let content_len: usize = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf[header_end..header_end + content_len].to_vec()).ok()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn cfg(url: &str, broadcast: bool) -> DemoConfig {
    DemoConfig {
        rpc_url: url.to_string(),
        chain_id: SEPOLIA_CHAIN_ID,
        to: [0x35u8; 20],
        value_wei: DEFAULT_VALUE_WEI,
        broadcast,
        driver: Driver::Sim,
        data_dir: std::path::PathBuf::new(),
        receipt_interval: Duration::from_millis(10),
        receipt_timeout: Duration::from_secs(5),
    }
}

/// Canned funded-chain responses (1.5 gwei priority, 30 gwei gasPrice,
/// next base fee 2 gwei → max fee 1.5 + 2×2 = 5.5 gwei).
fn funded_responses() -> Vec<(&'static str, String)> {
    vec![
        ("eth_chainId", "\"0xaa36a7\"".into()),
        ("eth_getBalance", "\"0xde0b6b3a7640000\"".into()), // 1 ETH
        ("eth_getTransactionCount", "\"0x7\"".into()),
        ("eth_maxPriorityFeePerGas", "\"0x59682f00\"".into()), // 1.5 gwei
        ("eth_gasPrice", "\"0x6fc23ac00\"".into()),          // 30 gwei
        (
            "eth_feeHistory",
            r#"{"oldestBlock":"0x123450","baseFeePerGas":["0x3b9aca00","0x3b9aca01","0x3b9aca02","0x3b9aca03","0x77359400"],"gasUsedRatio":[0.5,0.5,0.5,0.5]}"#.into(),
        ),
    ]
}

#[test]
fn dry_run_end_to_end_mocked_rpc() {
    let mock = Mock::start(funded_responses());
    let report = run_demo(&cfg(&mock.url, false)).unwrap();

    // The dry-run variant is signature-free BY TYPE (no arc, no tx_hash
    // — there is nothing to check for absence of).
    let dry = match report {
        DemoReport::DryRun(d) => d,
        other => panic!("expected DryRun, got {other:?}"),
    };
    assert_eq!(dry.nonce, 7);
    assert_eq!(dry.fees.max_priority_fee_per_gas, 1_500_000_000);
    assert_eq!(dry.fees.max_fee_per_gas, 1_500_000_000 + 2 * 2_000_000_000);
    assert_eq!(dry.unsigned_sighash, dry.tx.sighash());
    assert_eq!(dry.tx.nonce, 7, "the unsigned tx carries the live nonce");

    // The exact RPC call sequence, then nothing else.
    assert_eq!(
        mock.methods(),
        vec![
            "eth_chainId",
            "eth_getBalance",
            "eth_getTransactionCount",
            "eth_maxPriorityFeePerGas",
            "eth_gasPrice",
            "eth_feeHistory",
        ]
    );

    // Request shapes: nonce is fetched at "pending" for the committee
    // address; ids increment.
    let seen = mock.seen.lock().unwrap();
    let nonce_req = json::parse(&seen[2]).unwrap();
    let params = nonce_req.get("params").and_then(Json::as_array).unwrap();
    assert_eq!(params[0].as_str(), Some(dry.address.as_str()));
    assert_eq!(params[1].as_str(), Some("pending"));
    let ids: Vec<i128> = seen
        .iter()
        .filter_map(|b| {
            json::parse(b)
                .ok()
                .and_then(|v| v.get("id").and_then(Json::as_int))
        })
        .collect();
    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6]);
    drop(seen);
}

#[test]
fn broadcast_end_to_end_mocked_rpc() {
    let mut responses = funded_responses();
    responses.push((
        "eth_sendRawTransaction",
        format!("\"0x{}\"", "22".repeat(32)),
    ));
    responses.push(("eth_getTransactionReceipt", RECEIPT.into()));
    let mock = Mock::start(responses);

    let report = run_demo(&cfg(&mock.url, true)).unwrap();
    let b = match report {
        DemoReport::Broadcast(b) => b,
        other => panic!("expected Broadcast, got {other:?}"),
    };
    assert_eq!(b.tx_hash, [0x22u8; 32]);
    assert!(b.receipt.status);
    assert_eq!(b.receipt.block_number, 0x123456);
    assert_eq!(b.receipt.gas_used, 21_000);

    // The raw transaction sent is exactly the signed tx from the arc
    // (signed with a FRESH presignature — the assertion is independent
    // of which k was drawn).
    let seen = mock.seen.lock().unwrap();
    let send_req = seen
        .iter()
        .map(|b| json::parse(b).unwrap())
        .find(|v| v.get("method").and_then(Json::as_str) == Some("eth_sendRawTransaction"))
        .unwrap();
    let raw = send_req.get("params").and_then(Json::as_array).unwrap()[0]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(raw, format!("0x{}", hex_encode(&b.arc.signed_tx)));
    drop(seen); // release before methods() locks the same mutex
    let methods = mock.methods();
    assert_eq!(
        methods.last().map(String::as_str),
        Some("eth_getTransactionReceipt")
    );
}

#[test]
fn unfunded_committee_exits_at_the_faucet_gate() {
    let mock = Mock::start(vec![
        ("eth_chainId", "\"0xaa36a7\"".into()),
        ("eth_getBalance", "\"0x0\"".into()),
    ]);
    let report = run_demo(&cfg(&mock.url, false)).unwrap();
    assert!(
        matches!(report, DemoReport::Unfunded { .. }),
        "unfunded: no signing, no sending"
    );
    assert_eq!(mock.methods(), vec!["eth_chainId", "eth_getBalance"]);
}

#[test]
fn chain_id_mismatch_refuses() {
    let mock = Mock::start(vec![("eth_chainId", "\"0x1\"".into())]); // mainnet!
    let err = run_demo(&cfg(&mock.url, false)).unwrap_err();
    match err {
        DemoError::ChainIdMismatch { expected, got } => {
            assert_eq!(expected, SEPOLIA_CHAIN_ID);
            assert_eq!(got, 1);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
    assert_eq!(
        mock.methods(),
        vec!["eth_chainId"],
        "nothing else may be called"
    );
}

#[test]
fn real_sepolia_receipt_fixture_parses() {
    let mut responses = funded_responses();
    responses.push((
        "eth_sendRawTransaction",
        format!("\"0x{}\"", "22".repeat(32)),
    ));
    responses.push(("eth_getTransactionReceipt", REAL_SEPOLIA_RECEIPT.into()));
    let mock = Mock::start(responses);
    let report = run_demo(&cfg(&mock.url, true)).unwrap();
    let receipt = match report {
        DemoReport::Broadcast(b) => b.receipt,
        other => panic!("expected Broadcast, got {other:?}"),
    };
    assert!(receipt.status);
    assert_eq!(receipt.block_number, 0xadedb3);
    assert_eq!(receipt.gas_used, 0x1f331);
}

#[test]
fn unsupported_priority_method_falls_back_to_gas_price() {
    // No eth_maxPriorityFeePerGas entry → the mock answers -32601.
    let mock = Mock::start(vec![
        ("eth_chainId", "\"0xaa36a7\"".into()),
        ("eth_getBalance", "\"0xde0b6b3a7640000\"".into()),
        ("eth_getTransactionCount", "\"0x0\"".into()),
        ("eth_gasPrice", "\"0x6fc23ac00\"".into()), // 30 gwei
        (
            "eth_feeHistory",
            r#"{"oldestBlock":"0x1","baseFeePerGas":["0x77359400","0x77359400"],"gasUsedRatio":[0.5]}"#.into(),
        ),
    ]);
    let report = run_demo(&cfg(&mock.url, false)).unwrap();
    let fees = match report {
        DemoReport::DryRun(d) => d.fees,
        other => panic!("expected DryRun, got {other:?}"),
    };
    // Fallback: priority = gasPrice = 30 gwei; max = 30 + 2×2 = 34 gwei.
    assert_eq!(fees.max_priority_fee_per_gas, 30_000_000_000);
    assert_eq!(fees.max_fee_per_gas, 34_000_000_000);
}
