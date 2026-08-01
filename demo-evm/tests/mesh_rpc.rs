//! M3 mesh-driver tests: the demo committee as three REAL `PartyNode`
//! drivers on loopback TCP with per-node durable single-use stores.
//!
//! Coverage: address determinism across setups (deterministic keygen →
//! stable funded address) AND freshness vs the burned M2 sim committee,
//! a full mock-RPC broadcast through the mesh driver (sign via
//! `sign_stored_scalar` → raw tx == signed tx → receipt), the dry-run
//! staying signature-free while warming the stores, and durable
//! single-use: re-signing a consumed presignature id fails.
//!
//! Data dirs are per-test temp dirs — never the real `data/mesh`.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ohm_ecdsa::scalar_from_digest;
use ohm_ecdsa_demo_evm::json::{self, Json};
use ohm_ecdsa_demo_evm::tx::hex_encode;
use ohm_ecdsa_demo_evm::{
    mesh, run_demo, Committee, DemoConfig, DemoError, DemoReport, Driver, DEFAULT_VALUE_WEI,
    SEPOLIA_CHAIN_ID,
};

/// A fresh empty temp directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "ohm-demo-mesh-test-{name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic keygen → the SAME mesh address across setups and data
/// dirs; DISTINCT from the sim committee (burned in the k-reuse
/// incident — the mesh committee is a fresh key).
#[test]
fn mesh_address_is_deterministic_and_fresh() {
    let a = mesh::setup(&tmpdir("addr-a")).unwrap();
    let b = mesh::setup(&tmpdir("addr-b")).unwrap();
    assert_eq!(a.address, b.address, "deterministic keygen must be stable");
    let sim = Committee::deterministic().unwrap();
    assert_ne!(a.address, sim.address(), "mesh committee is a NEW key");
    // Sanity: a real EIP-55 address.
    assert!(a.address.starts_with("0x") && a.address.len() == 42);
}

// --- minimal mock JSON-RPC endpoint (as in mock_rpc.rs) -------------------

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
                        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"unsupported"}}}}"#
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
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = std::str::from_utf8(&buf[..header_end]).ok()?;
    let content_len: usize = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
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

fn funded_responses() -> Vec<(&'static str, String)> {
    vec![
        ("eth_chainId", "\"0xaa36a7\"".into()),
        ("eth_getBalance", "\"0xde0b6b3a7640000\"".into()), // 1 ETH
        ("eth_getTransactionCount", "\"0x3\"".into()),
        ("eth_maxPriorityFeePerGas", "\"0x59682f00\"".into()),
        ("eth_gasPrice", "\"0x6fc23ac00\"".into()),
        (
            "eth_feeHistory",
            r#"{"oldestBlock":"0x1","baseFeePerGas":["0x77359400","0x77359400"],"gasUsedRatio":[0.5]}"#.into(),
        ),
    ]
}

fn cfg(url: &str, data_dir: PathBuf, broadcast: bool) -> DemoConfig {
    DemoConfig {
        rpc_url: url.to_string(),
        chain_id: SEPOLIA_CHAIN_ID,
        to: [0x35u8; 20],
        value_wei: DEFAULT_VALUE_WEI,
        broadcast,
        driver: Driver::Mesh,
        data_dir,
        receipt_interval: Duration::from_millis(10),
        receipt_timeout: Duration::from_secs(5),
    }
}

/// Dry run through the mesh driver: keygen + store warmup happen
/// (setup), but the report is signature-free by type — and the durable
/// stores now hold the minted record.
#[test]
fn mesh_dry_run_warms_stores_and_never_signs() {
    let mock = Mock::start(funded_responses());
    let dir = tmpdir("dry");
    let report = run_demo(&cfg(&mock.url, dir.clone(), false)).unwrap();
    let dry = match report {
        DemoReport::DryRun(d) => d,
        other => panic!("expected DryRun, got {other:?}"),
    };
    assert_eq!(
        dry.address,
        mesh::setup(&tmpdir("dry-check")).unwrap().address
    );
    assert_eq!(dry.nonce, 3);
    // The warmup minted presignature #0 and persisted it per node, and
    // the id counter advanced (monotonic across runs).
    assert_eq!(
        fs::read_to_string(dir.join("next-presign-id"))
            .unwrap()
            .trim(),
        "1"
    );
    for id in 1..=3 {
        assert!(dir.join(format!("node-{id}/store/0.presig")).exists());
    }
}

/// Full broadcast through the mesh driver: `sign_stored_scalar` over
/// the wire, raw tx == signed tx, receipt polled — then a second sign
/// with the SAME (consumed) id fails at the durable store.
#[test]
fn mesh_broadcast_end_to_end_and_single_use() {
    let mut responses = funded_responses();
    responses.push((
        "eth_sendRawTransaction",
        format!("\"0x{}\"", "33".repeat(32)),
    ));
    responses.push((
        "eth_getTransactionReceipt",
        r#"{"status":"0x1","blockNumber":"0xabc","gasUsed":"0x5208"}"#.into(),
    ));
    let mock = Mock::start(responses);
    let dir = tmpdir("broadcast");

    let report = run_demo(&cfg(&mock.url, dir.clone(), true)).unwrap();
    let b = match report {
        DemoReport::Broadcast(b) => b,
        other => panic!("expected Broadcast, got {other:?}"),
    };
    assert_eq!(b.tx_hash, [0x33u8; 32]);
    assert!(b.receipt.status);
    assert_eq!(b.receipt.gas_used, 21_000);

    // Raw tx on the wire == the signed tx from the mesh arc.
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
    drop(seen);

    // The broadcast consumed presignature id 0 (first sign-id)...
    for id in 1..=3 {
        assert!(dir.join(format!("node-{id}/store/0.consumed")).exists());
    }
    // ...and re-signing the SAME id fails at the durable store — the
    // failed/burned attempt is not retryable with the same record.
    let m = scalar_from_digest(&b.arc.sighash);
    let err = mesh::sign_with_id(&dir, 0, &m).unwrap_err();
    assert!(
        matches!(err, DemoError::Store(_)),
        "second sign with consumed id 0: {err:?}"
    );
}
