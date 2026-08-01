//! Blocking JSON-RPC client for Ethereum execution endpoints (HTTPS via
//! ureq/rustls; plain HTTP only in tests against the local mock).
//!
//! Only the methods the M2 flow needs: `eth_chainId`, `eth_getBalance`,
//! `eth_getTransactionCount`, `eth_maxPriorityFeePerGas` (optional —
//! `-32601` method-not-found falls back to `eth_gasPrice`),
//! `eth_feeHistory` (optional, for the base fee), `eth_gasPrice`,
//! `eth_sendRawTransaction`, and `eth_getTransactionReceipt` (polled
//! with a bounded timeout).
//!
//! Fee policy (sane, testable, see [`suggest_fees`]):
//! `max_fee = priority_fee + 2 × base_fee`, where the base fee comes
//! from `eth_feeHistory` when available and from `eth_gasPrice` as an
//! approximation otherwise.

use std::time::{Duration, Instant};

use crate::json::{self, Json};
use crate::tx::hex_decode;

/// JSON-RPC / transport failures.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("http transport: {0}")]
    Http(String),
    #[error("JSON-RPC error {code}: {message}")]
    Rpc { code: i128, message: String },
    #[error("malformed response: {0}")]
    BadResponse(String),
    #[error("timed out waiting for the transaction receipt")]
    ReceiptTimeout,
}

/// `eth_feeHistory`, only the parts we use.
#[derive(Clone, Debug, PartialEq)]
pub struct FeeHistory {
    /// Next-block base fee (last entry of `baseFeePerGas`), wei.
    pub next_base_fee: u128,
}

/// `eth_getTransactionReceipt`, only the parts we print.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
}

/// Suggested EIP-1559 fee pair.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fees {
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
}

/// `max_fee = priority + 2 × base` — priority from
/// `eth_maxPriorityFeePerGas` (or `eth_gasPrice` when unsupported), base
/// from `eth_feeHistory` (or `eth_gasPrice` as an approximation).
pub fn suggest_fees(
    priority: Option<u128>,
    gas_price: u128,
    fee_history: Option<&FeeHistory>,
) -> Fees {
    let max_priority_fee_per_gas = priority.unwrap_or(gas_price);
    let base = fee_history.map(|h| h.next_base_fee).unwrap_or(gas_price);
    Fees {
        max_priority_fee_per_gas,
        max_fee_per_gas: max_priority_fee_per_gas + 2 * base,
    }
}

/// Blocking client over one ureq agent (connection reuse).
pub struct Client {
    url: String,
    agent: ureq::Agent,
    next_id: u64,
}

impl Client {
    pub fn new(url: &str) -> Client {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        Client {
            url: url.to_string(),
            agent,
            next_id: 1,
        }
    }

    /// One JSON-RPC call; returns the `result` value or the peer's
    /// error object.
    fn call(&mut self, method: &str, params: Json) -> Result<Json, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let body = Json::Object(vec![
            ("jsonrpc".into(), Json::Str("2.0".into())),
            ("id".into(), Json::Int(id as i128)),
            ("method".into(), Json::Str(method.into())),
            ("params".into(), params),
        ]);
        let resp = self
            .agent
            .post(&self.url)
            .set("content-type", "application/json")
            .send_string(&body.to_string());
        let text = match resp {
            Ok(r) => r.into_string().map_err(|e| RpcError::Http(e.to_string()))?,
            Err(ureq::Error::Status(code, r)) => {
                // JSON-RPC errors arrive with HTTP 4xx/5xx on some nodes;
                // try the body before giving up.
                let text = r.into_string().map_err(|e| RpcError::Http(e.to_string()))?;
                if text.trim_start().starts_with('{') {
                    text
                } else {
                    return Err(RpcError::Http(format!("HTTP {code}")));
                }
            }
            Err(e) => return Err(RpcError::Http(e.to_string())),
        };
        let v =
            json::parse(&text).map_err(|e| RpcError::BadResponse(format!("invalid JSON: {e}")))?;
        if let Some(err) = v.get("error") {
            let code = err.get("code").and_then(Json::as_int).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Json::as_str)
                .unwrap_or("unknown")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::BadResponse("no result field".into()))
    }

    /// `eth_chainId` → chain id.
    pub fn chain_id(&mut self) -> Result<u64, RpcError> {
        let v = self.call("eth_chainId", Json::Array(vec![]))?;
        let q = v
            .as_str()
            .ok_or_else(|| RpcError::BadResponse("chainId not a string".into()))?;
        quantity_u64(q)
    }

    /// `eth_getBalance(addr, "latest")` → wei.
    pub fn get_balance(&mut self, address: &str) -> Result<u128, RpcError> {
        let v = self.call(
            "eth_getBalance",
            Json::Array(vec![Json::Str(address.into()), Json::Str("latest".into())]),
        )?;
        let q = v
            .as_str()
            .ok_or_else(|| RpcError::BadResponse("balance not a string".into()))?;
        quantity_u128(q)
    }

    /// `eth_getTransactionCount(addr, "pending")` → next nonce.
    pub fn get_transaction_count(&mut self, address: &str) -> Result<u64, RpcError> {
        let v = self.call(
            "eth_getTransactionCount",
            Json::Array(vec![Json::Str(address.into()), Json::Str("pending".into())]),
        )?;
        let q = v
            .as_str()
            .ok_or_else(|| RpcError::BadResponse("nonce not a string".into()))?;
        quantity_u64(q)
    }

    /// `eth_maxPriorityFeePerGas` → wei, or `Ok(None)` when the node
    /// does not support the method (`-32601`).
    pub fn max_priority_fee_per_gas(&mut self) -> Result<Option<u128>, RpcError> {
        match self.call("eth_maxPriorityFeePerGas", Json::Array(vec![])) {
            Ok(v) => {
                let q = v
                    .as_str()
                    .ok_or_else(|| RpcError::BadResponse("fee not a string".into()))?;
                Ok(Some(quantity_u128(q)?))
            }
            Err(RpcError::Rpc { code: -32601, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `eth_gasPrice` → wei.
    pub fn gas_price(&mut self) -> Result<u128, RpcError> {
        let v = self.call("eth_gasPrice", Json::Array(vec![]))?;
        let q = v
            .as_str()
            .ok_or_else(|| RpcError::BadResponse("gasPrice not a string".into()))?;
        quantity_u128(q)
    }

    /// `eth_feeHistory(4, "latest", [])` — errors are non-fatal
    /// (`Ok(None)`); the caller falls back to `eth_gasPrice`.
    pub fn fee_history(&mut self) -> Result<Option<FeeHistory>, RpcError> {
        match self.call(
            "eth_feeHistory",
            Json::Array(vec![
                Json::Str("0x4".into()),
                Json::Str("latest".into()),
                Json::Array(vec![]),
            ]),
        ) {
            Ok(v) => {
                let fees = v
                    .get("baseFeePerGas")
                    .and_then(Json::as_array)
                    .ok_or_else(|| RpcError::BadResponse("no baseFeePerGas".into()))?;
                let last = fees
                    .last()
                    .and_then(Json::as_str)
                    .ok_or_else(|| RpcError::BadResponse("empty baseFeePerGas".into()))?;
                Ok(Some(FeeHistory {
                    next_base_fee: quantity_u128(last)?,
                }))
            }
            Err(RpcError::Rpc { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `eth_sendRawTransaction` → the transaction hash.
    pub fn send_raw_transaction(&mut self, signed_tx: &[u8]) -> Result<[u8; 32], RpcError> {
        let hex = format!("0x{}", crate::tx::hex_encode(signed_tx));
        let v = self.call("eth_sendRawTransaction", Json::Array(vec![Json::Str(hex)]))?;
        let h = v
            .as_str()
            .ok_or_else(|| RpcError::BadResponse("tx hash not a string".into()))?;
        let bytes =
            hex_decode(h).map_err(|e| RpcError::BadResponse(format!("tx hash not hex: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| RpcError::BadResponse("tx hash not 32 bytes".into()))
    }

    /// `eth_getTransactionReceipt` → `Ok(None)` while pending.
    pub fn get_transaction_receipt(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<Receipt>, RpcError> {
        let v = self.call(
            "eth_getTransactionReceipt",
            Json::Array(vec![Json::Str(format!(
                "0x{}",
                crate::tx::hex_encode(hash)
            ))]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let status_hex = v
            .get("status")
            .and_then(Json::as_str)
            .ok_or_else(|| RpcError::BadResponse("receipt without status".into()))?;
        let status = match status_hex {
            "0x1" => true,
            "0x0" => false,
            other => return Err(RpcError::BadResponse(format!("bad status {other}"))),
        };
        let block_number = quantity_u64(
            v.get("blockNumber")
                .and_then(Json::as_str)
                .ok_or_else(|| RpcError::BadResponse("receipt without blockNumber".into()))?,
        )?;
        let gas_used = quantity_u64(
            v.get("gasUsed")
                .and_then(Json::as_str)
                .ok_or_else(|| RpcError::BadResponse("receipt without gasUsed".into()))?,
        )?;
        Ok(Some(Receipt {
            status,
            block_number,
            gas_used,
        }))
    }

    /// Poll for the receipt every `interval` until `timeout`.
    pub fn wait_for_receipt(
        &mut self,
        hash: &[u8; 32],
        interval: Duration,
        timeout: Duration,
    ) -> Result<Receipt, RpcError> {
        let start = Instant::now();
        loop {
            if let Some(receipt) = self.get_transaction_receipt(hash)? {
                return Ok(receipt);
            }
            if start.elapsed() >= timeout {
                return Err(RpcError::ReceiptTimeout);
            }
            std::thread::sleep(interval);
        }
    }
}

/// Parse a JSON-RPC QUANTITY (`0x`-prefixed hex, `0x0` = 0) into u128.
pub fn quantity_u128(q: &str) -> Result<u128, RpcError> {
    let hex = q
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::BadResponse(format!("quantity {q:?} missing 0x prefix")))?;
    if hex.is_empty() || hex.len() > 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RpcError::BadResponse(format!("bad quantity {q:?}")));
    }
    u128::from_str_radix(hex, 16).map_err(|_| RpcError::BadResponse(format!("bad quantity {q:?}")))
}

/// QUANTITY into u64 (rejects values that do not fit).
pub fn quantity_u64(q: &str) -> Result<u64, RpcError> {
    let v = quantity_u128(q)?;
    u64::try_from(v).map_err(|_| RpcError::BadResponse(format!("quantity {q:?} exceeds u64")))
}

/// Explorer transaction URL by chain id (Sepolia / Plume testnet).
pub fn explorer_tx_url(chain_id: u64, tx_hash: &[u8; 32]) -> Option<String> {
    let base = match chain_id {
        11155111 => "https://sepolia.etherscan.io",
        98899 => "https://testnet-explorer.plume.org",
        _ => return None,
    };
    Some(format!("{base}/tx/0x{}", crate::tx::hex_encode(tx_hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantity_parsing() {
        assert_eq!(quantity_u128("0x0").unwrap(), 0);
        assert_eq!(quantity_u128("0x1").unwrap(), 1);
        assert_eq!(
            quantity_u128("0xde0b6b3a7640000").unwrap(),
            1_000_000_000_000_000_000
        );
        assert_eq!(quantity_u64("0xaa36a7").unwrap(), 11155111);
        assert_eq!(quantity_u64("0x5208").unwrap(), 21_000);
        // Malformed / out of range.
        assert!(quantity_u128("").is_err());
        assert!(quantity_u128("0x").is_err());
        assert!(quantity_u128("100").is_err());
        assert!(quantity_u128("0xZZ").is_err());
        assert!(quantity_u128(&format!("0x{}", "f".repeat(33))).is_err());
        assert!(quantity_u64("0x10000000000000000").is_err()); // 2^64
    }

    #[test]
    fn fee_cap_logic() {
        let g = 1_000_000_000u128; // 1 gwei
                                   // Happy path: priority method supported + feeHistory base fee.
        let f = suggest_fees(
            Some(2 * g),
            30 * g,
            Some(&FeeHistory {
                next_base_fee: 20 * g,
            }),
        );
        assert_eq!(f.max_priority_fee_per_gas, 2 * g);
        assert_eq!(f.max_fee_per_gas, 2 * g + 2 * 20 * g);
        // Method unsupported: gasPrice becomes the priority fee.
        let f = suggest_fees(
            None,
            30 * g,
            Some(&FeeHistory {
                next_base_fee: 20 * g,
            }),
        );
        assert_eq!(f.max_priority_fee_per_gas, 30 * g);
        assert_eq!(f.max_fee_per_gas, 30 * g + 40 * g);
        // No feeHistory: gasPrice approximates the base fee.
        let f = suggest_fees(Some(2 * g), 30 * g, None);
        assert_eq!(f.max_fee_per_gas, 2 * g + 60 * g);
        // Neither: legacy-shaped (priority = base = gasPrice).
        let f = suggest_fees(None, 30 * g, None);
        assert_eq!(f.max_priority_fee_per_gas, 30 * g);
        assert_eq!(f.max_fee_per_gas, 90 * g);
    }

    #[test]
    fn explorer_links() {
        let hash = [0xabu8; 32];
        assert_eq!(
            explorer_tx_url(11155111, &hash).unwrap(),
            format!("https://sepolia.etherscan.io/tx/0x{}", "ab".repeat(32))
        );
        assert_eq!(
            explorer_tx_url(98899, &hash).unwrap(),
            format!(
                "https://testnet-explorer.plume.org/tx/0x{}",
                "ab".repeat(32)
            )
        );
        assert!(explorer_tx_url(1, &hash).is_none());
    }
}
