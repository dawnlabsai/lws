//! [Blockfrost](https://blockfrost.io) RPC provider.

use super::{blocking_client, CardanoRpcError, CardanoRpcProvider, ADA_DECIMALS};
use crate::{BalanceInfo, TokenBalance};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct Amount {
    unit: String,
    quantity: String,
}

#[derive(Debug, Deserialize)]
struct AddressInfo {
    amount: Vec<Amount>,
}

#[derive(Debug, Deserialize)]
struct AssetInfo {
    fingerprint: String,
    metadata: Option<AssetMetadata>,
}

#[derive(Debug, Deserialize)]
struct AssetMetadata {
    ticker: Option<String>,
    decimals: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TxCborResponse {
    cbor: String,
}

/// Split a Blockfrost asset `unit` into `(policy_id, asset_name)` — the policy
/// id is the first 28 bytes (56 hex chars); the rest is the (hex) asset name.
fn split_asset_unit(unit: &str) -> (String, String) {
    if unit.len() >= 56 {
        (unit[..56].to_string(), unit[56..].to_string())
    } else {
        (unit.to_string(), String::new())
    }
}

/// [Blockfrost](https://blockfrost.io) RPC provider. Authenticates every
/// request with the `project_id` header.
pub struct BlockfrostProvider {
    base_url: String,
    project_id: String,
}

impl BlockfrostProvider {
    pub fn new(base_url: &str, project_id: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            project_id,
        }
    }

    fn get(
        &self,
        client: &reqwest::blocking::Client,
        path: &str,
    ) -> Result<reqwest::blocking::Response, CardanoRpcError> {
        client
            .get(format!("{}{}", self.base_url, path))
            .header("project_id", &self.project_id)
            .send()
            .map_err(|e| CardanoRpcError::Http(e.to_string()))
    }
}

impl CardanoRpcProvider for BlockfrostProvider {
    fn broadcast_tx(&self, tx_cbor: &[u8]) -> Result<String, CardanoRpcError> {
        let url = format!("{}/tx/submit", self.base_url);
        let client = blocking_client()?;

        let resp = client
            .post(&url)
            .header("project_id", &self.project_id)
            .header("Content-Type", "application/cbor")
            .body(tx_cbor.to_vec())
            .send()
            .map_err(|e| CardanoRpcError::Http(e.to_string()))?;

        let status = resp.status();
        let body = resp.text().unwrap_or_default();

        if !status.is_success() {
            return Err(CardanoRpcError::Rpc(format!(
                "Blockfrost tx submit failed ({status}): {body}"
            )));
        }

        let tx_hash = body.trim().trim_matches('"').to_string();
        if tx_hash.len() != 64 {
            return Err(CardanoRpcError::Rpc(format!(
                "Blockfrost broadcast: invalid transaction hash in response: {tx_hash}"
            )));
        }

        Ok(tx_hash)
    }

    fn fetch_txs_cbor(
        &self,
        tx_hashes: &[String],
    ) -> Result<BTreeMap<String, String>, CardanoRpcError> {
        if tx_hashes.is_empty() {
            return Ok(BTreeMap::new());
        }

        let client = blocking_client()?;
        let mut txs_cbor: BTreeMap<String, String> = BTreeMap::new();

        // Blockfrost exposes CBOR per-hash only (`GET /txs/{hash}/cbor`);
        // missing txs are skipped so the result may be partial.
        for hash in tx_hashes {
            let resp = self.get(&client, &format!("/txs/{hash}/cbor"))?;
            if resp.status().as_u16() == 404 {
                continue;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                return Err(CardanoRpcError::Rpc(format!(
                    "Blockfrost txs/cbor returned {status}: {text}"
                )));
            }

            let body: TxCborResponse = resp
                .json()
                .map_err(|e| CardanoRpcError::Decode(format!("Blockfrost txs/cbor JSON: {e}")))?;
            txs_cbor.insert(hash.clone(), body.cbor);
        }

        Ok(txs_cbor)
    }

    fn get_balances(&self, address: &str) -> Result<Vec<TokenBalance>, CardanoRpcError> {
        let client = blocking_client()?;

        let resp = self.get(&client, &format!("/addresses/{address}"))?;
        // An address that has never appeared on-chain has no balances.
        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(CardanoRpcError::Rpc(format!(
                "Blockfrost addresses returned {status}: {body}"
            )));
        }

        let info: AddressInfo = resp
            .json()
            .map_err(|e| CardanoRpcError::Decode(format!("Blockfrost address JSON: {e}")))?;

        let mut out: Vec<TokenBalance> = Vec::new();
        for amount in info.amount {
            let quantity = amount.quantity.parse::<u64>().map_err(|e| {
                CardanoRpcError::Decode(format!("Blockfrost address quantity parse: {e}"))
            })?;
            if quantity == 0 {
                continue;
            }

            if amount.unit == "lovelace" {
                out.push(TokenBalance {
                    address: "lovelace".into(),
                    name: "Cardano".into(),
                    symbol: "ADA".into(),
                    chain: "cardano".into(),
                    decimals: ADA_DECIMALS,
                    balance: BalanceInfo {
                        amount: quantity as f64 / 10_f64.powi(ADA_DECIMALS as i32),
                        value: None,
                        price: None,
                    },
                });
                continue;
            }

            let (policy_id, asset_name) = split_asset_unit(&amount.unit);

            // Look up per-asset metadata (fingerprint / ticker / decimals).
            let asset_resp = self.get(&client, &format!("/assets/{}", amount.unit))?;
            let (fingerprint, ticker, decimals) = if asset_resp.status().is_success() {
                let asset: AssetInfo = asset_resp
                    .json()
                    .map_err(|e| CardanoRpcError::Decode(format!("Blockfrost asset JSON: {e}")))?;
                let ticker = asset.metadata.as_ref().and_then(|m| m.ticker.clone());
                let decimals = asset
                    .metadata
                    .as_ref()
                    .and_then(|m| m.decimals)
                    .unwrap_or(0);
                (asset.fingerprint, ticker, decimals)
            } else {
                (amount.unit.clone(), None, 0)
            };

            let symbol = ticker.unwrap_or_else(|| asset_name.chars().take(10).collect());

            out.push(TokenBalance {
                address: fingerprint,
                name: format!("{policy_id}.{asset_name}"),
                symbol,
                chain: "cardano".into(),
                decimals,
                balance: BalanceInfo {
                    amount: quantity as f64 / 10_f64.powi(decimals as i32),
                    value: None,
                    price: None,
                },
            });
        }

        out.sort_by(|a, b| {
            b.balance
                .amount
                .partial_cmp(&a.balance.amount)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[test]
    fn split_asset_unit_splits_policy_and_name() {
        let policy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 56 hex chars
        let name = "746f6b656e";
        let (p, n) = split_asset_unit(&format!("{policy}{name}"));
        assert_eq!(p, policy);
        assert_eq!(n, name);
    }

    #[test]
    fn blockfrost_broadcast_tx() {
        let tx_hash = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

        let mut server = Server::new();
        let mock = server
            .mock("POST", "/tx/submit")
            .match_header("project_id", "test-project")
            .with_status(200)
            .with_body(format!("\"{tx_hash}\""))
            .create();

        let provider = BlockfrostProvider::new(&server.url(), "test-project".into());
        let returned = provider.broadcast_tx(b"\x00\x01\x02").unwrap();

        mock.assert();
        assert_eq!(returned, tx_hash);
    }

    #[test]
    fn blockfrost_fetch_txs_cbor() {
        let tx_hash = "abababababababababababababababababababababababababababababababab";
        let cbor = "84a400d9010281825820deadbeef";

        let mut server = Server::new();
        let mock = server
            .mock("GET", format!("/txs/{tx_hash}/cbor").as_str())
            .match_header("project_id", "test-project")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "cbor": cbor,
                })
                .to_string(),
            )
            .create();

        let provider = BlockfrostProvider::new(&server.url(), "test-project".into());
        let result = provider.fetch_txs_cbor(&[tx_hash.to_string()]).unwrap();

        mock.assert();
        assert_eq!(
            result,
            BTreeMap::from([(tx_hash.to_string(), cbor.to_string())])
        );
    }

    #[test]
    fn blockfrost_get_balances() {
        let address = "addr_test1qbalance";
        let policy_id = "aabbccddeeff00112233445566778899aabbccddeeff001122334455"; // 56 hex chars
        let asset_name = "54455354";
        let unit = format!("{policy_id}{asset_name}");
        let fingerprint = "asset1ua6pz3yd5mdka946z8jw2fld3f8d0mmxt75gv9";

        let mut server = Server::new();
        let address_mock = server
            .mock("GET", format!("/addresses/{address}").as_str())
            .match_header("project_id", "test-project")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "address": address,
                    "amount": [
                        { "unit": "lovelace", "quantity": "10000000" },
                        { "unit": unit, "quantity": "2500000" }
                    ]
                })
                .to_string(),
            )
            .create();

        let asset_mock = server
            .mock("GET", format!("/assets/{unit}").as_str())
            .match_header("project_id", "test-project")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "asset": unit,
                    "fingerprint": fingerprint,
                    "metadata": { "ticker": "TEST", "decimals": 6 }
                })
                .to_string(),
            )
            .create();

        let provider = BlockfrostProvider::new(&server.url(), "test-project".into());
        let balances = provider.get_balances(address).unwrap();

        address_mock.assert();
        asset_mock.assert();

        assert_eq!(
            balances,
            vec![
                TokenBalance {
                    address: "lovelace".into(),
                    name: "Cardano".into(),
                    symbol: "ADA".into(),
                    chain: "cardano".into(),
                    decimals: ADA_DECIMALS,
                    balance: BalanceInfo {
                        amount: 10.0,
                        value: None,
                        price: None,
                    },
                },
                TokenBalance {
                    address: fingerprint.into(),
                    name: format!("{policy_id}.{asset_name}"),
                    symbol: "TEST".into(),
                    chain: "cardano".into(),
                    decimals: 6,
                    balance: BalanceInfo {
                        amount: 2.5,
                        value: None,
                        price: None,
                    },
                },
            ]
        );
    }

    #[test]
    fn blockfrost_get_balances_unknown_address_is_empty() {
        let address = "addr_test1qunknown";
        let mut server = Server::new();
        let mock = server
            .mock("GET", format!("/addresses/{address}").as_str())
            .with_status(404)
            .with_body(r#"{"status_code":404,"error":"Not Found","message":"The requested component has not been found."}"#)
            .create();

        let provider = BlockfrostProvider::new(&server.url(), "test-project".into());
        let balances = provider.get_balances(address).unwrap();

        mock.assert();
        assert_eq!(balances, vec![]);
    }
}
