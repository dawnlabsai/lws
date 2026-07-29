//! [Koios](https://koios.rest) RPC provider.

use super::{blocking_client, CardanoRpcError, CardanoRpcProvider, ADA_DECIMALS};
use crate::{BalanceInfo, TokenBalance};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

const TXS_CBOR_CHUNK_SIZE: usize = 10;
/// Keeping the `asset_info` page size small avoids 413 Payload Too Large errors.
const ASSET_LIST_CHUNK_SIZE: usize = 20;

#[derive(Debug, Serialize, Deserialize)]
struct AddressInfoRow {
    balance: String,
    utxo_set: Vec<AddressUtxo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddressUtxo {
    asset_list: Option<Vec<Asset>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Asset {
    policy_id: String,
    asset_name: Option<String>,
    fingerprint: String,
    quantity: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TxCborRow {
    tx_hash: String,
    cbor: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AssetInfoRow {
    policy_id: String,
    asset_name: Option<String>,
    token_registry_metadata: Option<TokenRegistryMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenRegistryMetadata {
    ticker: Option<String>,
    #[serde(default)]
    decimals: u32,
}

/// [Koios](https://koios.rest) RPC provider.
pub struct KoiosProvider {
    base_url: String,
}

impl KoiosProvider {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn fetch_assets_info(
        &self,
        client: &reqwest::blocking::Client,
        assets: &[(String, String)], // (policy_id, asset_name)
    ) -> Result<HashMap<(String, String), AssetInfoRow>, CardanoRpcError> {
        let mut out: HashMap<(String, String), AssetInfoRow> = HashMap::new();
        if assets.is_empty() {
            return Ok(out);
        }

        let url = format!("{}/asset_info", self.base_url);

        for assets_chunk in assets.chunks(ASSET_LIST_CHUNK_SIZE) {
            let body = serde_json::json!({
                "_asset_list": assets_chunk.iter().map(|(p, a)| [p.clone(), a.clone()]).collect::<Vec<_>>()
            });

            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .map_err(|e| CardanoRpcError::Http(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                return Err(CardanoRpcError::Rpc(format!(
                    "Koios asset_info returned {status}: {body}"
                )));
            }
            let rows: Vec<AssetInfoRow> = resp
                .json()
                .map_err(|e| CardanoRpcError::Decode(format!("Koios asset_info JSON: {e}")))?;
            for row in rows {
                let key = (
                    row.policy_id.clone(),
                    row.asset_name.clone().unwrap_or_default(),
                );
                out.insert(key, row);
            }
        }

        Ok(out)
    }
}

impl CardanoRpcProvider for KoiosProvider {
    fn broadcast_tx(&self, tx_cbor: &[u8]) -> Result<String, CardanoRpcError> {
        let url = format!("{}/submittx", self.base_url);
        let client = blocking_client()?;

        let resp = client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .body(tx_cbor.to_vec())
            .send()
            .map_err(|e| CardanoRpcError::Http(e.to_string()))?;

        let status = resp.status();
        let body = resp.text().unwrap_or_default();

        if status.as_u16() != 202 {
            return Err(CardanoRpcError::Rpc(format!(
                "Cardano broadcast failed ({status}): {body}"
            )));
        }

        let tx_hash = body.trim().trim_matches('"').to_string();
        if tx_hash.len() != 64 {
            return Err(CardanoRpcError::Rpc(format!(
                "Cardano broadcast: invalid transaction hash in response: {tx_hash}"
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

        let url = format!("{}/tx_cbor", self.base_url);
        let mut txs_cbor: BTreeMap<String, String> = BTreeMap::new();

        for chunk in tx_hashes.chunks(TXS_CBOR_CHUNK_SIZE) {
            let body = serde_json::json!({
                "_tx_hashes": chunk,
            });

            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .map_err(|e| CardanoRpcError::Http(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                return Err(CardanoRpcError::Rpc(format!(
                    "Koios tx_cbor returned {status}: {text}"
                )));
            }

            let fetched: Vec<TxCborRow> = resp
                .json()
                .map_err(|e| CardanoRpcError::Decode(format!("Koios tx_cbor JSON: {e}")))?;

            for row in fetched {
                txs_cbor.insert(row.tx_hash, row.cbor);
            }
        }

        Ok(txs_cbor)
    }

    fn get_balances(&self, address: &str) -> Result<Vec<TokenBalance>, CardanoRpcError> {
        let client = blocking_client()?;
        let body = serde_json::json!({ "_addresses": [address] });
        let url = format!("{}/address_info", self.base_url);

        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| CardanoRpcError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(CardanoRpcError::Rpc(format!(
                "Koios address_info returned {status}: {body}"
            )));
        }

        let rows: Vec<AddressInfoRow> = resp
            .json()
            .map_err(|e| CardanoRpcError::Decode(format!("Koios address_info JSON: {e}")))?;

        // we are fetching the balances for a single address, so we expect only one row
        let Some(info) = rows.into_iter().next() else {
            return Ok(Vec::new());
        };

        let total_lovelace = info
            .balance
            .parse::<u64>()
            .map_err(|e| CardanoRpcError::Decode(format!("invalid lovelace balance: {e}")))?;

        let mut assets_quantities: HashMap<(String, String, String), u64> = HashMap::new();
        for utxo in info.utxo_set {
            for asset in utxo.asset_list.unwrap_or_default() {
                let qty = asset
                    .quantity
                    .parse::<u64>()
                    .map_err(|e| CardanoRpcError::Decode(format!("invalid asset quantity: {e}")))?;
                if qty == 0 {
                    continue;
                }

                let key = (
                    asset.policy_id.clone(),
                    asset.asset_name.clone().unwrap_or_default(),
                    asset.fingerprint.clone(),
                );
                *assets_quantities.entry(key).or_insert(0) += qty;
            }
        }

        let assets = assets_quantities
            .keys()
            .cloned()
            .map(|(p, a, _f)| (p, a))
            .collect::<Vec<(String, String)>>();
        let assets_info = self.fetch_assets_info(&client, &assets)?;

        let mut out: Vec<TokenBalance> = Vec::new();

        if total_lovelace > 0 {
            out.push(TokenBalance {
                address: "lovelace".into(),
                name: "Cardano".into(),
                symbol: "ADA".into(),
                chain: "cardano".into(),
                decimals: ADA_DECIMALS,
                balance: BalanceInfo {
                    amount: total_lovelace as f64 / 10_f64.powi(ADA_DECIMALS as i32),
                    value: None,
                    price: None,
                },
            });
        }

        out.extend(assets_quantities.iter().map(
            |((policy_id, asset_name, fingerprint), quantity)| {
                let asset_info = assets_info.get(&(policy_id.clone(), asset_name.clone()));

                let ticker = asset_info
                    .and_then(|i| i.token_registry_metadata.as_ref())
                    .and_then(|m| m.ticker.clone())
                    .unwrap_or_else(|| asset_name.chars().take(10).collect());

                let decimals = asset_info
                    .and_then(|i| i.token_registry_metadata.as_ref().map(|m| m.decimals))
                    .unwrap_or(0);

                TokenBalance {
                    address: fingerprint.into(),
                    name: format!("{policy_id}.{asset_name}"),
                    symbol: ticker.clone(),
                    chain: "cardano".into(),
                    decimals,
                    balance: BalanceInfo {
                        amount: *quantity as f64 / 10_f64.powi(decimals as i32),
                        value: None,
                        price: None,
                    },
                }
            },
        ));

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
    fn koios_get_balances() {
        let wallet = "addr1q9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmsl80734zn65gc55ecvafkhuxawlnn6wevkmg8dm5kt9vxyys322t44";
        let policy_id = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let asset_name = "54455354";
        let fingerprint = "asset1ua6pz3yd5mdka946z8jw2fld3f8d0mmxt75gv9";

        let mut server = Server::new();

        let address_mock = server
            .mock("POST", "/address_info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([{
                    "balance": "10000000",
                    "utxo_set": [{
                        "asset_list": [{
                            "policy_id": policy_id,
                            "asset_name": asset_name,
                            "fingerprint": fingerprint,
                            "quantity": "2500000",
                        }],
                    }],
                }])
                .to_string(),
            )
            .create();

        let asset_mock = server
            .mock("POST", "/asset_info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([{
                    "policy_id": policy_id,
                    "asset_name": asset_name,
                    "token_registry_metadata": { "ticker": "TEST", "decimals": 6 },
                }])
                .to_string(),
            )
            .create();

        let provider = KoiosProvider::new(&server.url());
        let balances = provider.get_balances(wallet).unwrap();

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
    fn koios_fetch_txs_cbor() {
        let tx_hash = "abababababababababababababababababababababababababababababababab";
        let cbor = "84a400d9010281825820deadbeef";

        let mut server = Server::new();
        let mock = server
            .mock("POST", "/tx_cbor")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([{
                    "tx_hash": tx_hash,
                    "cbor": cbor,
                }])
                .to_string(),
            )
            .create();

        let provider = KoiosProvider::new(&server.url());
        let result = provider.fetch_txs_cbor(&[tx_hash.to_string()]).unwrap();

        mock.assert();
        assert_eq!(
            result,
            BTreeMap::from([(tx_hash.to_string(), cbor.to_string())])
        );
    }

    #[test]
    fn koios_fetch_txs_cbor_empty_input_skips_request() {
        // No server interaction expected for empty inputs.
        let provider = KoiosProvider::new("http://127.0.0.1:1/api/v1");
        assert_eq!(provider.fetch_txs_cbor(&[]).unwrap(), BTreeMap::new());
    }

    #[test]
    fn koios_broadcast_tx() {
        let tx_hash = "abababababababababababababababababababababababababababababababab";

        let mut server = Server::new();
        let mock = server
            .mock("POST", "/submittx")
            .with_status(202)
            .with_body(format!("\"{tx_hash}\""))
            .create();

        let provider = KoiosProvider::new(&server.url());
        let returned = provider.broadcast_tx(b"\x00\x01\x02").unwrap();

        mock.assert();
        assert_eq!(returned, tx_hash);
    }

    #[test]
    fn koios_broadcast_tx_error_status() {
        let mut server = Server::new();
        let mock = server
            .mock("POST", "/submittx")
            .with_status(400)
            .with_body("bad tx")
            .create();

        let provider = KoiosProvider::new(&server.url());
        let err = provider.broadcast_tx(b"\x00").unwrap_err();

        mock.assert();
        assert!(matches!(err, CardanoRpcError::Rpc(_)));
    }
}
