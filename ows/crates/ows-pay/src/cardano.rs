use crate::error::{PayError, PayErrorCode};
use crate::types::{BalanceInfo, TokenBalance};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct KoiosAddressInfoRow {
    balance: String,
    utxo_set: Vec<KoiosAddressUtxo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KoiosAddressUtxo {
    asset_list: Option<Vec<KoiosAsset>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KoiosAsset {
    policy_id: String,
    asset_name: Option<String>,
    fingerprint: String,
    quantity: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KoiosAssetInfoRow {
    policy_id: String,
    asset_name: Option<String>,
    token_registry_metadata: Option<KoiosTokenRegistryMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KoiosTokenRegistryMetadata {
    ticker: Option<String>,
    #[serde(default)]
    decimals: u32,
}

const ADA_DECIMALS: u32 = 6;

// keeping page size small to avoid 413 Payload Too Large errors
const KOIOS_ASSET_LIST_CHUNK_SIZE: usize = 20;

pub(crate) async fn get_cardano_balances(
    wallet_address: &str,
    koios_base_url: &str,
) -> Result<Vec<TokenBalance>, PayError> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({ "_addresses": [wallet_address] });
    let url = format!("{koios_base_url}/address_info");

    let resp = client.post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("Koios address_info returned {status}: {body}"),
        ));
    }

    let rows: Vec<KoiosAddressInfoRow> = resp.json().await?;

    // we are fetching the balances for a single address, so we expect only one row
    let Some(info) = rows.into_iter().next() else {
        return Ok(Vec::new());
    };

    let total_lovelace = info.balance.parse::<u64>().map_err(|e| {
        PayError::new(
            PayErrorCode::InvalidData,
            format!("invalid lovelace balance: {e}"),
        )
    })?;

    let mut assets_quantities: HashMap<(String, String, String), u64> = HashMap::new();
    for utxo in info.utxo_set {
        for asset in utxo.asset_list.unwrap_or_default() {
            let qty = asset.quantity.parse::<u64>().map_err(|e| {
                PayError::new(
                    PayErrorCode::InvalidData,
                    format!("invalid asset quantity: {e}"),
                )
            })?;
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
    let assets_info = fetch_assets_info(&client, koios_base_url, &assets).await?;

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

    out.extend(
        assets_quantities
            .iter()
            .map(|((policy_id, asset_name, fingerprint), quantity)| {
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
            }),
    );

    out.sort_by(|a, b| {
        b.balance
            .amount
            .partial_cmp(&a.balance.amount)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(out)
}

async fn fetch_assets_info(
    client: &reqwest::Client,
    koios_base: &str,
    assets: &[(String, String)], // (policy_id, asset_name)
) -> Result<HashMap<(String, String), KoiosAssetInfoRow>, PayError> {
    let mut out: HashMap<(String, String), KoiosAssetInfoRow> = HashMap::new();
    if assets.is_empty() {
        return Ok(out);
    }

    let url = format!("{koios_base}/asset_info");

    for assets_chunk in assets.chunks(KOIOS_ASSET_LIST_CHUNK_SIZE) {
        let body = serde_json::json!({
            "_asset_list": assets_chunk.iter().map(|(p, a)| [p.clone(), a.clone()]).collect::<Vec<_>>()
        });

        let resp = client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(PayError::new(
                PayErrorCode::HttpStatus,
                format!("Koios asset_info returned {status}: {body}"),
            ));
        }
        let rows: Vec<KoiosAssetInfoRow> = resp.json().await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn mock_address_info_response(
        server: &mut Server,
        rows: &[KoiosAddressInfoRow],
    ) -> mockito::Mock {
        server
            .mock("POST", "/address_info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(rows).unwrap())
            .create()
    }

    fn mock_asset_info_response(server: &mut Server, rows: &[KoiosAssetInfoRow]) -> mockito::Mock {
        server
            .mock("POST", "/asset_info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(rows).unwrap())
            .create()
    }

    #[test]
    fn get_cardano_balances_from_koios() {
        let wallet = "addr1q9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmsl80734zn65gc55ecvafkhuxawlnn6wevkmg8dm5kt9vxyys322t44";
        let policy_id = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let asset_name = "54455354";
        let fingerprint = "asset1ua6pz3yd5mdka946z8jw2fld3f8d0mmxt75gv9";

        let mut server = Server::new();

        let address_mock = mock_address_info_response(
            &mut server,
            &[KoiosAddressInfoRow {
                balance: "10000000".into(),
                utxo_set: vec![KoiosAddressUtxo {
                    asset_list: Some(vec![KoiosAsset {
                        policy_id: policy_id.into(),
                        asset_name: Some(asset_name.into()),
                        fingerprint: fingerprint.into(),
                        quantity: "2500000".into(),
                    }]),
                }],
            }],
        );

        let asset_mock = mock_asset_info_response(
            &mut server,
            &[KoiosAssetInfoRow {
                policy_id: policy_id.into(),
                asset_name: Some(asset_name.into()),
                token_registry_metadata: Some(KoiosTokenRegistryMetadata {
                    ticker: Some("TEST".into()),
                    decimals: 6,
                }),
            }],
        );

        let koios_url = server.url();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let balances = rt
            .block_on(get_cardano_balances(wallet, &koios_url))
            .unwrap();

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
}
