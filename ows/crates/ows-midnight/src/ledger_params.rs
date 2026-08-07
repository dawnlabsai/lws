//! Fetch on-chain `LedgerParameters` via the indexer's `block` GraphQL query.
//!
//! Returned by the indexer as a hex-encoded SCALE blob; we decode it via the
//! ledger crate's tagged-deserialization so callers get a fully typed
//! [`midnight_ledger::structure::LedgerParameters`].

use midnight_serialize::tagged_deserialize;
use serde::Deserialize;
use std::sync::OnceLock;

use super::midnight_env;

#[derive(Debug, Deserialize)]
struct IndexerBlockData {
    #[allow(dead_code)]
    height: i64,
    #[allow(dead_code)]
    hash: String,
    #[serde(rename = "ledgerParameters")]
    ledger_parameters: String,
    timestamp: serde_json::Value,
}

pub(crate) fn parse_indexer_timestamp_secs(v: &serde_json::Value) -> Option<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    // Indexer docs say seconds, but some deployments return milliseconds.
    // Heuristic: anything >= year 33658 in seconds is definitely ms.
    if n >= 1_000_000_000_000 {
        Some(n / 1000)
    } else {
        Some(n)
    }
}

#[derive(Debug, Deserialize)]
struct IndexerBlockResp {
    block: Option<IndexerBlockData>,
}

#[derive(Debug, Deserialize)]
struct IndexerGraphqlResp<T> {
    data: Option<T>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightData {
    height: i64,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightResp {
    block: Option<IndexerBlockHeightData>,
}

static INDEXER_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

/// Shared HTTP client for Midnight indexer GraphQL (bounded request timeout).
pub fn indexer_http_client() -> &'static reqwest::Client {
    INDEXER_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(midnight_env::indexer_http_timeout())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Latest indexer block: on-chain ledger parameters and chain timestamp (unix seconds).
pub async fn fetch_indexer_tip(
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    fetch_indexer_tip_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_tip_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    let q = r#"query BlockHash($offset: BlockOffset) { block(offset: $offset) { height hash ledgerParameters timestamp } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {e}")))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer read body failed: {e}")))?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    let block = parsed
        .data
        .and_then(|d| d.block)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))?;
    let timestamp_secs = parse_indexer_timestamp_secs(&block.timestamp)
        .ok_or_else(|| std::io::Error::other("indexer did not return block.timestamp"))?;
    let lp_hex = block.ledger_parameters;

    let raw = hex::decode(lp_hex.strip_prefix("0x").unwrap_or(lp_hex.as_str()))
        .map_err(|e| std::io::Error::other(format!("invalid ledgerParameters hex: {e}")))?;
    let mut r: &[u8] = &raw;
    let ledger_parameters = tagged_deserialize::<midnight_ledger::structure::LedgerParameters>(
        &mut r,
    )
    .map_err(|e| std::io::Error::other(format!("failed to decode ledger parameters: {e}")))?;
    Ok((ledger_parameters, timestamp_secs))
}

/// Current indexer chain-tip block height (HTTP `block { height }`).
pub async fn fetch_indexer_block_height(indexer_url: &str) -> Result<i64, std::io::Error> {
    fetch_indexer_block_height_with_client(indexer_http_client(), indexer_url).await
}

pub async fn fetch_indexer_block_height_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<i64, std::io::Error> {
    let q = r#"query BlockHeight($offset: BlockOffset) { block(offset: $offset) { height } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {e}")))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer read body failed: {e}")))?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockHeightResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.height)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))
}

pub async fn fetch_indexer_ledger_parameters(
    indexer_url: &str,
) -> Result<midnight_ledger::structure::LedgerParameters, std::io::Error> {
    Ok(fetch_indexer_tip(indexer_url).await?.0)
}
