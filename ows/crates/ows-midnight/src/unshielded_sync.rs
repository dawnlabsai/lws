//! Sync the unshielded UTXO set for a Midnight address via the indexer's
//! `unshieldedTransactions` GraphQL-over-WebSocket subscription.
//!
//! Replay `created` / `spent` events until the indexer reports
//! `highestTransactionId` matching the last processed transaction id.

use futures_util::StreamExt as _;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use super::indexer_ws;
use super::ledger_params::parse_indexer_timestamp_secs;
use super::midnight_env::{stall_timeout, ws_idle_timeout, SyncStream};

/// One spendable unshielded UTXO as reported by the indexer (after replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldedUtxo {
    pub token_type: String,
    pub value: u128,
    pub intent_hash: String,
    pub output_index: i64,
    pub owner: String,
    /// Block timestamp (seconds since Unix epoch) for the creating transaction, when the indexer
    /// provides `transaction.block.timestamp`. Used to bound DUST fee allowance from Night inputs.
    #[serde(default)]
    pub ctime_unix_secs: Option<u64>,
    /// Whether this UTXO is already registered for Dust generation (indexer field).
    /// Matches the ledger's `night_indices` membership used by `generationless_fee_availability`.
    #[serde(default)]
    pub registered_for_dust_generation: bool,
}

/// GraphQL subscription (indexer v4 supports optional `transactionId` resume).
const UNSHIELDED_SUBSCRIPTION: &str = r#"
subscription UnshieldedTransactions($address: UnshieldedAddress!, $transactionId: Int) {
  unshieldedTransactions(address: $address, transactionId: $transactionId) {
    __typename
    ... on UnshieldedTransaction {
      transaction { id hash block { timestamp } }
      createdUtxos { tokenType value intentHash outputIndex owner ctime registeredForDustGeneration }
      spentUtxos { tokenType value intentHash outputIndex owner ctime registeredForDustGeneration }
    }
    ... on UnshieldedTransactionsProgress {
      highestTransactionId
    }
  }
}
"#;

/// Unshielded UTXOs for `ows fund balance` — replays the indexer from genesis.
pub async fn get_unshielded_utxos_for_display(
    indexer_url: &str,
    address: &str,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let mut tx_seen = false;
    get_unshielded_utxos_inner(indexer_url, address, None, &mut tx_seen).await
}

fn normalize_ledger_tx_hash(h: &str) -> String {
    let bare = h.strip_prefix("0x").unwrap_or(h).to_ascii_lowercase();
    format!("0x{bare}")
}

fn tx_hashes_match(indexer_hash: &str, ledger_hash: &str) -> bool {
    normalize_ledger_tx_hash(indexer_hash) == normalize_ledger_tx_hash(ledger_hash)
}

fn unshielded_sync_done(progress_received: bool, highest: Option<i64>, last_seen: i64) -> bool {
    if !progress_received {
        return false;
    }
    let Some(h) = highest else {
        return false;
    };
    // `midnight-wallet-cli` / balance-subscription.ts: done when highest is 0 (empty chain tip)
    // or we've applied all transactions up to the reported highest id.
    h == 0 || last_seen >= h
}

#[allow(clippy::too_many_arguments)]
fn process_unshielded_event(
    transaction: TransactionRef,
    created_utxos: Vec<UnshieldedUtxoWire>,
    spent_utxos: Vec<UnshieldedUtxoWire>,
    last_seen: &mut i64,
    n_txs: &mut u64,
    utxos: &mut BTreeMap<(String, i64, String), UnshieldedUtxo>,
    progress_received: bool,
    highest: Option<i64>,
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<bool, std::io::Error> {
    if let Some(target) = wait_for_tx_hash {
        if tx_hashes_match(&transaction.hash, target) {
            *tx_seen = true;
        }
    }
    *last_seen = (*last_seen).max(transaction.id);
    *n_txs = n_txs.saturating_add(1);
    let block_ts = transaction
        .block
        .as_ref()
        .and_then(|b| b.timestamp.as_ref())
        .and_then(parse_indexer_timestamp_secs);
    for u in created_utxos {
        let key = (u.intent_hash.clone(), u.output_index, u.token_type.clone());
        let val: u128 = u
            .value
            .parse()
            .map_err(|_| std::io::Error::other("invalid u128 value"))?;
        let utxo_ctime = u
            .ctime
            .as_ref()
            .and_then(parse_indexer_timestamp_secs)
            .or(block_ts);
        utxos.insert(
            key,
            UnshieldedUtxo {
                token_type: u.token_type,
                value: val,
                intent_hash: u.intent_hash,
                output_index: u.output_index,
                owner: u.owner,
                ctime_unix_secs: utxo_ctime,
                registered_for_dust_generation: u.registered_for_dust_generation.unwrap_or(false),
            },
        );
    }
    for u in spent_utxos {
        let key = (u.intent_hash, u.output_index, u.token_type);
        utxos.remove(&key);
    }
    if *n_txs == 1 || n_txs.is_multiple_of(1000) {
        eprintln!(
            "[ows-midnight] unshielded sync progress: last_seen={last_seen} highest={highest:?} txs_seen={n_txs}"
        );
    }
    Ok(unshielded_sync_done(progress_received, highest, *last_seen))
}

async fn get_unshielded_utxos_inner(
    indexer_url: &str,
    address: &str,
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let mut utxos: BTreeMap<(String, i64, String), UnshieldedUtxo> = BTreeMap::new();
    let mut last_seen: i64 = 0;

    eprintln!("[ows-midnight] unshielded sync: syncing from genesis");

    let stall_timeout = stall_timeout(SyncStream::Unshielded);
    let ws_idle = ws_idle_timeout(SyncStream::Unshielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;

    let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;

    let sub_vars = serde_json::json!({ "address": address });
    indexer_ws::subscribe(&mut ws, "1", UNSHIELDED_SUBSCRIPTION, sub_vars).await?;

    let mut highest: Option<i64> = None;
    let mut progress_received = false;
    let mut n_txs: u64 = 0;
    let mut sync_done = false;

    while !sync_done {
        let stall_elapsed = last_event_at.unwrap_or(sync_started).elapsed();
        if stall_elapsed > stall_timeout {
            return Err(std::io::Error::other(format!(
                    "no unshielded indexer events for {}s (last_seen_tx_id={last_seen} highest={highest:?}); \
indexer may be stalled",
                    stall_timeout.as_secs()
                ),
            ));
        }

        let msg = match tokio::time::timeout(ws_idle, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                return Err(std::io::Error::other(e.to_string()));
            }
            Ok(None) => break,
            Err(_) => {
                eprintln!(
                    "[ows-midnight] unshielded sync: no indexer message for {}s (last_seen={last_seen} highest={highest:?})",
                    ws_idle.as_secs()
                );
                return Err(std::io::Error::other(format!(
                    "Midnight indexer unshielded sync: no WebSocket data for {}s \
(last_seen_tx_id={last_seen} highest={highest:?})",
                    ws_idle.as_secs()
                )));
            }
        };
        let tokio_tungstenite::tungstenite::Message::Text(t) = msg else {
            continue;
        };
        last_event_at = Some(Instant::now());

        let frame: indexer_ws::WsFrame<UnshieldedWsData> =
            serde_json::from_str(&t).map_err(|e| std::io::Error::other(e.to_string()))?;
        match frame.r#type.as_str() {
            "next" => {
                let Some(payload) = frame.payload else {
                    continue;
                };
                if let Some(errs) = payload.errors.as_ref() {
                    let msg = errs
                        .first()
                        .and_then(|e| e.get("message").and_then(|m| m.as_str()))
                        .unwrap_or("unknown GraphQL error");
                    return Err(std::io::Error::other(format!(
                        "indexer GraphQL error: {msg}"
                    )));
                }
                let Some(evt) = payload.data.and_then(|d| d.unshielded_transactions) else {
                    continue;
                };
                match evt {
                    UnshieldedEvent::Progress {
                        highest_transaction_id,
                    } => {
                        highest = Some(highest_transaction_id);
                        progress_received = true;
                        eprintln!(
                            "[ows-midnight] unshielded sync progress: last_seen={last_seen} highest={highest_transaction_id}"
                        );
                        if unshielded_sync_done(progress_received, highest, last_seen) {
                            sync_done = true;
                            eprintln!(
                                "[ows-midnight] unshielded sync: caught up (last_seen={last_seen} highest={highest_transaction_id})"
                            );
                        }
                    }
                    UnshieldedEvent::Tx {
                        transaction,
                        created_utxos,
                        spent_utxos,
                    } => {
                        sync_done = process_unshielded_event(
                            transaction,
                            created_utxos,
                            spent_utxos,
                            &mut last_seen,
                            &mut n_txs,
                            &mut utxos,
                            progress_received,
                            highest,
                            wait_for_tx_hash,
                            tx_seen,
                        )?;
                    }
                }
            }
            "error" => {
                return Err(std::io::Error::other(format!(
                    "indexer subscription error: {t}"
                )));
            }
            "complete" => break,
            _ => {}
        }
    }

    // Drop the socket instead of awaiting `complete` — some indexers never ack it and block for minutes.
    drop(ws);

    if !unshielded_sync_done(progress_received, highest, last_seen) {
        return Err(std::io::Error::other(
            "Midnight indexer closed the unshielded subscription before sync completed; \
try again or check indexer health."
                .to_string(),
        ));
    }

    let list: Vec<UnshieldedUtxo> = utxos.into_values().collect();
    eprintln!(
        "[ows-midnight] unshielded sync: finished ({} UTXOs)",
        list.len()
    );
    Ok(list)
}

#[derive(Debug, Default, Deserialize)]
struct UnshieldedWsData {
    #[serde(rename = "unshieldedTransactions")]
    #[serde(default)]
    unshielded_transactions: Option<UnshieldedEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "__typename")]
enum UnshieldedEvent {
    #[serde(rename = "UnshieldedTransactionsProgress")]
    Progress {
        #[serde(rename = "highestTransactionId")]
        highest_transaction_id: i64,
    },
    #[serde(rename = "UnshieldedTransaction")]
    Tx {
        transaction: TransactionRef,
        #[serde(rename = "createdUtxos")]
        created_utxos: Vec<UnshieldedUtxoWire>,
        #[serde(rename = "spentUtxos")]
        spent_utxos: Vec<UnshieldedUtxoWire>,
    },
}

#[derive(Debug, Deserialize)]
struct TransactionRef {
    id: i64,
    hash: String,
    #[serde(default)]
    block: Option<TransactionBlockRef>,
}

#[derive(Debug, Deserialize)]
struct TransactionBlockRef {
    /// Indexer may return seconds as JSON number or string.
    timestamp: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UnshieldedUtxoWire {
    #[serde(rename = "tokenType")]
    token_type: String,
    value: String,
    #[serde(rename = "intentHash")]
    intent_hash: String,
    #[serde(rename = "outputIndex")]
    output_index: i64,
    owner: String,
    #[serde(default)]
    ctime: Option<serde_json::Value>,
    #[serde(rename = "registeredForDustGeneration")]
    #[serde(default)]
    registered_for_dust_generation: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_hashes_match_normalizes_0x_and_case() {
        assert!(tx_hashes_match("0xAbCd", "abcd"));
        assert!(tx_hashes_match("ABCD", "0xabcd"));
        assert!(!tx_hashes_match("0xaaaa", "0xbbbb"));
    }
}
