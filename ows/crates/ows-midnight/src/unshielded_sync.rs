//! Sync the unshielded UTXO set for a Midnight address via the indexer's
//! `unshieldedTransactions` GraphQL-over-WebSocket subscription.
//!
//! Replay `created` / `spent` events until the indexer reports
//! `highestTransactionId` matching the last processed transaction id. When a disk
//! snapshot of a previous run exists, resume from its cursor and apply only the
//! newer events instead of replaying from genesis.

use futures_util::StreamExt as _;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use super::cache_io::{self, SyncCacheScope};
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

/// On-disk resume snapshot: the indexer cursor plus the unspent UTXO set as of that
/// cursor. A later run resumes the subscription from `last_seen_tx_id` and applies only
/// newer events. Stores source state (the UTXO set), never a derived balance — the
/// balance is recomputed by summing the set on read.
#[derive(Debug, Serialize, Deserialize)]
struct UnshieldedSnapshot {
    version: u32,
    /// CAIP-2 chain id the snapshot was synced against; guards against reusing a
    /// snapshot from a different network.
    chain_id: String,
    /// Fingerprint of `(indexer_url, chain_id)`; guards against reusing a snapshot
    /// from a different indexer.
    site_fp: String,
    /// Highest indexer transaction id already folded into `utxos`.
    last_seen_tx_id: i64,
    /// Unspent UTXO set as of `last_seen_tx_id`.
    utxos: Vec<UnshieldedUtxo>,
}

const UNSHIELDED_SNAPSHOT_VERSION: u32 = 1;

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

/// Unshielded UTXOs for `ows fund balance` — resumes from the address's disk snapshot
/// when one exists, otherwise replays the indexer from genesis.
pub async fn get_unshielded_utxos_for_display(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let mut tx_seen = false;
    get_unshielded_utxos_inner(indexer_url, address, scope, None, &mut tx_seen).await
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
    resume_last_seen: i64,
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
    // Anything at or below the resumed cursor is already folded into the seeded UTXO
    // set, so advance the cursor and skip re-applying its mutations. This keeps the
    // result correct whether the indexer honors `transactionId` or replays from genesis.
    if transaction.id <= resume_last_seen {
        *last_seen = (*last_seen).max(transaction.id);
        *n_txs = n_txs.saturating_add(1);
        return Ok(unshielded_sync_done(progress_received, highest, *last_seen));
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

/// Snapshot-aware unshielded sync: resume from the address's disk snapshot, and if its
/// cursor is ahead of the indexer (a reset), fall back to a full genesis re-sync. The
/// resulting set is persisted for the next run.
async fn get_unshielded_utxos_inner(
    indexer_url: &str,
    address: &str,
    scope: &SyncCacheScope,
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let snapshot_path = cache_io::snapshot_path("unshielded", indexer_url, address, scope);
    let site_fp = cache_io::sync_site_fingerprint(indexer_url, scope);

    // Resume only from a snapshot that belongs to this same indexer site and network;
    // an absent or mismatched snapshot syncs fresh from genesis.
    let resume = snapshot_path
        .as_ref()
        .and_then(|p| {
            cache_io::try_load_versioned::<UnshieldedSnapshot>(p, UNSHIELDED_SNAPSHOT_VERSION)
        })
        .filter(|snap| {
            cache_io::snapshot_site_matches(scope, &snap.chain_id, &site_fp, &snap.site_fp)
        });
    let (resume_last_seen, seed) = match resume {
        Some(snap) => (snap.last_seen_tx_id, snap.utxos),
        None => (0, Vec::new()),
    };

    let synced = match replay_unshielded(
        indexer_url,
        address,
        resume_last_seen,
        &seed,
        wait_for_tx_hash,
        tx_seen,
    )
    .await?
    {
        ReplayOutcome::Done(synced) => synced,
        ReplayOutcome::ResumeUnusable => {
            eprintln!(
                "[ows-midnight] unshielded snapshot cursor is ahead of the indexer; re-syncing from genesis"
            );
            match replay_unshielded(indexer_url, address, 0, &[], wait_for_tx_hash, tx_seen).await?
            {
                ReplayOutcome::Done(synced) => synced,
                ReplayOutcome::ResumeUnusable => {
                    return Err(std::io::Error::other(
                        "unshielded sync reported the indexer behind a genesis cursor",
                    ));
                }
            }
        }
    };

    let list: Vec<UnshieldedUtxo> = synced.utxos.into_values().collect();
    if let Some(path) = snapshot_path {
        cache_io::try_save(
            &path,
            &UnshieldedSnapshot {
                version: UNSHIELDED_SNAPSHOT_VERSION,
                chain_id: cache_io::snapshot_chain_id(scope),
                site_fp,
                last_seen_tx_id: synced.last_seen,
                utxos: list.clone(),
            },
        );
    }
    eprintln!(
        "[ows-midnight] unshielded sync: finished ({} UTXOs)",
        list.len()
    );
    Ok(list)
}

/// The synced unshielded state: the unspent UTXO set and the cursor it is current as of.
struct Synced {
    last_seen: i64,
    utxos: BTreeMap<(String, i64, String), UnshieldedUtxo>,
}

enum ReplayOutcome {
    Done(Synced),
    /// The indexer is behind the resume cursor (reset / rollback); the snapshot is stale.
    ResumeUnusable,
}

/// Rebuild the working UTXO map (keyed by `(intent_hash, output_index, token_type)`) from a
/// snapshot's flat UTXO list.
fn seed_utxo_map(utxos: &[UnshieldedUtxo]) -> BTreeMap<(String, i64, String), UnshieldedUtxo> {
    utxos
        .iter()
        .map(|u| {
            (
                (u.intent_hash.clone(), u.output_index, u.token_type.clone()),
                u.clone(),
            )
        })
        .collect()
}

/// Run one subscription replay seeded from `resume_last_seen` + `seed`. Resumes from the
/// cursor when `resume_last_seen > 0`, otherwise replays the whole history from genesis.
async fn replay_unshielded(
    indexer_url: &str,
    address: &str,
    resume_last_seen: i64,
    seed: &[UnshieldedUtxo],
    wait_for_tx_hash: Option<&str>,
    tx_seen: &mut bool,
) -> Result<ReplayOutcome, std::io::Error> {
    let mut utxos = seed_utxo_map(seed);
    let mut last_seen: i64 = resume_last_seen;

    if resume_last_seen > 0 {
        eprintln!(
            "[ows-midnight] unshielded sync: resuming from tx id {resume_last_seen} ({} UTXOs)",
            utxos.len()
        );
    } else {
        eprintln!("[ows-midnight] unshielded sync: syncing from genesis");
    }

    let stall_timeout = stall_timeout(SyncStream::Unshielded);
    let ws_idle = ws_idle_timeout(SyncStream::Unshielded);
    let sync_started = Instant::now();
    let mut last_event_at: Option<Instant> = None;

    let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;

    // Ask the indexer to start after the cursor when resuming; the skip branch in
    // `process_unshielded_event` keeps us correct even if it ignores the parameter.
    let sub_vars = if resume_last_seen > 0 {
        serde_json::json!({ "address": address, "transactionId": resume_last_seen })
    } else {
        serde_json::json!({ "address": address })
    };
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
                        // Indexer has fewer transactions than our resume cursor — it reset or
                        // rolled back past our snapshot, so the seeded set can't be trusted.
                        if resume_last_seen > 0 && highest_transaction_id < resume_last_seen {
                            return Ok(ReplayOutcome::ResumeUnusable);
                        }
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
                            resume_last_seen,
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

    Ok(ReplayOutcome::Done(Synced { last_seen, utxos }))
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

    #[test]
    fn unshielded_sync_done_requires_progress_and_catching_up_to_highest() {
        // Without a Progress event we never declare done, even if last_seen looks high.
        assert!(!unshielded_sync_done(false, Some(500), 500));
        // With Progress, done only once we've applied everything up to the current highest.
        assert!(!unshielded_sync_done(true, Some(500), 499));
        assert!(unshielded_sync_done(true, Some(500), 500));
        // Empty chain tip (highest == 0) is trivially done.
        assert!(unshielded_sync_done(true, Some(0), 0));
    }

    #[test]
    fn seed_utxo_map_keys_by_intent_output_and_token() {
        let utxo = |intent: &str, idx: i64, token: &str| UnshieldedUtxo {
            token_type: token.to_string(),
            value: 1,
            intent_hash: intent.to_string(),
            output_index: idx,
            owner: "owner".to_string(),
            ctime_unix_secs: None,
            registered_for_dust_generation: false,
        };
        let seed = vec![utxo("aa", 0, "night"), utxo("aa", 1, "night")];
        let map = seed_utxo_map(&seed);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&("aa".to_string(), 0, "night".to_string())));
        assert!(map.contains_key(&("aa".to_string(), 1, "night".to_string())));
    }
}
