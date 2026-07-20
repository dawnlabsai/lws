//! Sync local Dust state by replaying `dustLedgerEvents` from the indexer.
//!
//! Mirrors the Midnight ledger `DustLocalState::replay_events` logic: decode each raw `Event`
//! payload and apply it in order. Exposes [`get_dust_balance_for_display`] (apply the ledger
//! decay rules at a given chain time) and [`format_dust_specks`] (render the
//! `SPECKS_PER_DUST`-denominated value).
//!
//! This replays the dust ledger from genesis on every call; a disk resume snapshot lands later.

use futures_util::{SinkExt as _, StreamExt as _};
use midnight_ledger::dust::{DustLocalState, DustPublicKey, INITIAL_DUST_PARAMETERS};
use midnight_ledger::events::Event;
use midnight_serialize::tagged_deserialize;
use midnight_serialize::Serializable;
use midnight_storage::db::InMemoryDB;
use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;
use std::time::{Duration, Instant};

use crate::cache_io::{self, SyncCacheScope};
mod sync_cache;
use crate::indexer_ws;
use crate::midnight_env::{stall_timeout, ws_idle_timeout, SyncStream};

/// Max reconnect attempts before a dust replay gives up.
const DUST_SYNC_MAX_ATTEMPTS: u32 = 4;

/// Read budget for the dust-liveness probe. A live indexer serves the first `dustLedgerEvents`
/// frame right away, so the probe needs far less than the full-sync idle window.
const DUST_PROBE_TIMEOUT_SECS: u64 = 15;

/// Persist a progress snapshot every N applied events during a long replay, so a later run
/// resumes near the tip even if this one is interrupted.
const DUST_SNAPSHOT_INTERVAL: u64 = 1000;

const DUST_LEDGER_SUB: &str = r#"
subscription DustLedgerEvents($id: Int) {
  dustLedgerEvents(id: $id) {
    __typename
    id
    raw
    maxId
    protocolVersion
    ... on DustInitialUtxo { output { nonce } }
  }
}
"#;

#[derive(Debug, Default, Deserialize)]
struct DustWsData {
    #[serde(rename = "dustLedgerEvents")]
    #[serde(default)]
    dust_ledger_events: Option<DustLedgerEvent>,
}

#[derive(Debug, Deserialize)]
struct DustLedgerEvent {
    id: i64,
    raw: String,
    #[serde(rename = "maxId")]
    max_id: i64,
}

fn dust_merge_max_id(current: Option<i64>, event_max_id: i64) -> Option<i64> {
    if event_max_id <= 0 {
        return current;
    }
    Some(current.map_or(event_max_id, |m| m.max(event_max_id)))
}

fn dust_at_chain_tip(last_seen_id: i64, max_id: Option<i64>) -> bool {
    max_id.is_some_and(|m| m > 0 && last_seen_id >= m)
}

fn dust_stall_error(
    stall_timeout: Duration,
    last_seen_id: i64,
    max_id: Option<i64>,
) -> std::io::Error {
    std::io::Error::other(format!(
        "no dust ledger events applied for {}s (last_seen_id={last_seen_id} max_id={max_id:?}); \
indexer may be stalled",
        stall_timeout.as_secs()
    ))
}

/// Persist the dust ledger state + cursor for the next run (best-effort; ignored when caching
/// is disabled or serialization fails).
#[allow(clippy::too_many_arguments)]
fn save_dust_snapshot(
    path: Option<&std::path::Path>,
    scope: &SyncCacheScope,
    fp: &str,
    dust_pk_hex: &str,
    state: &DustLocalState<InMemoryDB>,
    last_seen_id: i64,
    max_id: Option<i64>,
    block_height: i64,
) {
    let Some(path) = path else {
        return;
    };
    let Ok(state_hex) = sync_cache::encode_state(state) else {
        return;
    };
    cache_io::try_save(
        path,
        &sync_cache::DustSyncSnapshot {
            version: sync_cache::SNAPSHOT_VERSION,
            indexer_fingerprint: fp.to_string(),
            chain_id: cache_io::snapshot_chain_id(scope),
            dust_public_key_hex: dust_pk_hex.to_string(),
            last_seen_event_id: last_seen_id,
            max_id_when_saved: max_id.map(|m| m.max(last_seen_id)).unwrap_or(last_seen_id),
            block_height_when_saved: block_height,
            state_hex,
        },
    );
}

/// Sync the dust ledger and return the local state: resume from this dust key's disk snapshot
/// when present, otherwise replay from genesis. The synced state is persisted for the next run.
async fn sync_dust_local_state(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<DustLocalState<InMemoryDB>, std::io::Error> {
    // Validate the provider yields a serializable dust public key before we open a socket.
    let dust_pk = crypto_provider
        .dust_public_key()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let dust_pk_hex = dust_public_key_hex(&dust_pk)?;
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let cache_path = sync_cache::snapshot_path(indexer_url, &dust_pk_hex, scope);

    let mut state = DustLocalState::new(INITIAL_DUST_PARAMETERS);
    let mut last_seen_id: i64 = -1;
    let mut max_id: Option<i64> = None;
    let mut saved_block_height: i64 = 0;

    // Resume only from a snapshot for this same indexer site, network, and dust key.
    let resumed = cache_path
        .as_ref()
        .and_then(|p| sync_cache::try_load_snapshot(p))
        .filter(|snap| {
            cache_io::snapshot_site_matches(scope, &snap.chain_id, &fp, &snap.indexer_fingerprint)
                && snap.dust_public_key_hex == dust_pk_hex
        })
        .and_then(|snap| {
            let st = sync_cache::decode_state(&snap.state_hex).ok()?;
            Some((
                st,
                snap.last_seen_event_id,
                snap.max_id_when_saved,
                snap.block_height_when_saved,
            ))
        });
    if let Some((st, last, saved_max, saved_height)) = resumed {
        state = st;
        last_seen_id = last;
        max_id = Some(saved_max);
        saved_block_height = saved_height;
        eprintln!(
            "[ows-midnight] dust sync: resuming from event id {last_seen_id} (saved tip {saved_max})"
        );
    } else {
        eprintln!("[ows-midnight] dust sync: replaying from genesis");
    }

    // Fast path: when the indexer's HTTP tip height matches the snapshot's, the snapshot
    // already reflects the live tip — skip the WebSocket catch-up entirely.
    let snapshot_complete = dust_at_chain_tip(last_seen_id, max_id);
    if crate::tip_verify::snapshot_fresh_by_http_tip(
        current_block_height,
        saved_block_height,
        snapshot_complete,
    ) {
        eprintln!(
            "[ows-midnight] dust sync: indexer block height unchanged ({saved_block_height}); using on-disk snapshot"
        );
        return Ok(state);
    }

    let snapshot_block_height = current_block_height.unwrap_or(0);
    let ws_idle = ws_idle_timeout(SyncStream::Dust);
    let stall_timeout = stall_timeout(SyncStream::Dust);
    let sync_started = Instant::now();
    let mut last_applied_at: Option<Instant> = None;
    let mut n_events: u64 = 0;

    for attempt in 0..DUST_SYNC_MAX_ATTEMPTS {
        let mut ws = indexer_ws::connect_and_init(indexer_url, ws_idle, None).await?;
        let resume_id = last_seen_id.saturating_add(1);
        indexer_ws::subscribe(
            &mut ws,
            "1",
            DUST_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        // Set on every loop exit: true if the socket dropped (reconnect), false if caught up.
        let dropped;
        loop {
            if last_applied_at.unwrap_or(sync_started).elapsed() > stall_timeout {
                save_dust_snapshot(
                    cache_path.as_deref(),
                    scope,
                    &fp,
                    &dust_pk_hex,
                    &state,
                    last_seen_id,
                    max_id,
                    snapshot_block_height,
                );
                if dust_at_chain_tip(last_seen_id, max_id) {
                    return Ok(state);
                }
                return Err(dust_stall_error(stall_timeout, last_seen_id, max_id));
            }

            use tokio_tungstenite::tungstenite::Message;
            let msg = match tokio::time::timeout(ws_idle, ws.next()).await {
                Ok(Some(Ok(m))) => m,
                Ok(Some(Err(_))) | Ok(None) => {
                    dropped = true;
                    break;
                }
                Err(_) => {
                    // No frames within the idle window: done if already at tip, else reconnect.
                    if dust_at_chain_tip(last_seen_id, max_id) {
                        dropped = false;
                    } else {
                        eprintln!(
                            "[ows-midnight] dust sync: no indexer message for {}s, reconnecting…",
                            ws_idle.as_secs()
                        );
                        dropped = true;
                    }
                    break;
                }
            };
            let t = match msg {
                Message::Text(t) => t,
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                    continue;
                }
                Message::Close(_) => {
                    dropped = true;
                    break;
                }
                Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => continue,
            };

            let frame: indexer_ws::WsFrame<DustWsData> =
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
                    let Some(evt) = payload.data.and_then(|d| d.dust_ledger_events) else {
                        continue;
                    };
                    max_id = dust_merge_max_id(max_id, evt.max_id);
                    last_seen_id = last_seen_id.max(evt.id);
                    let raw_hex = evt.raw.strip_prefix("0x").unwrap_or(evt.raw.as_str());
                    let bytes = hex::decode(raw_hex).map_err(|e| {
                        std::io::Error::other(format!("invalid event raw hex: {e}"))
                    })?;
                    let mut reader: &[u8] = &bytes;
                    let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader)
                        .map_err(|e| std::io::Error::other(format!("decode dust event: {e}")))?;
                    state = crypto_provider
                        .fold_dust(state, &ev)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    n_events = n_events.saturating_add(1);
                    last_applied_at = Some(Instant::now());

                    if n_events == 1 || n_events.is_multiple_of(1000) {
                        eprintln!(
                            "[ows-midnight] dust sync progress: last_seen_id={last_seen_id} max_id={max_id:?} events_applied={n_events}"
                        );
                    }
                    if n_events.is_multiple_of(DUST_SNAPSHOT_INTERVAL) {
                        save_dust_snapshot(
                            cache_path.as_deref(),
                            scope,
                            &fp,
                            &dust_pk_hex,
                            &state,
                            last_seen_id,
                            max_id,
                            snapshot_block_height,
                        );
                    }

                    if max_id.is_some_and(|m| last_seen_id >= m) {
                        dropped = false;
                        break;
                    }
                }
                "complete" => {
                    if max_id.is_none() && last_seen_id >= 0 {
                        max_id = Some(last_seen_id);
                    }
                    dropped = !dust_at_chain_tip(last_seen_id, max_id);
                    break;
                }
                _ => {}
            }
        }

        drop(ws);

        if dropped {
            save_dust_snapshot(
                cache_path.as_deref(),
                scope,
                &fp,
                &dust_pk_hex,
                &state,
                last_seen_id,
                max_id,
                snapshot_block_height,
            );
        }
        if !dropped && dust_at_chain_tip(last_seen_id, max_id) {
            break;
        }
        if attempt + 1 < DUST_SYNC_MAX_ATTEMPTS {
            let backoff_ms = 250u64.saturating_mul((attempt + 1) as u64);
            if dropped {
                eprintln!(
                    "[ows-midnight] dust sync: retry {}/{} in {}ms…",
                    attempt + 2,
                    DUST_SYNC_MAX_ATTEMPTS,
                    backoff_ms
                );
            }
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            continue;
        }
        return Err(std::io::Error::other(format!(
            "dust ledger sync websocket connection dropped after {DUST_SYNC_MAX_ATTEMPTS} attempts"
        )));
    }

    save_dust_snapshot(
        cache_path.as_deref(),
        scope,
        &fp,
        &dust_pk_hex,
        &state,
        last_seen_id,
        max_id,
        snapshot_block_height,
    );
    Ok(state)
}

/// DUST balance for `ows fund balance` — resumes the dust ledger from this dust key's disk
/// snapshot when present, otherwise replays from genesis, then applies the ledger decay rules
/// at `dust_ctime_unix_secs`. Returns `(utxo_count, summed_specks)`.
pub async fn get_dust_balance_for_display(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    dust_ctime_unix_secs: u64,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<(usize, u128), std::io::Error> {
    let st =
        sync_dust_local_state(indexer_url, crypto_provider, scope, current_block_height).await?;
    Ok(dust_balance_from_state(&st, dust_ctime_unix_secs))
}

/// Whether the network's dust ledger is live — a runtime property of the indexer, not the
/// network's name. Probes the `dustLedgerEvents` stream for its tip cursor and reports live only
/// when a positive `maxId` is observed, so the dust-fee section appears on any network whose dust
/// ledger is active (mainnet included) with no per-network code change. Needs no wallet key: the
/// tip is chain-global. Fail-safe — a missing or empty stream, a GraphQL/transport error, or a
/// silent socket all read as not live.
pub(crate) async fn dust_ledger_is_live(indexer_url: &str) -> bool {
    match probe_dust_stream_tip(indexer_url).await {
        Ok(max_id) => is_dust_live(max_id),
        Err(e) => {
            eprintln!("[ows-midnight] dust liveness probe failed ({e}); hiding dust section");
            false
        }
    }
}

/// True when a dust stream tip cursor marks a live ledger (a positive `maxId`).
fn is_dust_live(max_id: Option<i64>) -> bool {
    matches!(max_id, Some(m) if m > 0)
}

/// Read the dust stream's tip `maxId` from the first informative frame, then disconnect.
/// `Ok(None)` means no live tip was revealed (empty stream, GraphQL error, close, or idle window).
async fn probe_dust_stream_tip(indexer_url: &str) -> Result<Option<i64>, std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let timeout = Duration::from_secs(DUST_PROBE_TIMEOUT_SECS);
    let mut ws =
        indexer_ws::connect_and_init(indexer_url, ws_idle_timeout(SyncStream::Dust), None).await?;
    indexer_ws::subscribe(
        &mut ws,
        "1",
        DUST_LEDGER_SUB,
        serde_json::json!({ "id": 0 }),
    )
    .await?;

    let started = Instant::now();
    loop {
        if started.elapsed() > timeout {
            return Ok(None);
        }
        let msg = match tokio::time::timeout(timeout, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(std::io::Error::other(e.to_string())),
            Ok(None) | Err(_) => return Ok(None),
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(p) => {
                let _ = ws.send(Message::Pong(p)).await;
                continue;
            }
            Message::Close(_) => return Ok(None),
            Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => continue,
        };
        let frame: indexer_ws::WsFrame<DustWsData> =
            serde_json::from_str(&text).map_err(|e| std::io::Error::other(e.to_string()))?;
        match frame.r#type.as_str() {
            "next" => {
                let Some(payload) = frame.payload else {
                    continue;
                };
                // A GraphQL error (e.g. a schema without `dustLedgerEvents`) means not live.
                if payload.errors.is_some() {
                    return Ok(None);
                }
                if let Some(evt) = payload.data.and_then(|d| d.dust_ledger_events) {
                    return Ok(Some(evt.max_id));
                }
            }
            "error" | "complete" => return Ok(None),
            _ => {}
        }
    }
}

fn dust_public_key_hex(dust_pk: &DustPublicKey) -> Result<String, std::io::Error> {
    let mut b = Vec::new();
    dust_pk
        .serialize(&mut b)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(hex::encode(b))
}

fn dust_balance_from_state(
    st: &DustLocalState<InMemoryDB>,
    dust_ctime_unix_secs: u64,
) -> (usize, u128) {
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger::dust::DustOutput;

    let dust_ctime = Timestamp::from_secs(dust_ctime_unix_secs);
    let mut sum: u128 = 0;
    let mut n: usize = 0;
    for qdo in st.utxos().collect::<Vec<_>>() {
        let Some(gen_info) = st.generation_info(&qdo) else {
            continue;
        };
        n += 1;
        let v = DustOutput::from(qdo).updated_value(&gen_info, dust_ctime, &st.params);
        sum = sum.saturating_add(v);
    }
    (n, sum)
}

/// Format a DUST amount (specks) into a human-readable decimal string.
///
/// The ledger denominates DUST in `SPECKS_PER_DUST` "specks". If that constant is a power of 10
/// (as expected), we render a fixed-point decimal; otherwise we fall back to `"<specks> specks"`.
pub fn format_dust_specks(specks: u128) -> String {
    let scale = midnight_ledger::structure::SPECKS_PER_DUST;
    if scale == 0 {
        return specks.to_string();
    }

    // Check scale is 10^k so fixed-point formatting is unambiguous.
    let mut tmp = scale;
    let mut decimals: u32 = 0;
    while tmp.is_multiple_of(10) {
        tmp /= 10;
        decimals += 1;
    }
    if tmp != 1 {
        return format!("{specks} specks");
    }

    let whole = specks / scale;
    let frac = specks % scale;
    if decimals == 0 {
        return whole.to_string();
    }
    format!("{whole}.{frac:0width$}", width = decimals as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_max_id_ignores_nonpositive_and_keeps_highest() {
        assert_eq!(dust_merge_max_id(None, 0), None);
        assert_eq!(dust_merge_max_id(Some(5), 0), Some(5));
        assert_eq!(dust_merge_max_id(Some(5), 3), Some(5));
        assert_eq!(dust_merge_max_id(Some(5), 9), Some(9));
        assert_eq!(dust_merge_max_id(None, 7), Some(7));
    }

    #[test]
    fn at_chain_tip_requires_positive_max_and_caught_up_cursor() {
        assert!(!dust_at_chain_tip(10, None));
        assert!(!dust_at_chain_tip(10, Some(0)));
        assert!(!dust_at_chain_tip(9, Some(10)));
        assert!(dust_at_chain_tip(10, Some(10)));
        assert!(dust_at_chain_tip(11, Some(10)));
    }

    #[test]
    fn dust_live_only_on_positive_tip() {
        // No tip observed (empty/absent stream, or probe error) → not live.
        assert!(!is_dust_live(None));
        // A zero tip is treated as no live ledger, matching the chain-tip cursor semantics.
        assert!(!is_dust_live(Some(0)));
        assert!(!is_dust_live(Some(-1)));
        // Any positive tip means the dust ledger is live.
        assert!(is_dust_live(Some(1)));
        assert!(is_dust_live(Some(9_999)));
    }
}
