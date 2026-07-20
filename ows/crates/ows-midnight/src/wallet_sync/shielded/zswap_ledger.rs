//! Full `zswapLedgerEvents` replay (Mode B) for shielded balance sync.
//!
//! No viewing key is sent to the indexer. We subscribe to every zswap event,
//! decode each one locally with `tagged_deserialize<Event>`, and identify owned
//! coins by handing each output's preimage evidence to the crypto provider's
//! `detect_shielded_output` (the keys stay inside the provider), matching the
//! returned nullifier against later inputs.

use futures_util::{SinkExt as _, StreamExt as _};
use midnight_coin_structure::coin;
use midnight_ledger::events::{Event, EventDetails};
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;
use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cache_io::{self, SyncCacheScope};
use crate::indexer_ws::{self, IndexerWs};
use crate::midnight_env::{self, SyncStream};
use super::sync_cache;
use crate::ShieldedBalances;

const ZSWAP_LEDGER_SUB: &str = r#"
subscription ZswapLedgerEvents($id: Int) {
  zswapLedgerEvents(id: $id) { id raw maxId protocolVersion }
}
"#;

pub(super) fn token_type_hex(ci: &coin::Info) -> String {
    let t = ci.type_.into_inner();
    format!("0x{}", hex::encode(t.0))
}

/// Persist a progress snapshot every N applied events during a long replay, so a later run
/// resumes near the tip even if this one is interrupted.
const ZSWAP_SNAPSHOT_INTERVAL: u64 = 1000;

pub(super) fn balances_from_owned_coins(
    owned: &BTreeMap<coin::Nullifier, coin::Info>,
) -> ShieldedBalances {
    let mut balances: ShieldedBalances = BTreeMap::new();
    for ci in owned.values() {
        *balances.entry(token_type_hex(ci)).or_insert(0) += ci.value;
    }
    balances
}

/// Zswap-ledger-events shielded balance fetch — VK-free path (Mode B).
///
/// Resumes from this zswap key's disk snapshot (unspent owned coins + cursor) when present,
/// otherwise replays from genesis; the synced coin set is persisted for the next run.
pub(super) async fn fetch_balances(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    seed_fp: &str,
    current_block_height: Option<i64>,
) -> Result<ShieldedBalances, std::io::Error> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let cache_path = sync_cache::snapshot_path(indexer_url, seed_fp, scope);

    let mut owned: BTreeMap<coin::Nullifier, coin::Info> = BTreeMap::new();
    let mut last_seen_id: i64 = -1;
    let mut max_id: Option<i64> = None;
    let mut saved_block_height: i64 = 0;

    // Resume only from a snapshot for this same indexer site, network, and zswap key.
    let resumed = cache_path
        .as_ref()
        .and_then(|p| sync_cache::try_load_snapshot(p))
        .filter(|snap| {
            cache_io::snapshot_site_matches(scope, &snap.chain_id, &fp, &snap.indexer_fingerprint)
                && snap.zswap_key_fingerprint == seed_fp
        })
        .and_then(|snap| {
            let owned = sync_cache::decode_owned_coins(&snap.owned_coins).ok()?;
            Some((
                owned,
                snap.last_seen_event_id,
                snap.max_id_when_saved,
                snap.block_height_when_saved,
            ))
        });
    if let Some((resumed_owned, last, saved_max, saved_height)) = resumed {
        owned = resumed_owned;
        last_seen_id = last;
        max_id = Some(saved_max);
        saved_block_height = saved_height;
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: resuming from event id {} ({} unspent coins, saved tip {saved_max})",
            resume_subscribe_id(last_seen_id),
            owned.len()
        );
    } else {
        eprintln!("[ows-midnight] zswapLedgerEvents: replaying from genesis");
    }

    // Fast path: when the indexer's HTTP tip height matches the snapshot's, the snapshot
    // already reflects the live tip — skip the WebSocket catch-up entirely.
    let snapshot_complete = max_id.is_some_and(|m| m > 0 && last_seen_id >= m);
    if crate::tip_verify::snapshot_fresh_by_http_tip(
        current_block_height,
        saved_block_height,
        snapshot_complete,
    ) {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: indexer block height unchanged ({saved_block_height}); using on-disk snapshot"
        );
        return Ok(balances_from_owned_coins(&owned));
    }

    let mut state = ZswapReplayState {
        owned,
        last_seen_id,
        max_id,
        n_events: 0,
        n_outputs_decrypted: 0,
        last_event_at: None,
    };
    let cfg = ZswapReplayCfg {
        ws_idle: midnight_env::ws_idle_timeout(SyncStream::Shielded),
        stall_timeout: midnight_env::stall_timeout(SyncStream::Shielded),
        progress_interval: 1000,
        sync_started: Instant::now(),
    };
    let cache = cache_path.as_deref().map(|path| ZswapCache {
        path,
        scope,
        fp: &fp,
        key_fp: seed_fp,
        block_height: current_block_height.unwrap_or(0),
    });

    for attempt in 0..=3u32 {
        if attempt > 0 {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: reconnecting (attempt {}) from event id {}",
                attempt + 1,
                resume_subscribe_id(state.last_seen_id)
            );
        }

        eprintln!("[ows-midnight] zswapLedgerEvents: connecting to indexer websocket…");

        let mut ws =
            indexer_ws::connect_and_init(indexer_url, cfg.ws_idle, Some("zswapLedgerEvents"))
                .await?;

        let resume_id = resume_subscribe_id(state.last_seen_id);
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: subscribed from event id {resume_id} (last_seen_id={})",
            state.last_seen_id
        );
        indexer_ws::subscribe(
            &mut ws,
            "1",
            ZSWAP_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        let (dropped, attempt_events) =
            replay_zswap_ws_loop(&mut ws, crypto_provider, &mut state, &cfg, cache.as_ref())
                .await?;

        drop(ws);

        if dropped {
            save_zswap_snapshot(cache.as_ref(), &state);
        }
        if !dropped && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: caught up (last_seen_id={} max_id={})",
                state.last_seen_id,
                state.max_id.unwrap_or(-1)
            );
            break;
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(
                250u64.saturating_mul((attempt + 1) as u64),
            ))
            .await;
            continue;
        }
        if attempt_events == 0 && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
            break;
        }
        save_zswap_snapshot(cache.as_ref(), &state);
        return Err(std::io::Error::other(format!(
            "zswap ledger sync incomplete: last_seen_id={} max_id={:?}; try again",
            state.last_seen_id, state.max_id
        )));
    }

    save_zswap_snapshot(cache.as_ref(), &state);

    let balances = balances_from_owned_coins(&state.owned);

    eprintln!(
        "[ows-midnight] zswapLedgerEvents replay done: events_seen={} decrypted_outputs={} token_kinds={} last_seen_id={} max_id={:?}",
        state.n_events,
        state.n_outputs_decrypted,
        balances.len(),
        state.last_seen_id,
        state.max_id
    );

    Ok(balances)
}

struct ZswapReplayState {
    owned: BTreeMap<coin::Nullifier, coin::Info>,
    last_seen_id: i64,
    max_id: Option<i64>,
    n_events: u64,
    n_outputs_decrypted: u64,
    last_event_at: Option<Instant>,
}

struct ZswapReplayCfg {
    ws_idle: Duration,
    stall_timeout: Duration,
    progress_interval: u64,
    sync_started: Instant,
}

/// Where to persist the zswap replay snapshot, plus the keys that scope it.
struct ZswapCache<'a> {
    path: &'a Path,
    scope: &'a SyncCacheScope,
    fp: &'a str,
    key_fp: &'a str,
    /// Indexer HTTP tip height observed at sync start; stamped onto saved snapshots so a
    /// later run can skip the WebSocket catch-up when the tip is unchanged.
    block_height: i64,
}

/// Persist the unspent owned coins + cursor for the next run (best-effort; ignored when caching
/// is disabled or serialization fails).
fn save_zswap_snapshot(cache: Option<&ZswapCache<'_>>, state: &ZswapReplayState) {
    let Some(cache) = cache else {
        return;
    };
    let Ok(owned_coins) = sync_cache::encode_owned_coins(&state.owned) else {
        return;
    };
    cache_io::try_save(
        cache.path,
        &sync_cache::ShieldedSyncSnapshot {
            version: sync_cache::SNAPSHOT_VERSION,
            indexer_fingerprint: cache.fp.to_string(),
            chain_id: cache_io::snapshot_chain_id(cache.scope),
            zswap_key_fingerprint: cache.key_fp.to_string(),
            last_seen_event_id: state.last_seen_id,
            max_id_when_saved: state
                .max_id
                .map(|m| m.max(state.last_seen_id))
                .unwrap_or(state.last_seen_id),
            block_height_when_saved: cache.block_height,
            owned_coins,
        },
    );
}

/// Subscribe id for resuming the zswap ledger subscription. The indexer treats `id` as an
/// inclusive lower bound, so resuming from the last-seen event re-sends that event —
/// carrying the live max id — instead of tailing silently past the tip when nothing new has
/// happened. Re-applying it is a no-op (`apply_zswap_event` inserts/removes by nullifier).
/// The unshielded sync resumes the same way (inclusive cursor + idempotent apply). Genesis
/// (no cursor) starts at 0.
fn resume_subscribe_id(last_seen_id: i64) -> i64 {
    last_seen_id.max(0)
}

/// Decode one raw zswap ledger event and apply it to `owned` via the crypto provider: an owned
/// output is inserted by nullifier, a spent input removed. Returns 1 if an owned output was
/// detected, else 0. Coin detection (the only key-bearing step) happens inside the provider.
fn apply_zswap_event(
    crypto_provider: &MidnightCryptoProvider,
    owned: &mut BTreeMap<coin::Nullifier, coin::Info>,
    raw: &str,
) -> Result<u64, std::io::Error> {
    let raw_hex = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw_hex)
        .map_err(|e| std::io::Error::other(format!("invalid zswap event raw hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("decode zswap event: {e}")))?;
    match ev.content {
        EventDetails::ZswapOutput {
            preimage_evidence, ..
        } => {
            if let Some((nul, ci)) = crypto_provider.detect_shielded_output(&preimage_evidence) {
                owned.insert(nul, ci);
                return Ok(1);
            }
        }
        EventDetails::ZswapInput { nullifier, .. } => {
            owned.remove(&nullifier);
        }
        _ => {}
    }
    Ok(0)
}

/// Drain zswap-ledger events from `ws`, applying each to `state` until the tip is
/// reached or the socket drops. Transport only; per-event key-matching lives in
/// [`apply_zswap_event`]. Returns `(dropped, events_seen_this_attempt)`.
async fn replay_zswap_ws_loop(
    ws: &mut IndexerWs,
    crypto_provider: &MidnightCryptoProvider,
    state: &mut ZswapReplayState,
    cfg: &ZswapReplayCfg,
    cache: Option<&ZswapCache<'_>>,
) -> Result<(bool, u64), std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let mut dropped = false;
    let mut attempt_events: u64 = 0;

    loop {
        let stall_elapsed = state.last_event_at.unwrap_or(cfg.sync_started).elapsed();
        if stall_elapsed > cfg.stall_timeout {
            save_zswap_snapshot(cache, state);
            return Err(std::io::Error::other(format!(
                "no zswap ledger events for {}s (last_seen_id={} max_id={:?}); \
indexer may be stalled",
                cfg.stall_timeout.as_secs(),
                state.last_seen_id,
                state.max_id
            )));
        }

        let msg = match tokio::time::timeout(cfg.ws_idle, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(_))) | Ok(None) => {
                dropped = true;
                break;
            }
            Err(_) => {
                if attempt_events == 0 && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: no new events (already at tip last_seen_id={} max_id={:?})",
                        state.last_seen_id, state.max_id
                    );
                    dropped = false;
                } else {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: no indexer message for {}s (last_seen_id={} max_id={:?})",
                        cfg.ws_idle.as_secs(),
                        state.last_seen_id,
                        state.max_id
                    );
                    dropped = true;
                }
                break;
            }
        };

        let Message::Text(t) = msg else {
            match msg {
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
                Message::Close(_) => {
                    dropped = true;
                }
                Message::Text(_) => unreachable!(),
            }
            if dropped {
                break;
            }
            continue;
        };
        state.last_event_at = Some(Instant::now());

        let frame: indexer_ws::WsFrame<ZswapWsData> =
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
                let Some(zdata) = payload.data else {
                    continue;
                };
                let Some(evt) = zdata.zswap_ledger_events else {
                    continue;
                };
                state.max_id = Some(match state.max_id {
                    Some(m) => m.max(evt.max_id),
                    None => evt.max_id,
                });
                state.last_seen_id = state.last_seen_id.max(evt.id);
                state.n_events = state.n_events.saturating_add(1);
                attempt_events = attempt_events.saturating_add(1);

                let decrypted = apply_zswap_event(crypto_provider, &mut state.owned, &evt.raw)?;
                state.n_outputs_decrypted = state.n_outputs_decrypted.saturating_add(decrypted);

                if state.n_events == 1 || state.n_events.is_multiple_of(cfg.progress_interval) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents replay progress: last_seen_id={} max_id={:?} events_seen={} decrypted_outputs={}",
                        state.last_seen_id, state.max_id, state.n_events, state.n_outputs_decrypted
                    );
                }
                if state.n_events.is_multiple_of(ZSWAP_SNAPSHOT_INTERVAL) {
                    save_zswap_snapshot(cache, state);
                }

                if state.max_id.is_some_and(|m| state.last_seen_id >= m) {
                    dropped = false;
                    break;
                }
            }
            "complete" => {
                dropped = false;
                break;
            }
            _ => {}
        }
    }

    Ok((dropped, attempt_events))
}

#[derive(Debug, Default, Deserialize)]
struct ZswapWsData {
    #[serde(rename = "zswapLedgerEvents")]
    #[serde(default)]
    zswap_ledger_events: Option<ZswapLedgerEventWire>,
}

#[derive(Debug, Deserialize)]
struct ZswapLedgerEventWire {
    id: i64,
    raw: String,
    #[serde(rename = "maxId")]
    max_id: i64,
}

#[cfg(test)]
mod tests {
    use super::resume_subscribe_id;

    #[test]
    fn resume_is_inclusive_of_last_seen_event() {
        // Warm resume re-fetches the last-seen event (inclusive) so the indexer echoes it
        // and reveals the live max id, instead of tailing past the tip from last_seen+1.
        assert_eq!(resume_subscribe_id(84699), 84699);
        // Genesis (no cursor, last_seen_id = -1) starts the replay at event 0.
        assert_eq!(resume_subscribe_id(-1), 0);
        assert_eq!(resume_subscribe_id(0), 0);
    }
}
