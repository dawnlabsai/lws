//! VK-hidden shielded sync: full `zswapLedgerEvents` replay.
//!
//! No viewing key is sent to the indexer. We subscribe to every zswap event, decode each one
//! locally with `tagged_deserialize<Event>`, and fold it into a full `ZswapLocalState` (the
//! commitment Merkle tree + qualified coins) via `replay_events` — the spendable wallet state.
//! Balances are derived from that state; nothing here is signing-specific, every sync builds it.

mod sync_cache;

use futures_util::{SinkExt as _, StreamExt as _};
use midnight_ledger::events::Event;
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;
use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;
use std::path::Path;
use std::time::{Duration, Instant};

use super::ShieldedWalletState;
use crate::cache_io::{self, SyncCacheScope};
use crate::indexer_ws::{self, IndexerWs};
use crate::midnight_env::{self, SyncStream};

const ZSWAP_LEDGER_SUB: &str = r#"
subscription ZswapLedgerEvents($id: Int) {
  zswapLedgerEvents(id: $id) { id raw maxId protocolVersion }
}
"#;

/// Persist a progress snapshot every N applied events during a long replay, so a later run
/// resumes near the tip even if this one is interrupted.
const ZSWAP_SNAPSHOT_INTERVAL: u64 = 1000;

/// "Nothing synced yet" resume cursor. zswap ledger event ids start at 0, so genesis must sit
/// below 0 to stay distinct from "synced through event 0"; `resume_subscribe_id` clamps it to 0.
const GENESIS_CURSOR: i64 = -1;

/// VK-hidden shielded wallet sync: replay `zswapLedgerEvents` into a full spendable
/// `ZswapLocalState` without ever sending a viewing key to the indexer, persisting it for resume
/// and later spends. Resumes from this zswap key's disk snapshot when present, else from genesis.
pub(super) async fn sync_wallet(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedWalletState, std::io::Error> {
    let seed_fp = hex::encode(
        &crypto_provider
            .shielded_key_fingerprint()
            .map_err(|e| std::io::Error::other(e.to_string()))?[..16],
    );
    let state = run_zswap_replay(
        indexer_url,
        crypto_provider,
        scope,
        &seed_fp,
        current_block_height,
    )
    .await?;
    Ok(ShieldedWalletState {
        zswap: state.wallet,
    })
}

/// Drive the `zswapLedgerEvents` replay into a spendable `ZswapLocalState`, resuming from this
/// key's snapshot when present. Returns the final replay state; the caller projects the wallet
/// (and balances) from it.
async fn run_zswap_replay(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    seed_fp: &str,
    current_block_height: Option<i64>,
) -> Result<ZswapReplayState, std::io::Error> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let cache_path = sync_cache::snapshot_path(indexer_url, seed_fp, scope);

    let mut wallet = ZswapLocalState::new();
    let mut last_seen_id: i64 = GENESIS_CURSOR;
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
            let w = super::cache::decode_zswap_state(&snap.zswap_state_hex).ok()?;
            Some((
                w,
                snap.last_seen_event_id,
                snap.max_id_when_saved,
                snap.block_height_when_saved,
            ))
        });
    if let Some((resumed_wallet, last, saved_max, saved_height)) = resumed {
        wallet = resumed_wallet;
        last_seen_id = last;
        max_id = Some(saved_max);
        saved_block_height = saved_height;
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: resuming spend wallet from snapshot (event id {}, saved tip {saved_max})",
            resume_subscribe_id(last_seen_id)
        );
    } else {
        eprintln!("[ows-midnight] zswapLedgerEvents: replaying from genesis");
    }

    let mut state = ZswapReplayState {
        wallet,
        // The wallet was persisted exactly at `last_seen_id` (or GENESIS_CURSOR from genesis). The
        // inclusive resume re-sends that boundary event; feeding its commitment to `replay_events`
        // again fails ("inserted non-linearly"), so the wallet only ingests events strictly past
        // this cursor.
        wallet_resume_cursor: last_seen_id,
        last_seen_id,
        max_id,
        n_events: 0,
        last_event_at: None,
    };

    // Fast path: when the indexer's HTTP tip height matches the snapshot's, the snapshot
    // already reflects the live tip — skip the WebSocket catch-up entirely.
    let snapshot_complete = state
        .max_id
        .is_some_and(|m| m > 0 && state.last_seen_id >= m);
    if crate::tip_verify::snapshot_fresh_by_http_tip(
        current_block_height,
        saved_block_height,
        snapshot_complete,
    ) {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: indexer block height unchanged ({saved_block_height}); using on-disk snapshot"
        );
        return Ok(state);
    }

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

    eprintln!(
        "[ows-midnight] zswapLedgerEvents replay done: events_seen={} last_seen_id={} max_id={:?}",
        state.n_events, state.last_seen_id, state.max_id
    );

    Ok(state)
}

struct ZswapReplayState {
    /// Full spendable state (Merkle tree + qualified coins), built on every sync; the snapshot
    /// persists it and the balance is derived from it.
    wallet: ZswapLocalState<InMemoryDB>,
    /// Highest event id already folded into `wallet` at resume time; events at or below it are not
    /// re-fed to `replay_events` (the commitment tree rejects re-inserting an already committed
    /// output, and the inclusive resume re-sends the boundary event).
    wallet_resume_cursor: i64,
    last_seen_id: i64,
    max_id: Option<i64>,
    n_events: u64,
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

/// Persist the spendable wallet state + cursor for the next run (best-effort; ignored when caching
/// is disabled or serialization fails). The freshly built wallet is always current, so it is
/// persisted directly — no stale-tree preservation dance.
fn save_zswap_snapshot(cache: Option<&ZswapCache<'_>>, state: &ZswapReplayState) {
    let Some(cache) = cache else {
        return;
    };
    let Ok(zswap_state_hex) = super::cache::encode_zswap_state(&state.wallet) else {
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
            zswap_state_hex,
        },
    );
}

/// Subscribe id for resuming the zswap ledger subscription. The indexer treats `id` as an
/// inclusive lower bound, so resuming from the last-seen event re-sends that event —
/// carrying the live max id — instead of tailing silently past the tip when nothing new has
/// happened. The unshielded sync resumes the same way. Genesis (no cursor) starts at 0.
fn resume_subscribe_id(last_seen_id: i64) -> i64 {
    last_seen_id.max(0)
}

/// Decode one raw zswap ledger event and fold it into the spendable `ZswapLocalState` via
/// `crypto_provider.fold_shielded` — adding owned output commitments to the Merkle tree and
/// removing spent inputs. This is the single source for both the balance (summed from the
/// wallet's coins) and spends.
fn fold_zswap_event(
    crypto_provider: &MidnightCryptoProvider,
    wallet: &mut ZswapLocalState<InMemoryDB>,
    raw: &str,
) -> Result<(), std::io::Error> {
    let raw_hex = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw_hex)
        .map_err(|e| std::io::Error::other(format!("invalid zswap event raw hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("decode zswap event: {e}")))?;
    *wallet = crypto_provider
        .fold_shielded(wallet.clone(), &ev)
        .map_err(|e| std::io::Error::other(format!("replay zswap event into wallet: {e}")))?;
    Ok(())
}

/// Drain zswap-ledger events from `ws`, folding each into `state.wallet` until the tip is
/// reached or the socket drops. Transport only; per-event folding lives in [`fold_zswap_event`].
/// Returns `(dropped, events_seen_this_attempt)`.
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

                // Feed the wallet only events past its resume cursor: the inclusive resume re-sends
                // the boundary event, and `replay_events` rejects re-inserting an already committed
                // output.
                if evt.id > state.wallet_resume_cursor {
                    fold_zswap_event(crypto_provider, &mut state.wallet, &evt.raw)?;
                }

                if state.n_events == 1 || state.n_events.is_multiple_of(cfg.progress_interval) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents replay progress: last_seen_id={} max_id={:?} events_seen={}",
                        state.last_seen_id, state.max_id, state.n_events
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
        // Genesis (no cursor, GENESIS_CURSOR = -1) starts the replay at event 0.
        assert_eq!(resume_subscribe_id(-1), 0);
        assert_eq!(resume_subscribe_id(0), 0);
    }
}
