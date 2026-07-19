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
use std::time::{Duration, Instant};

use super::cache_io::SyncCacheScope;
use super::indexer_ws::{self, IndexerWs};
use super::midnight_env::{self, SyncStream};
use super::ShieldedBalances;

const ZSWAP_LEDGER_SUB: &str = r#"
subscription ZswapLedgerEvents($id: Int) {
  zswapLedgerEvents(id: $id) { id raw maxId protocolVersion }
}
"#;

pub(super) fn token_type_hex(ci: &coin::Info) -> String {
    let t = ci.type_.into_inner();
    format!("0x{}", hex::encode(t.0))
}

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
/// No caching: every call replays the entire zswap ledger from genesis. The
/// disk-snapshot wiring lands in a follow-up.
pub(super) async fn fetch_balances(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    _scope: &SyncCacheScope,
) -> Result<ShieldedBalances, std::io::Error> {
    let owned: BTreeMap<coin::Nullifier, coin::Info> = BTreeMap::new();
    let last_seen_id: i64 = -1;
    let mut state = ZswapReplayState {
        owned,
        last_seen_id,
        max_id: None,
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

    eprintln!("[ows-midnight] zswapLedgerEvents: replaying from genesis");

    for attempt in 0..=3u32 {
        if attempt > 0 {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: reconnecting (attempt {}) from event id {}",
                attempt + 1,
                state.last_seen_id.saturating_add(1)
            );
        }

        eprintln!("[ows-midnight] zswapLedgerEvents: connecting to indexer websocket…");

        let mut ws =
            indexer_ws::connect_and_init(indexer_url, cfg.ws_idle, Some("zswapLedgerEvents"))
                .await?;

        let resume_id = state.last_seen_id.saturating_add(1);
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
            replay_zswap_ws_loop(&mut ws, crypto_provider, &mut state, &cfg).await?;

        drop(ws);

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
        return Err(std::io::Error::other(format!(
            "zswap ledger sync incomplete: last_seen_id={} max_id={:?}; try again",
            state.last_seen_id, state.max_id
        )));
    }

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
) -> Result<(bool, u64), std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let mut dropped = false;
    let mut attempt_events: u64 = 0;

    loop {
        let stall_elapsed = state.last_event_at.unwrap_or(cfg.sync_started).elapsed();
        if stall_elapsed > cfg.stall_timeout {
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
