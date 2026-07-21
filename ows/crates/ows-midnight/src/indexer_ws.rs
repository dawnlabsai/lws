//! Shared GraphQL-over-WebSocket helpers for Midnight indexer sync.

use futures_util::{SinkExt as _, StreamExt as _};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::urls::indexer_ws_url;

pub type IndexerWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Inbound GraphQL-transport-ws subscription frame (`D` is the subscription `data` shape).
#[derive(Debug, Deserialize)]
pub struct WsFrame<D> {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(default)]
    pub payload: Option<WsPayload<D>>,
}

#[derive(Debug, Deserialize)]
pub struct WsPayload<D> {
    #[serde(default)]
    pub data: Option<D>,
    #[serde(default)]
    pub errors: Option<Vec<serde_json::Value>>,
}

fn transport_err(e: impl ToString) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

use super::midnight_env;

/// Open a GraphQL-transport-ws connection to the indexer.
pub async fn connect_indexer(indexer_url: &str) -> Result<IndexerWs, std::io::Error> {
    let ws_url = indexer_ws_url(indexer_url)?;
    let mut req = ws_url
        .into_client_request()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "graphql-transport-ws".parse().expect("valid header"),
    );
    let connect_timeout = midnight_env::ws_connect_timeout();
    let (ws, _resp) = match tokio::time::timeout(connect_timeout, connect_async(req)).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            return Err(std::io::Error::other(format!(
                "failed to connect to Midnight indexer websocket: {e}"
            )));
        }
        Err(_) => {
            return Err(std::io::Error::other(format!(
                "timed out connecting to Midnight indexer websocket after {}s",
                connect_timeout.as_secs()
            )));
        }
    };
    Ok(ws)
}

/// Send `connection_init` on an open WebSocket.
pub async fn send_connection_init(ws: &mut IndexerWs) -> Result<(), std::io::Error> {
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({ "type": "connection_init" }).to_string(),
    ))
    .await
    .map_err(transport_err)
}

/// Wait for `connection_ack` (or fail on `connection_error` / idle timeout).
///
/// When `log_label` is set, prints a ready line after ack.
pub async fn wait_for_connection_ack(
    ws: &mut IndexerWs,
    ws_idle: Duration,
    log_label: Option<&str>,
) -> Result<(), std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let started = Instant::now();
    loop {
        // Overall ack budget is three idle windows: a couple of unrelated frames
        // (pings, server keepalives) may arrive before connection_ack, so we don't
        // give up on the first idle window — only once three have elapsed with no ack.
        if started.elapsed() > ws_idle.saturating_mul(3) {
            return Err(std::io::Error::other(format!(
                "timed out waiting for indexer connection_ack after {}s",
                (ws_idle.saturating_mul(3)).as_secs()
            )));
        }
        let msg = match tokio::time::timeout(ws_idle, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(transport_err(e)),
            Ok(None) => {
                return Err(std::io::Error::other(
                    "indexer websocket closed before connection_ack".to_string(),
                ));
            }
            Err(_) => {
                return Err(std::io::Error::other(format!(
                    "no indexer websocket data for {}s while waiting for connection_ack",
                    ws_idle.as_secs()
                )));
            }
        };
        match msg {
            Message::Text(t) => {
                let v: serde_json::Value =
                    serde_json::from_str(&t).map_err(|e| std::io::Error::other(e.to_string()))?;
                match v.get("type").and_then(|x| x.as_str()) {
                    Some("connection_ack") => {
                        if let Some(label) = log_label {
                            eprintln!("[ows-midnight] {label}: indexer websocket ready");
                        }
                        return Ok(());
                    }
                    Some("connection_error") => {
                        return Err(std::io::Error::other(format!(
                            "indexer connection_error: {t}"
                        )));
                    }
                    _ => continue,
                }
            }
            Message::Ping(p) => {
                let _ = ws.send(Message::Pong(p)).await;
            }
            Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
            Message::Close(_) => {
                return Err(std::io::Error::other(
                    "indexer websocket closed before connection_ack".to_string(),
                ));
            }
        }
    }
}

/// Connect, init, and wait for ack in one step.
pub async fn connect_and_init(
    indexer_url: &str,
    ws_idle: Duration,
    log_label: Option<&str>,
) -> Result<IndexerWs, std::io::Error> {
    let mut ws = connect_indexer(indexer_url).await?;
    send_connection_init(&mut ws).await?;
    wait_for_connection_ack(&mut ws, ws_idle, log_label).await?;
    Ok(ws)
}

/// Send a GraphQL subscription frame.
pub async fn subscribe(
    ws: &mut IndexerWs,
    sub_id: &str,
    query: &str,
    variables: serde_json::Value,
) -> Result<(), std::io::Error> {
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({
            "id": sub_id,
            "type": "subscribe",
            "payload": { "query": query, "variables": variables }
        })
        .to_string(),
    ))
    .await
    .map_err(transport_err)
}

/// Read budget for a stream-tip probe: a live indexer serves the first frame right away, so the
/// probe needs far less than a full-sync idle window.
const TIP_PROBE_TIMEOUT_SECS: u64 = 15;

/// Probe an `id`-cursored indexer subscription (e.g. `zswapLedgerEvents`, `dustLedgerEvents`) for
/// its live tip `maxId`, then disconnect. Subscribes from event id 0; the first data frame carries
/// `maxId` = the current stream tip. Used to detect a resume snapshot whose saved cursor sits past
/// the live tip (an indexer/chain reset). `Ok(None)` means the tip was undetermined (empty stream,
/// GraphQL error, close, or idle window) — callers treat that as "unknown", never as stale.
pub async fn probe_stream_max_id(
    indexer_url: &str,
    subscription_query: &str,
) -> Result<Option<i64>, std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let probe_timeout = Duration::from_secs(TIP_PROBE_TIMEOUT_SECS);
    let mut ws = connect_and_init(indexer_url, probe_timeout, None).await?;
    subscribe(
        &mut ws,
        "1",
        subscription_query,
        serde_json::json!({ "id": 0 }),
    )
    .await?;

    let started = Instant::now();
    loop {
        if started.elapsed() > probe_timeout {
            return Ok(None);
        }
        let msg = match tokio::time::timeout(probe_timeout, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(transport_err(e)),
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
        let frame: WsFrame<serde_json::Value> =
            serde_json::from_str(&text).map_err(transport_err)?;
        match frame.r#type.as_str() {
            "next" => {
                let Some(payload) = frame.payload else {
                    continue;
                };
                if payload.errors.is_some() {
                    return Ok(None);
                }
                if let Some(max_id) = payload.data.as_ref().and_then(extract_max_id) {
                    return Ok(Some(max_id));
                }
            }
            "error" | "complete" => return Ok(None),
            _ => {}
        }
    }
}

/// Pull `maxId` from a subscription payload's single event object. The field name varies by stream
/// (`zswapLedgerEvents`, `dustLedgerEvents`, …), so one probe serves every `id`-cursored stream
/// without a per-stream data type.
fn extract_max_id(data: &serde_json::Value) -> Option<i64> {
    data.as_object()?
        .values()
        .find_map(|v| v.get("maxId"))
        .and_then(|m| m.as_i64())
}

#[cfg(test)]
mod tests {
    use super::extract_max_id;

    #[test]
    fn extract_max_id_from_stream_payloads() {
        let zswap = serde_json::json!({
            "zswapLedgerEvents": { "id": 2, "raw": "0x00", "maxId": 4569 }
        });
        assert_eq!(extract_max_id(&zswap), Some(4569));
        let dust = serde_json::json!({
            "dustLedgerEvents": { "id": 1, "raw": "0x00", "maxId": 4572 }
        });
        assert_eq!(extract_max_id(&dust), Some(4572));
        // A null event object (no data yet) reveals no tip.
        assert_eq!(
            extract_max_id(&serde_json::json!({ "zswapLedgerEvents": null })),
            None
        );
        // No fields at all → no tip.
        assert_eq!(extract_max_id(&serde_json::json!({})), None);
    }
}
