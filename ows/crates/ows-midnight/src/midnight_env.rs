//! Sync-stream identifiers and fixed timeout tuning for Midnight indexer sync.

use std::time::Duration;

/// Indexer sync stream. Extended with Shielded/Dust as those balance types land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStream {
    Unshielded,
}

// Fixed sync tuning (not environment-configurable).
const WS_IDLE_TIMEOUT_SECS: u64 = 90;
const STALL_TIMEOUT_SECS: u64 = 120;
const INDEXER_HTTP_TIMEOUT_SECS: u64 = 30;
const WS_CONNECT_TIMEOUT_SECS: u64 = 30;

pub fn ws_idle_timeout(_stream: SyncStream) -> Duration {
    Duration::from_secs(WS_IDLE_TIMEOUT_SECS)
}

pub fn stall_timeout(_stream: SyncStream) -> Duration {
    Duration::from_secs(STALL_TIMEOUT_SECS)
}

/// Per-request timeout for Midnight indexer GraphQL HTTP calls.
pub fn indexer_http_timeout() -> Duration {
    Duration::from_secs(INDEXER_HTTP_TIMEOUT_SECS)
}

/// Timeout for establishing a Midnight indexer WebSocket connection.
pub fn ws_connect_timeout() -> Duration {
    Duration::from_secs(WS_CONNECT_TIMEOUT_SECS)
}
