//! Fast chain-tip freshness check via indexer HTTP (`block { height }`), avoiding a slow WebSocket catch-up.

use super::ledger_params;

/// Fetch the indexer's current block height once (HTTP). `None` on failure, which
/// forces the slow WebSocket catch-up (fail-safe — never trusts a stale snapshot).
pub(super) fn fetch_current_block_height(indexer_url: &str) -> Option<i64> {
    match super::block_on(ledger_params::fetch_indexer_block_height(indexer_url)) {
        Ok(height) => {
            eprintln!("[ows-midnight] indexer tip block height={height} (HTTP)");
            Some(height)
        }
        Err(_) => {
            eprintln!("[ows-midnight] indexer block height query failed; using WebSocket catch-up");
            None
        }
    }
}

/// True when a complete on-disk snapshot can be trusted without a WebSocket catch-up.
pub(super) fn snapshot_fresh_by_http_tip(
    current_block_height: Option<i64>,
    saved_block_height: i64,
    snapshot_complete: bool,
) -> bool {
    snapshot_complete && saved_block_height > 0 && current_block_height == Some(saved_block_height)
}

#[cfg(test)]
mod tests {
    use super::snapshot_fresh_by_http_tip;

    #[test]
    fn http_tip_fresh_only_when_complete_and_height_matches() {
        // Heights match and snapshot complete → trust the snapshot.
        assert!(snapshot_fresh_by_http_tip(Some(100), 100, true));
        // Height differs → catch up.
        assert!(!snapshot_fresh_by_http_tip(Some(101), 100, true));
        // Snapshot incomplete → catch up.
        assert!(!snapshot_fresh_by_http_tip(Some(100), 100, false));
        // No saved height (legacy snapshot) → catch up once.
        assert!(!snapshot_fresh_by_http_tip(Some(0), 0, true));
        // HTTP height fetch failed → catch up.
        assert!(!snapshot_fresh_by_http_tip(None, 100, true));
    }
}
