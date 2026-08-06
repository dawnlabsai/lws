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

/// True when a complete on-disk snapshot can be trusted via the indexer's HTTP block height alone.
///
/// This block-height match is only a *fallback* for when the event-tip probe was inconclusive
/// (`live_tip` is `None`). With a known `live_tip`, the caller's event-tip fast path is
/// authoritative: it already returned when the snapshot sat at the tip, so reaching here with a
/// `Some` tip means the snapshot is provably behind and must catch up. A `Some` `live_tip`
/// therefore forbids the HTTP path — the coarser height check misses whenever ledger events
/// advanced without a block-height change, which would otherwise leave balances stale.
pub(super) fn snapshot_fresh_by_http_tip(
    current_block_height: Option<i64>,
    saved_block_height: i64,
    snapshot_complete: bool,
    live_tip: Option<i64>,
) -> bool {
    live_tip.is_none()
        && snapshot_complete
        && saved_block_height > 0
        && current_block_height == Some(saved_block_height)
}

/// True when a resume snapshot's saved cursor sits beyond the live stream tip — the signature of
/// an indexer/chain reset that rewound (or rebuilt) the event ledger, leaving the snapshot pinned
/// to a longer, now-defunct chain. Resuming from such a cursor subscribes past the live tip: the
/// indexer serves nothing, so the sync would otherwise trust the stale saved tip and report
/// phantom balances. Only reports stale when a positive live tip was actually observed; an
/// undetermined tip (`None` — probe failed or empty stream) leaves the snapshot in place, so a
/// transient probe miss never discards good state.
///
/// Reset-safety therefore *requires* a successful tip probe: reset detection keys off the observed
/// `live_max_event_id`, so a chain reset that coincides with a failed probe is not caught this run
/// and the (now stale) snapshot is kept. This is a deliberate availability-over-strictness choice —
/// failing closed would force a full genesis re-replay on every transient probe hiccup. The window
/// closes on the next run whose probe succeeds.
pub(super) fn snapshot_stale_by_event_tip(
    saved_last_seen_event_id: i64,
    live_max_event_id: Option<i64>,
) -> bool {
    live_max_event_id.is_some_and(|live| live > 0 && saved_last_seen_event_id > live)
}

#[cfg(test)]
mod tests {
    use super::snapshot_fresh_by_http_tip;

    #[test]
    fn stale_when_saved_cursor_past_live_tip() {
        use super::snapshot_stale_by_event_tip;
        // Saved cursor far beyond the live tip → chain reset, snapshot is stale.
        assert!(snapshot_stale_by_event_tip(194177, Some(4569)));
        // Cursor exactly at the tip → still valid (at tip, not past it).
        assert!(!snapshot_stale_by_event_tip(4569, Some(4569)));
        // Cursor behind the tip → valid; a normal catch-up handles it.
        assert!(!snapshot_stale_by_event_tip(4000, Some(4569)));
        // Live tip undetermined (probe failed / empty stream) → keep the snapshot.
        assert!(!snapshot_stale_by_event_tip(194177, None));
        // Non-positive live tip is not a usable signal → keep the snapshot.
        assert!(!snapshot_stale_by_event_tip(194177, Some(0)));
    }

    #[test]
    fn http_tip_fresh_only_when_complete_and_height_matches() {
        // Event tip undetermined + heights match + snapshot complete → trust the snapshot.
        assert!(snapshot_fresh_by_http_tip(Some(100), 100, true, None));
        // Height differs → catch up.
        assert!(!snapshot_fresh_by_http_tip(Some(101), 100, true, None));
        // Snapshot incomplete → catch up.
        assert!(!snapshot_fresh_by_http_tip(Some(100), 100, false, None));
        // No saved height (legacy snapshot) → catch up once.
        assert!(!snapshot_fresh_by_http_tip(Some(0), 0, true, None));
        // HTTP height fetch failed → catch up.
        assert!(!snapshot_fresh_by_http_tip(None, 100, true, None));
        // Event tip WAS observed → the event-tip fast path is authoritative; never trust the
        // coarser HTTP height match (it misses events that advanced with no block-height change).
        assert!(!snapshot_fresh_by_http_tip(Some(100), 100, true, Some(42)));
    }
}
