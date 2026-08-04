//! Sync-stream identifiers and timeout tuning for Midnight indexer sync.
//!
//! Each timeout ships a default suited to a healthy indexer, plus an environment override for the
//! cases a fixed default cannot serve: a cold wallet replaying a long history over a slow link, or
//! an indexer that is degraded but still making progress.
//!
//! Overriding is safe in both directions. A longer budget only gives a sync more room to finish. A
//! shorter one surfaces as a stall error from the unshielded and shielded streams, or as a missing
//! dust section — never as a partial balance reported as if it were complete.
//!
//! | Variable | Default (seconds) |
//! |----------|-------------------|
//! | `OWS_MIDNIGHT_WS_IDLE_TIMEOUT_SECS` | 90 |
//! | `OWS_MIDNIGHT_STALL_TIMEOUT_SECS` | 120 |
//! | `OWS_MIDNIGHT_INDEXER_HTTP_TIMEOUT_SECS` | 30 |
//! | `OWS_MIDNIGHT_WS_CONNECT_TIMEOUT_SECS` | 30 |

use std::time::Duration;

/// Indexer sync stream (unshielded / shielded / dust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStream {
    Unshielded,
    Shielded,
    Dust,
}

const WS_IDLE_TIMEOUT_SECS: u64 = 90;
const STALL_TIMEOUT_SECS: u64 = 120;
const INDEXER_HTTP_TIMEOUT_SECS: u64 = 30;
const WS_CONNECT_TIMEOUT_SECS: u64 = 30;

const WS_IDLE_TIMEOUT_VAR: &str = "OWS_MIDNIGHT_WS_IDLE_TIMEOUT_SECS";
const STALL_TIMEOUT_VAR: &str = "OWS_MIDNIGHT_STALL_TIMEOUT_SECS";
const INDEXER_HTTP_TIMEOUT_VAR: &str = "OWS_MIDNIGHT_INDEXER_HTTP_TIMEOUT_SECS";
const WS_CONNECT_TIMEOUT_VAR: &str = "OWS_MIDNIGHT_WS_CONNECT_TIMEOUT_SECS";

/// A timeout override is a positive whole number of seconds; anything else is rejected.
///
/// Zero is rejected rather than honored: it would expire every budget instantly, which reads as a
/// broken sync rather than as the tuning the caller intended.
fn parse_timeout_override(raw: &str) -> Option<u64> {
    match raw.trim().parse::<u64>() {
        Ok(secs) if secs > 0 => Some(secs),
        _ => None,
    }
}

/// Resolve `var` to a duration, falling back to `default_secs`.
///
/// A malformed value warns and falls back instead of failing the command — a mistyped tuning knob
/// should not block a balance read. It is not silent, because a caller who believes they raised a
/// budget and did not would otherwise misread the resulting stall.
fn timeout_from_env(var: &str, default_secs: u64) -> Duration {
    let Ok(raw) = std::env::var(var) else {
        return Duration::from_secs(default_secs);
    };
    match parse_timeout_override(&raw) {
        Some(secs) => Duration::from_secs(secs),
        None => {
            eprintln!(
                "[ows-midnight] ignoring {var}={raw:?} (expected a positive number of seconds); \
                 using {default_secs}s"
            );
            Duration::from_secs(default_secs)
        }
    }
}

pub fn ws_idle_timeout(_stream: SyncStream) -> Duration {
    timeout_from_env(WS_IDLE_TIMEOUT_VAR, WS_IDLE_TIMEOUT_SECS)
}

pub fn stall_timeout(_stream: SyncStream) -> Duration {
    timeout_from_env(STALL_TIMEOUT_VAR, STALL_TIMEOUT_SECS)
}

/// Per-request timeout for Midnight indexer GraphQL HTTP calls.
pub fn indexer_http_timeout() -> Duration {
    timeout_from_env(INDEXER_HTTP_TIMEOUT_VAR, INDEXER_HTTP_TIMEOUT_SECS)
}

/// Timeout for establishing a Midnight indexer WebSocket connection.
pub fn ws_connect_timeout() -> Duration {
    timeout_from_env(WS_CONNECT_TIMEOUT_VAR, WS_CONNECT_TIMEOUT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_seconds_are_accepted() {
        assert_eq!(parse_timeout_override("300"), Some(300));
        assert_eq!(parse_timeout_override("  600 "), Some(600));
    }

    #[test]
    fn zero_and_malformed_values_are_rejected() {
        for raw in ["0", "", "   ", "-5", "90s", "1.5", "abc"] {
            assert_eq!(parse_timeout_override(raw), None, "raw={raw:?}");
        }
    }

    #[test]
    fn unset_var_falls_back_to_the_default() {
        let unset = "OWS_TEST_TIMEOUT_VAR_THAT_IS_NEVER_SET";
        assert_eq!(timeout_from_env(unset, 42), Duration::from_secs(42));
    }

    /// Pins the defaults against the table in this module's docs. Asserted on the constants rather
    /// than through the accessors, which would read whatever the developer has exported.
    #[test]
    fn defaults_are_the_documented_budgets() {
        assert_eq!(WS_IDLE_TIMEOUT_SECS, 90);
        assert_eq!(STALL_TIMEOUT_SECS, 120);
        assert_eq!(INDEXER_HTTP_TIMEOUT_SECS, 30);
        assert_eq!(WS_CONNECT_TIMEOUT_SECS, 30);
    }

    /// The stall budget must exceed the idle budget, or a stream would be torn down for idleness
    /// before the stall check it is meant to trigger could ever fire.
    #[test]
    fn stall_budget_outlasts_the_idle_budget() {
        assert!(STALL_TIMEOUT_SECS > WS_IDLE_TIMEOUT_SECS);
    }
}
