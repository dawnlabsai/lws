//! Zswap-ledger event replay path (Mode B) for shielded balance sync.
//!
//! Stub at this commit; the real `zswapLedgerEvents` subscription + `ZswapLocalState` replay
//! land in a follow-up. No viewing key is ever sent to the indexer in this path — owned coins
//! are identified locally by the crypto provider using the coin secret key it holds.

use ows_signer::chains::MidnightCryptoProvider;

use super::cache_io::SyncCacheScope;
use super::ShieldedBalances;

/// Zswap-ledger-events shielded balance fetch — VK-free path (Mode B).
///
/// Stub: returns an empty `ShieldedBalances`. The real replay (subscription to
/// `zswapLedgerEvents`, `tagged_deserialize<Event>`, local owned-coin detection via the provider's
/// `detect_shielded_output`) lands in a follow-up commit; this stub matches the `fetch_balances`
/// signature shared with the viewing-key path.
pub(super) async fn fetch_balances(
    _indexer_url: &str,
    _crypto_provider: &MidnightCryptoProvider,
    _scope: &SyncCacheScope,
) -> Result<ShieldedBalances, std::io::Error> {
    Ok(ShieldedBalances::default())
}
