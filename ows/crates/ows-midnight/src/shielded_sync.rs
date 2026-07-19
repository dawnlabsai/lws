//! Shielded (Zswap) balance sync orchestration.
//!
//! The shielded balance comes from a VK-free `zswapLedgerEvents` replay — no viewing key is ever
//! sent to the indexer.

use ows_signer::chains::MidnightCryptoProvider;

use super::cache_io::SyncCacheScope;
use super::zswap_ledger_sync;
use super::ShieldedBalances;

/// Shielded balances for `ows fund balance`, from the VK-free `zswapLedgerEvents` sync. The
/// shielded keys stay inside `crypto_provider`, which does the key-bearing owned-coin detection.
pub async fn get_shielded_balances_for_display(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
) -> Result<ShieldedBalances, std::io::Error> {
    zswap_ledger_sync::fetch_balances(indexer_url, crypto_provider, scope).await
}
