//! Shielded (Zswap) balance sync orchestration.
//!
//! The shielded balance comes from a full VK-free sync: subscribe to `zswapLedgerEvents`, replay
//! them locally, and derive balances from owned coins — no viewing key is ever sent to the
//! indexer.

use ows_signer::chains::MidnightCryptoProvider;

use super::cache_io::SyncCacheScope;
use super::zswap_ledger_sync;
use super::ShieldedBalances;

/// Shielded balances for `ows fund balance`, from the VK-free `zswapLedgerEvents` full sync. The
/// shielded keys stay inside `crypto_provider`, which does the key-bearing owned-coin detection.
pub async fn get_shielded_balances_for_display(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedBalances, std::io::Error> {
    let seed_fp = crypto_provider
        .shielded_key_fingerprint()
        .map(|fp| hex::encode(&fp[..16]))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    zswap_ledger_sync::fetch_balances(
        indexer_url,
        crypto_provider,
        scope,
        &seed_fp,
        current_block_height,
    )
    .await
}
