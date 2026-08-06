//! Midnight wallet helpers used by the balance-display path: indexer URL and
//! sync-cache scope resolution.

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Config;

use super::cache_io::SyncCacheScope;
use super::wallet_sync::unshielded::UnshieldedUtxo;

fn invalid_input(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Resolve the configured Midnight indexer URL for a CAIP-2 chain id.
pub fn resolve_indexer_url(chain_id: &str) -> Result<String, std::io::Error> {
    Config::load_or_default()
        .rpc_url(chain_id)
        .map(str::to_string)
        .ok_or_else(|| {
            invalid_input(format!(
                "no Midnight indexer URL configured for {chain_id} (set `rpc.{chain_id}` in config)"
            ))
        })
}

/// Build a sync-cache scope co-located with the wallet's vault entry.
///
/// The caller has already resolved the wallet id (it loaded the wallet to read
/// its accounts), so the scope is always per-wallet isolated.
pub fn sync_scope_for_wallet(
    wallet_id: &str,
    chain_id: Option<&str>,
    vault_path: Option<&Path>,
) -> SyncCacheScope {
    let mut scope = SyncCacheScope::for_wallet(wallet_id, vault_path);
    if let Some(cid) = chain_id {
        scope = scope.with_chain_id(cid);
    }
    scope
}

/// Sum unshielded UTXO values per token type.
pub fn sum_utxos_by_token(utxos: &[UnshieldedUtxo]) -> BTreeMap<String, u128> {
    let mut totals: BTreeMap<String, u128> = BTreeMap::new();
    for u in utxos {
        *totals.entry(u.token_type.clone()).or_insert(0) += u.value;
    }
    totals
}
