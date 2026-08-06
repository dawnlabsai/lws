//! Shielded (Zswap) balance + wallet sync orchestration.
//!
//! One [`sync_wallet`] is the single shielded sync for both the balance and the signing paths:
//! subscribe to `zswapLedgerEvents` and replay them locally into the full spendable
//! [`ShieldedWalletState`] — the viewing key is never sent to the indexer. Balances are derived
//! from that state via [`balances_from_wallet`], so consumers read balances or build spends from
//! the same synced wallet.

mod cache;
mod vk_hidden;

use midnight_coin_structure::coin;
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;
use ows_signer::chains::MidnightCryptoProvider;
use std::collections::BTreeMap;

use crate::cache_io::SyncCacheScope;
use crate::ShieldedBalances;

/// Synced shielded wallet state (Merkle tree + spendable qualified coins) used to derive balances
/// and to build Zswap spends (e.g. DApp Connector `makeIntent`).
pub struct ShieldedWalletState {
    pub zswap: ZswapLocalState<InMemoryDB>,
}

/// Hex token-type id (`0x…`) for a shielded coin — the key balances are summed under.
fn token_type_hex(ci: &coin::Info) -> String {
    let t = ci.type_.into_inner();
    format!("0x{}", hex::encode(t.0))
}

/// Per-token balances summed from a synced wallet's qualified coins — projected from the spendable
/// state, never stored.
fn balances_from_wallet(state: &ZswapLocalState<InMemoryDB>) -> ShieldedBalances {
    let mut balances: ShieldedBalances = BTreeMap::new();
    for (_nul, qci) in state.coins.iter() {
        let ci = coin::Info::from(&*qci);
        *balances.entry(token_type_hex(&ci)).or_insert(0) += ci.value;
    }
    balances
}

/// The one shielded wallet sync — subscribe to `zswapLedgerEvents`, replay into the spendable
/// [`ShieldedWalletState`], and return it; the caller derives balances or builds spends from it.
pub async fn sync_wallet(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedWalletState, std::io::Error> {
    vk_hidden::sync_wallet(indexer_url, crypto_provider, scope, current_block_height).await
}

/// Shielded balances for `ows fund balance` — derived from the synced wallet state.
pub async fn get_shielded_balances_for_display(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedBalances, std::io::Error> {
    let wallet = sync_wallet(indexer_url, crypto_provider, scope, current_block_height).await?;
    Ok(balances_from_wallet(&wallet.zswap))
}
