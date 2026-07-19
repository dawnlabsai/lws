//! Disk snapshot for Midnight shielded (Zswap) balance sync — the `zswapLedgerEvents` replay
//! path (Mode B), persisted through the generic [`ows_core::sync_cache`] store via `cache_io`.
//!
//! Stores source state (the unspent owned coins + indexer cursor), never a derived balance —
//! the per-token balance is recomputed from the coins on read.

use super::cache_io::{self, SyncCacheScope};
use midnight_coin_structure::coin;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) const SNAPSHOT_VERSION: u32 = 1;
const CACHE_SUBDIR: &str = "shielded";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ShieldedSyncSnapshot {
    pub version: u32,
    /// Fingerprint of `(indexer_url, chain_id)`; guards against reusing a snapshot from a
    /// different indexer.
    pub indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id; guards against reusing a snapshot from a different network.
    pub chain_id: String,
    /// Fingerprint of the zswap seed; guards against reusing a snapshot for a different key.
    pub zswap_key_fingerprint: String,
    /// Highest zswap ledger event id already folded into `owned_coins`.
    pub last_seen_event_id: i64,
    /// Chain tip `maxId` when saved; lets a resume at the saved tip settle without new events.
    pub max_id_when_saved: i64,
    /// Indexer block height when the snapshot was written; gates the HTTP-tip fast path.
    #[serde(default)]
    pub block_height_when_saved: i64,
    /// Unspent owned coins after the replay — source state, not a balance.
    pub owned_coins: Vec<ZswapOwnedCoinRecord>,
}

/// One unspent owned coin: the tagged-serialized nullifier (map key) and coin info (map value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ZswapOwnedCoinRecord {
    pub nullifier_hex: String,
    pub coin_hex: String,
}

pub(super) fn snapshot_path(
    indexer_url: &str,
    key_fp: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, key_fp, scope)
}

pub(super) fn try_load_snapshot(path: &Path) -> Option<ShieldedSyncSnapshot> {
    cache_io::try_load_versioned(path, SNAPSHOT_VERSION)
}

pub(super) fn encode_owned_coins(
    owned: &BTreeMap<coin::Nullifier, coin::Info>,
) -> Result<Vec<ZswapOwnedCoinRecord>, std::io::Error> {
    let mut out = Vec::with_capacity(owned.len());
    for (nul, ci) in owned {
        let mut nul_b = Vec::new();
        let mut ci_b = Vec::new();
        tagged_serialize(nul, &mut nul_b).map_err(|e| std::io::Error::other(e.to_string()))?;
        tagged_serialize(ci, &mut ci_b).map_err(|e| std::io::Error::other(e.to_string()))?;
        out.push(ZswapOwnedCoinRecord {
            nullifier_hex: hex::encode(nul_b),
            coin_hex: hex::encode(ci_b),
        });
    }
    Ok(out)
}

pub(super) fn decode_owned_coins(
    records: &[ZswapOwnedCoinRecord],
) -> Result<BTreeMap<coin::Nullifier, coin::Info>, std::io::Error> {
    let mut owned = BTreeMap::new();
    for rec in records {
        let nul_b = hex::decode(
            rec.nullifier_hex
                .strip_prefix("0x")
                .unwrap_or(&rec.nullifier_hex),
        )
        .map_err(|e| std::io::Error::other(format!("invalid nullifier hex: {e}")))?;
        let ci_b = hex::decode(rec.coin_hex.strip_prefix("0x").unwrap_or(&rec.coin_hex))
            .map_err(|e| std::io::Error::other(format!("invalid coin hex: {e}")))?;
        let mut nul_r: &[u8] = &nul_b;
        let mut ci_r: &[u8] = &ci_b;
        let nul: coin::Nullifier = tagged_deserialize(&mut nul_r)
            .map_err(|e| std::io::Error::other(format!("decode nullifier: {e}")))?;
        let ci: coin::Info = tagged_deserialize(&mut ci_r)
            .map_err(|e| std::io::Error::other(format!("decode coin info: {e}")))?;
        owned.insert(nul, ci);
    }
    Ok(owned)
}
