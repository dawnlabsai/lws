//! Disk snapshot for Midnight shielded (Zswap) balance sync — the VK-hidden `zswapLedgerEvents`
//! replay path, persisted through the generic [`ows_core::sync_cache`] store via `cache_io`.
//!
//! Stores resumable source state (the full spendable `ZswapLocalState` + indexer cursor), never a
//! derived balance — the per-token balance is recomputed from the synced state on read. The
//! zswap-state codec and seed fingerprint live in the shared [`super::super::cache`] module.

use crate::cache_io::{self, SyncCacheScope};
use serde::{Deserialize, Serialize};
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
    /// Highest zswap ledger event id already folded into `zswap_state_hex`.
    pub last_seen_event_id: i64,
    /// Chain tip `maxId` when saved; lets a resume at the saved tip settle without new events.
    pub max_id_when_saved: i64,
    /// Indexer block height when the snapshot was written; gates the HTTP-tip fast path.
    #[serde(default)]
    pub block_height_when_saved: i64,
    /// Tagged-serialized full spendable `ZswapLocalState` (Merkle tree + qualified coins) after
    /// the replay — the resumable source state. Spending needs each coin's Merkle path, and the
    /// per-token balance is recomputed from this state on read (never persisted as a balance).
    pub zswap_state_hex: String,
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
