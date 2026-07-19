//! Disk snapshot for the dust ledger state: the tagged-serialized `DustLocalState` plus the
//! indexer cursor, persisted through the generic [`ows_core::sync_cache`] store via `cache_io`.
//!
//! Stores source state (the ledger state + cursor), never a derived balance — the balance is
//! recomputed from the state on read.

use super::cache_io::{self, SyncCacheScope};
use midnight_ledger::dust::DustLocalState;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(super) const SNAPSHOT_VERSION: u32 = 1;
const CACHE_SUBDIR: &str = "dust";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DustSyncSnapshot {
    pub version: u32,
    /// Fingerprint of `(indexer_url, chain_id)`; guards against reusing a snapshot from a
    /// different indexer.
    pub indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id; guards against reusing a snapshot from a different network.
    pub chain_id: String,
    /// Hex dust public key; guards against reusing a snapshot for a different dust key.
    pub dust_public_key_hex: String,
    /// Highest dust ledger event id already folded into `state_hex`.
    pub last_seen_event_id: i64,
    /// Chain tip `maxId` when saved; lets a resume at the saved tip settle without new events.
    pub max_id_when_saved: i64,
    /// Indexer block height when the snapshot was written; gates the HTTP-tip fast path.
    #[serde(default)]
    pub block_height_when_saved: i64,
    /// Tagged-serialized `DustLocalState<InMemoryDB>`.
    pub state_hex: String,
}

pub(super) fn snapshot_path(
    indexer_url: &str,
    dust_pk_hex: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, dust_pk_hex, scope)
}

pub(super) fn try_load_snapshot(path: &Path) -> Option<DustSyncSnapshot> {
    cache_io::try_load_versioned(path, SNAPSHOT_VERSION)
}

pub(super) fn decode_state(hex_s: &str) -> Result<DustLocalState<InMemoryDB>, std::io::Error> {
    let bytes = hex::decode(hex_s.strip_prefix("0x").unwrap_or(hex_s))
        .map_err(|e| std::io::Error::other(format!("invalid dust state hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("failed to decode dust state: {e}")))
}

pub(super) fn encode_state(state: &DustLocalState<InMemoryDB>) -> Result<String, std::io::Error> {
    let mut out = Vec::new();
    tagged_serialize(state, &mut out)
        .map_err(|e| std::io::Error::other(format!("failed to encode dust state: {e}")))?;
    Ok(hex::encode(out))
}
