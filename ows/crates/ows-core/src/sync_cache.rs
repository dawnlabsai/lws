//! Generic on-disk snapshot store: persist per-wallet / per-chain data between
//! CLI invocations.
//!
//! This is the chain-agnostic mechanism — scope, fingerprinting, path layout,
//! and versioned JSON load/save. A chain wraps it with its own environment
//! knobs and directory naming (see `ows-midnight`'s `cache_io` for the canonical
//! wrapper).

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Scope for a chain's disk cache — isolates snapshots per wallet and per network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncCacheScope {
    /// Wallet UUID from the encrypted wallet file; isolates cache per wallet.
    pub wallet_id: Option<String>,
    /// Explicit vault root (e.g. `~/.ows` or a custom `--vault-path`).
    pub vault_path: Option<PathBuf>,
    /// CAIP-2 chain id (`midnight:preview`, …); isolates cache per network.
    pub chain_id: Option<String>,
}

impl SyncCacheScope {
    pub fn for_wallet(wallet_id: impl Into<String>, vault_path: Option<&Path>) -> Self {
        Self {
            wallet_id: Some(wallet_id.into()),
            vault_path: vault_path.map(Path::to_path_buf),
            chain_id: None,
        }
    }

    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }
}

/// Lowercase + trim a chain id for stable hashing and comparison.
pub fn normalize_chain_id(chain_id: &str) -> String {
    chain_id.trim().to_ascii_lowercase()
}

/// `chain_id` persisted in snapshot JSON (empty when the scope has none).
pub fn snapshot_chain_id(scope: &SyncCacheScope) -> String {
    scope
        .chain_id
        .as_deref()
        .map(normalize_chain_id)
        .unwrap_or_default()
}

/// True when an on-disk snapshot's `chain_id` matches the active scope.
pub fn snapshot_chain_matches(scope: &SyncCacheScope, snap_chain_id: &str) -> bool {
    match scope.chain_id.as_deref() {
        Some(expected) => snap_chain_id.eq_ignore_ascii_case(expected),
        None => snap_chain_id.is_empty(),
    }
}

/// `$HOME` (or `$USERPROFILE` on Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// 16-byte hex fingerprint of `parts` joined with `|` — stable across runs.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"|");
        }
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..16])
}

/// Snapshot file path under `root`, isolated by `scope.wallet_id` when present.
pub fn snapshot_file_path(root: &Path, scope: &SyncCacheScope, hashed_name: &str) -> PathBuf {
    match &scope.wallet_id {
        Some(wid) => root.join(wid).join(format!("{hashed_name}.json")),
        None => root.join(format!("{hashed_name}.json")),
    }
}

/// Best-effort JSON load. Returns `None` on any I/O or decode error.
pub fn try_load<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Load a versioned snapshot; rejects `version == 0` or `version > max_version`.
///
/// Reads the file once so the version check and the deserialized value always
/// come from the same bytes.
pub fn try_load_versioned<T: DeserializeOwned>(path: &Path, max_version: u32) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("version")?
        .as_u64()? as u32;
    if version == 0 || version > max_version {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort pretty-JSON save. Errors are silently ignored.
///
/// A snapshot can hold privacy-sensitive wallet state (qualified coins, openings, nullifiers), so
/// on Unix the file is written owner-only (`0o600`) and any parent dirs it creates are `0o700`.
pub fn try_save<T: Serialize>(path: &Path, snap: &T) {
    if let Some(parent) = path.parent() {
        let _ = create_dir_all_private(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(snap) {
        let _ = write_private(path, &bytes);
    }
}

/// Create `dir` (and missing parents) owner-only on Unix; plain recursive create elsewhere.
fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `bytes` to `path` owner-only (`0o600`) on Unix, tightening a pre-existing file too; a
/// plain write elsewhere.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // `mode` only applies when creating; tighten an existing, looser-permissioned file too.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn wallet_scoped_path_includes_wallet_id() {
        let scope = SyncCacheScope::for_wallet("wallet-abc", None);
        let p = snapshot_file_path(Path::new("/cache"), &scope, "deadbeef");
        assert!(p.to_string_lossy().contains("wallet-abc"));
    }

    #[test]
    fn fingerprint_is_order_and_separator_sensitive() {
        assert_ne!(fingerprint(&["a", "b"]), fingerprint(&["b", "a"]));
        assert_ne!(fingerprint(&["a", "b"]), fingerprint(&["ab"]));
    }

    #[test]
    fn chain_match_semantics() {
        let scope = SyncCacheScope::default().with_chain_id("midnight:preview");
        assert!(snapshot_chain_matches(&scope, "midnight:preview"));
        assert!(!snapshot_chain_matches(&scope, "midnight:mainnet"));
        assert!(snapshot_chain_matches(&SyncCacheScope::default(), ""));
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Versioned {
        version: u32,
        value: u32,
    }

    #[test]
    fn versioned_load_round_trip_and_gating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");

        try_save(
            &path,
            &Versioned {
                version: 2,
                value: 7,
            },
        );
        assert_eq!(
            try_load_versioned::<Versioned>(&path, 3),
            Some(Versioned {
                version: 2,
                value: 7
            })
        );
        // version above the supported max is rejected
        assert_eq!(try_load_versioned::<Versioned>(&path, 1), None);

        try_save(
            &path,
            &Versioned {
                version: 0,
                value: 9,
            },
        );
        assert_eq!(try_load_versioned::<Versioned>(&path, 3), None);
    }

    #[cfg(unix)]
    #[test]
    fn saved_snapshot_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("wallet-id");
        let path = nested.join("snap.json");

        try_save(
            &path,
            &Versioned {
                version: 1,
                value: 1,
            },
        );

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "snapshot file must be owner-only");
        let dir_mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "created cache dir must be owner-only");
    }
}
