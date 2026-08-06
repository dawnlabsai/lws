//! Midnight-specific wrapper around the generic [`ows_core::sync_cache`] store:
//! adds Midnight's `{vault}/chains/midnight/cache/{subdir}` directory layout and
//! the single disk-cache switch on top of the chain-agnostic primitives.
//!
//! ## Layout
//!
//! When [`SyncCacheScope::wallet_id`] is set (typical for CLI / library wallet flows):
//!
//! `{vault}/chains/midnight/cache/{unshielded|shielded|dust}/{wallet_id}/<hash>.json`
//!
//! `<hash>` covers `(indexer_url, chain_id, stream-specific key)` so preview / preprod /
//! mainnet never share a snapshot even when the key material matches.
//!
//! Without a wallet id, snapshots omit the `{wallet_id}/` segment. `{vault}` is the
//! configured vault path (`config.vault_path`, default `~/.ows`).
//!
//! ## Environment
//!
//! | Variable | Effect |
//! |----------|--------|
//! | `OWS_MIDNIGHT_SYNC_CACHE=0` | Disable disk snapshots |

use std::path::PathBuf;

use ows_core::sync_cache;

pub use ows_core::sync_cache::{
    snapshot_chain_id, snapshot_chain_matches, try_load_versioned, try_save, SyncCacheScope,
};

/// Normalize an indexer URL (trim trailing slash, lowercase) for stable hashing.
pub fn normalize_indexer_base(indexer_url: &str) -> String {
    indexer_url.trim_end_matches('/').to_lowercase()
}

/// Fingerprint for `(indexer_url, chain_id)` used to key a snapshot's sync site.
pub fn sync_site_fingerprint(indexer_url: &str, scope: &SyncCacheScope) -> String {
    let base = normalize_indexer_base(indexer_url);
    match scope.chain_id.as_deref() {
        Some(chain_id) => {
            sync_cache::fingerprint(&[&base, &sync_cache::normalize_chain_id(chain_id)])
        }
        None => sync_cache::fingerprint(&[&base]),
    }
}

/// Validate that a loaded snapshot belongs to the same indexer site + chain id.
pub fn snapshot_site_matches(
    scope: &SyncCacheScope,
    snap_chain_id: &str,
    site_fp: &str,
    snap_site_fp: &str,
) -> bool {
    site_fp == snap_site_fp && snapshot_chain_matches(scope, snap_chain_id)
}

fn cache_disabled() -> bool {
    std::env::var("OWS_MIDNIGHT_SYNC_CACHE")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// Default vault root: the scope's explicit vault path, else `~/.ows`.
fn vault_root(scope: &SyncCacheScope) -> Option<PathBuf> {
    if let Some(v) = &scope.vault_path {
        return Some(v.clone());
    }
    sync_cache::home_dir().map(|h| h.join(".ows"))
}

/// Cache root directory for `subdir` (e.g. `"unshielded"`): `{vault}/chains/midnight/cache/{subdir}`.
pub fn cache_root_dir(subdir: &str, scope: &SyncCacheScope) -> Option<PathBuf> {
    if cache_disabled() {
        return None;
    }
    let vault = vault_root(scope)?;
    Some(
        vault
            .join("chains")
            .join("midnight")
            .join("cache")
            .join(subdir),
    )
}

/// Directory holding the shared Midnight ZK proving keys (circuit prover/verifier keys + IR):
/// `{vault}/chains/midnight/proving-keys`. Vault-rooted like the snapshots but not per-scope — the
/// keys are circuit assets shared across wallets, and not disabled by `OWS_MIDNIGHT_SYNC_CACHE`.
pub fn proving_keys_dir(scope: &SyncCacheScope) -> Option<PathBuf> {
    vault_root(scope).map(|v| v.join("chains").join("midnight").join("proving-keys"))
}

/// File path for the snapshot keyed by `(indexer_url, chain_id, key)` under `subdir`.
pub fn snapshot_path(
    subdir: &str,
    indexer_url: &str,
    key: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    let root = cache_root_dir(subdir, scope)?;
    let base = normalize_indexer_base(indexer_url);
    let hashed = match scope.chain_id.as_deref() {
        Some(chain_id) => {
            sync_cache::fingerprint(&[&base, &sync_cache::normalize_chain_id(chain_id), key])
        }
        None => sync_cache::fingerprint(&[&base, key]),
    };
    Some(sync_cache::snapshot_file_path(&root, scope, &hashed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_scoped_path_includes_wallet_id() {
        let scope = SyncCacheScope::for_wallet("wallet-abc", None);
        let p = snapshot_path(
            "unshielded",
            "https://indexer.example/graphql",
            "addr1",
            &scope,
        )
        .unwrap();
        assert!(p.to_string_lossy().contains("wallet-abc"));
    }

    #[test]
    fn chain_id_produces_distinct_snapshot_paths() {
        let base = SyncCacheScope::for_wallet("wallet-abc", None);
        let preview = base.clone().with_chain_id("midnight:preview");
        let preprod = base.with_chain_id("midnight:preprod");
        let url = "https://indexer.example/graphql";
        let key = "same-address";
        let p_preview = snapshot_path("unshielded", url, key, &preview).unwrap();
        let p_preprod = snapshot_path("unshielded", url, key, &preprod).unwrap();
        assert_ne!(p_preview, p_preprod);
    }

    #[test]
    fn sync_site_fingerprint_includes_chain_id() {
        let scope = SyncCacheScope::default().with_chain_id("midnight:preview");
        let fp = sync_site_fingerprint("https://indexer.example/graphql", &scope);
        let fp_default = sync_site_fingerprint(
            "https://indexer.example/graphql",
            &SyncCacheScope::default(),
        );
        assert_ne!(fp, fp_default);
    }
}
