//! Midnight wallet helpers used by the balance-display path.

use ows_core::Config;

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
