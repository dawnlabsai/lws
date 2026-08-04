//! Cardano RPC provider abstraction.
//!
//! Cardano needs an RPC provider for three operations: broadcasting a signed
//! transaction, fetching UTxOs for a set of transaction inputs, and fetching an
//! address' token balances. This module defines a provider-agnostic
//! [`CardanoRpcProvider`] trait over those operations and
//! [`resolve_cardano_provider`], which selects the concrete provider from an RPC
//! URL. Provider-specific code lives in the [`koios`] and [`blockfrost`]
//! submodules.
//!
//! The trait is synchronous (all call sites are effectively sync — the balance
//! path bridges via `spawn_blocking`) and object-safe, so the resolver can hand
//! back a `Box<dyn CardanoRpcProvider>`.

mod blockfrost;
mod koios;

pub use blockfrost::BlockfrostProvider;
pub use koios::KoiosProvider;

use crate::TokenBalance;
use std::{collections::BTreeMap, time::Duration};

/// Lovelace-per-ADA exponent (1 ADA = 10^6 lovelace).
const ADA_DECIMALS: u32 = 6;
const REQUESTS_TIMEOUT: Duration = Duration::from_secs(45);

/// Errors returned by a [`CardanoRpcProvider`]. Consumers map these into their
/// own crate-local error types.
#[derive(Debug, thiserror::Error)]
pub enum CardanoRpcError {
    /// Transport-level failure (DNS, TLS, timeout, connection).
    #[error("HTTP error: {0}")]
    Http(String),
    /// The response could not be decoded into the expected shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The provider returned an error status or a semantically invalid response.
    #[error("RPC error: {0}")]
    Rpc(String),
}

/// Cardano RPC operations, independent of the concrete provider (Koios, Blockfrost, …).
pub trait CardanoRpcProvider: Send + Sync {
    /// Submit a signed transaction (CBOR bytes). Returns the transaction hash.
    fn broadcast_tx(&self, tx_cbor: &[u8]) -> Result<String, CardanoRpcError>;

    /// Fetch the CBOR-encoded transactions for a set of transaction hashes.
    /// NOTE: The result can be partial if some transactions are not found.
    fn fetch_txs_cbor(
        &self,
        tx_hashes: &[String],
    ) -> Result<BTreeMap<String, String>, CardanoRpcError>;

    /// Fetch the token balances (ADA + native assets) for an address.
    fn get_balances(&self, address: &str) -> Result<Vec<TokenBalance>, CardanoRpcError>;
}

/// Environment variable holding the Blockfrost `project_id` (API key).
pub const BLOCKFROST_PROJECT_ID_ENV: &str = "BLOCKFROST_PROJECT_ID";

const BLOCKFROST_URL_PREFIX: &str = "blockfrost|";
const KOIOS_URL_PREFIX: &str = "koios|";

fn is_blockfrost_url(url: &str) -> bool {
    url.starts_with(BLOCKFROST_URL_PREFIX) || url.contains("blockfrost.io/api")
}

fn is_koios_url(url: &str) -> bool {
    url.starts_with(KOIOS_URL_PREFIX) || url.contains("koios.rest/api")
}

fn strip_provider_prefix(url: &str) -> &str {
    url.strip_prefix(BLOCKFROST_URL_PREFIX)
        .or_else(|| url.strip_prefix(KOIOS_URL_PREFIX))
        .unwrap_or(url)
}

/// Select a Cardano RPC provider from its URL.
///
/// Blockfrost is selected when the URL contains `blockfrost.io/api` or is
/// prefixed with `blockfrost|` (reading the `project_id` from
/// [`BLOCKFROST_PROJECT_ID_ENV`]). Koios is selected when the URL contains
/// `koios.rest/api` or is prefixed with `koios|`. Any other URL is rejected.
pub fn resolve_cardano_provider(url: &str) -> Result<Box<dyn CardanoRpcProvider>, CardanoRpcError> {
    if is_blockfrost_url(url) {
        let project_id = std::env::var(BLOCKFROST_PROJECT_ID_ENV).map_err(|_| {
            CardanoRpcError::Rpc(format!(
                "{BLOCKFROST_PROJECT_ID_ENV} environment variable is required for Blockfrost RPC"
            ))
        })?;
        Ok(Box::new(BlockfrostProvider::new(
            strip_provider_prefix(url),
            project_id,
        )))
    } else if is_koios_url(url) {
        Ok(Box::new(KoiosProvider::new(strip_provider_prefix(url))))
    } else {
        Err(CardanoRpcError::Rpc(format!(
            "unsupported Cardano RPC URL: {url}"
        )))
    }
}

/// Shared blocking HTTP client used by the providers.
fn blocking_client() -> Result<reqwest::blocking::Client, CardanoRpcError> {
    reqwest::blocking::Client::builder()
        .timeout(REQUESTS_TIMEOUT)
        .build()
        .map_err(|e| CardanoRpcError::Http(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_to_koios() {
        // Non-blockfrost URL resolves without needing any env var.
        let provider = resolve_cardano_provider("https://api.koios.rest/api/v1").unwrap();
        // Smoke: the boxed provider is usable for the no-op empty utxo case.
        assert_eq!(provider.fetch_txs_cbor(&[]).unwrap(), BTreeMap::new());
    }
}
