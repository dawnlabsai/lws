use crate::error::{PayError, PayErrorCode};
use crate::types::TokenBalance;
use ows_core::{resolve_cardano_provider, CardanoRpcError};

/// Fetch Cardano token balances for an address via the configured RPC provider.
///
/// The provider API is synchronous (blocking HTTP); we run it on a blocking
/// thread so this `async fn` doesn't stall the reactor and its callers stay
/// unchanged.
pub(crate) async fn get_cardano_balances(
    wallet_address: &str,
    rpc_url: &str,
) -> Result<Vec<TokenBalance>, PayError> {
    let address = wallet_address.to_string();
    let rpc_url = rpc_url.to_string();

    tokio::task::spawn_blocking(move || {
        let provider = resolve_cardano_provider(&rpc_url)
            .map_err(|e| PayError::new(PayErrorCode::InvalidInput, e.to_string()))?;
        provider.get_balances(&address).map_err(|e| {
            let code = match e {
                CardanoRpcError::Http(_) => PayErrorCode::HttpTransport,
                CardanoRpcError::Decode(_) => PayErrorCode::InvalidData,
                CardanoRpcError::Rpc(_) => PayErrorCode::HttpStatus,
            };
            PayError::new(code, e.to_string())
        })
    })
    .await
    .map_err(|e| PayError::new(PayErrorCode::HttpTransport, format!("join error: {e}")))?
}
