//! DApp Connector request dispatch. The wallet receives a stringified connector request whose
//! top-level `method` names the operation; each method is parsed and handled by its own submodule.
//! A request with no `method` defaults to `balanceUnsealedTransaction`, the wallet's original method.
//!
//! Every method funnels through one diagonal: parse → [`plan_connector_tx`] (an inert
//! [`ConnectorPlan`]) → policy seam → [`ConnectorPlan::authorize`] (build + prove + sign + seal). The
//! plan carries no bearer instrument, so the seam can gate on it before any key-bearing work happens.

use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;

use crate::BalancedPlan;

mod balance_unsealed;
mod make_transfer;

pub use balance_unsealed::{
    classify_unsealed_payload, parse_balance_unsealed_json, BalanceUnsealedRequest, UnsealedKind,
};
pub use make_transfer::{
    parse_make_transfer_json, DesiredOutput, MakeTransferRequest, TransferKind,
};

/// A DApp Connector method the wallet can be asked to perform, resolved from a request's `method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorMethod {
    /// `balanceUnsealedTransaction` — also the default when a request carries no `method`.
    BalanceUnsealed,
    /// `makeTransfer` — the wallet builds a transaction that sends the requested outputs.
    MakeTransfer,
    /// A method name the wallet parses but does not yet handle (e.g. a sibling still to be built).
    Other(String),
}

#[derive(Deserialize)]
struct MethodEnvelope {
    #[serde(default)]
    method: Option<String>,
}

/// Resolve a connector request's `method` to decide how to route it. An absent `method` resolves to
/// [`ConnectorMethod::BalanceUnsealed`], preserving the wallet's behavior before it was multi-method.
pub fn parse_connector_method(json: &str) -> Result<ConnectorMethod, std::io::Error> {
    let env: MethodEnvelope = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid DApp Connector request JSON: {e}")))?;
    Ok(match env.method.as_deref() {
        None | Some("balanceUnsealedTransaction") => ConnectorMethod::BalanceUnsealed,
        Some("makeTransfer") => ConnectorMethod::MakeTransfer,
        Some(other) => ConnectorMethod::Other(other.to_string()),
    })
}

/// An inert, balanced-but-unauthorized connector transaction — the common denominator every method
/// resolves to. It carries no bearer instrument (proofs/signatures come later in
/// [`ConnectorPlan::authorize`]), so the policy seam can gate on it first. One variant per method.
pub enum ConnectorPlan {
    /// A `balanceUnsealedTransaction` planned against the wallet's own inputs.
    BalanceUnsealed(Box<BalancedPlan>),
    /// A `makeTransfer` request; the transaction is constructed, balanced, proved, and sealed in
    /// `authorize` (its outputs alone already determine the wallet-relative effects for the seam).
    MakeTransfer(MakeTransferRequest),
}

impl ConnectorPlan {
    /// Authorize the plan into signable, sealed transaction bytes: build + prove the wallet's bearer
    /// witnesses in the signer, sign the binding, and serialize. Runs **after** the policy seam.
    pub fn authorize(
        self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Vec<u8>, std::io::Error> {
        match self {
            ConnectorPlan::BalanceUnsealed(plan) => {
                crate::authorize_proven_tx(chain_id, crypto_provider, *plan)
            }
            ConnectorPlan::MakeTransfer(req) => {
                make_transfer::authorize(chain_id, crypto_provider, req)
            }
        }
    }
    // ── POLICY SEAM ── TODO(policy): `ConnectorPlan::effects()` belongs here — the wallet-relative
    // movement each method contributes (request-derived for the `make*` methods, plan-derived for the
    // `balance*` methods), for the seam to gate on before `authorize`. Not wired yet.
}

/// Parse a stringified connector request and plan it (inert) into a [`ConnectorPlan`], ready for the
/// policy seam. Routes by the request's `method`; each method plans in its own submodule.
pub fn plan_connector_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    match parse_connector_method(json)? {
        ConnectorMethod::BalanceUnsealed => balance_unsealed::plan(chain_id, crypto_provider, json),
        ConnectorMethod::MakeTransfer => {
            Ok(ConnectorPlan::MakeTransfer(parse_make_transfer_json(json)?))
        }
        ConnectorMethod::Other(method) => Err(std::io::Error::other(format!(
            "Midnight DApp Connector method '{method}' is not yet implemented"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_method_defaults_to_balance_unsealed() {
        assert_eq!(
            parse_connector_method(r#"{"tx":"00"}"#).unwrap(),
            ConnectorMethod::BalanceUnsealed
        );
    }

    #[test]
    fn named_balance_unsealed_routes() {
        assert_eq!(
            parse_connector_method(r#"{"method":"balanceUnsealedTransaction","tx":"00"}"#).unwrap(),
            ConnectorMethod::BalanceUnsealed
        );
    }

    #[test]
    fn named_make_transfer_routes() {
        assert_eq!(
            parse_connector_method(r#"{"method":"makeTransfer","desiredOutputs":[]}"#).unwrap(),
            ConnectorMethod::MakeTransfer
        );
    }

    #[test]
    fn unhandled_method_is_preserved_by_name() {
        assert_eq!(
            parse_connector_method(r#"{"method":"submitTransaction"}"#).unwrap(),
            ConnectorMethod::Other("submitTransaction".to_string())
        );
    }
}
