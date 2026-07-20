//! DApp Connector request dispatch. The wallet receives a stringified connector request whose
//! top-level `method` names the operation; each method is parsed and handled by its own submodule.
//! A request with no `method` defaults to `balanceUnsealedTransaction`, the wallet's original method.

use serde::Deserialize;

mod balance_unsealed;

pub use balance_unsealed::{
    classify_unsealed_payload, parse_balance_unsealed_json, BalanceUnsealedRequest, UnsealedKind,
};

/// A DApp Connector method the wallet can be asked to perform, resolved from a request's `method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorMethod {
    /// `balanceUnsealedTransaction` — also the default when a request carries no `method`.
    BalanceUnsealed,
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
        Some(other) => ConnectorMethod::Other(other.to_string()),
    })
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
    fn unhandled_method_is_preserved_by_name() {
        assert_eq!(
            parse_connector_method(r#"{"method":"makeTransfer"}"#).unwrap(),
            ConnectorMethod::Other("makeTransfer".to_string())
        );
    }
}
