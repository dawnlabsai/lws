//! DApp Connector request dispatch. The wallet receives a stringified connector request whose
//! top-level `method` names the operation; each method is parsed and handled by its own submodule.
//! A request with no `method` defaults to `balanceUnsealedTransaction`, the wallet's original method.
//!
//! Every method funnels through one diagonal: parse → [`plan_connector_tx`] (an inert
//! [`ConnectorPlan`]) → policy seam → [`ConnectorPlan::authorize`] (build + prove + sign + seal). The
//! plan carries no bearer instrument, so the seam can gate on it before any key-bearing work happens.

use ows_core::policy::TransactionEffect;
use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;

use crate::BalancedPlan;

mod balance_sealed;
mod balance_unsealed;
mod build;
mod make_intent;
mod make_transfer;
mod mip6;

pub use balance_sealed::{parse_balance_sealed_json, BalanceSealedRequest};
pub use balance_unsealed::{
    classify_unsealed_payload, is_sealed_maker_payload, parse_balance_unsealed_json,
    BalanceUnsealedRequest, UnsealedKind,
};
pub use build::{DesiredOutput, TransferKind};
pub use make_intent::{parse_make_intent_json, DesiredInput, MakeIntentRequest};
pub use make_transfer::{parse_make_transfer_json, MakeTransferRequest};

/// A DApp Connector method the wallet can be asked to perform, resolved from a request's `method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorMethod {
    /// `balanceUnsealedTransaction` — also the default when a request carries no `method`.
    BalanceUnsealed,
    /// `makeTransfer` — the wallet builds a transaction that sends the requested outputs.
    MakeTransfer,
    /// `makeIntent` — the wallet builds an imbalanced maker swap-offer intent.
    MakeIntent,
    /// `balanceSealedTransaction` — the wallet (taker) completes a maker's swap offer.
    BalanceSealed,
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
        Some("makeIntent") => ConnectorMethod::MakeIntent,
        Some("balanceSealedTransaction") => ConnectorMethod::BalanceSealed,
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
    /// A `makeIntent` request; the wallet builds an imbalanced maker offer, proved in `authorize`.
    MakeIntent(MakeIntentRequest),
    /// A `balanceSealedTransaction`: the taker's balancing of a proven maker offer, planned against
    /// the wallet's own inputs — the same shape as `BalanceUnsealed`.
    BalanceSealed(Box<BalancedPlan>),
    /// A `balanceSealedTransaction` where the maker offer is fully SEALED (`proof,pedersen-schnorr`).
    /// A sealed tx cannot be balanced in place (its binding fixes the value balance), so the taker
    /// completes it by MERGING: it builds its own imbalanced half — the per-token complement of the
    /// maker's imbalance — seals it, and `Transaction::merge`s the two. Carries the maker's sealed
    /// bytes and that derived complement.
    BalanceSealedMerge {
        maker_tx: Vec<u8>,
        complement: MakeIntentRequest,
        /// Whether the taker funds the merged tx's DUST fee. Off (or a fee-less chain) → the merged tx
        /// is value-balanced but carries no fee, so a live-DUST network rejects the submit.
        pay_fees: bool,
    },
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
            ConnectorPlan::MakeIntent(req) => {
                make_intent::authorize(chain_id, crypto_provider, req)
            }
            ConnectorPlan::BalanceSealed(plan) => {
                crate::authorize_proven_tx(chain_id, crypto_provider, *plan)
            }
            ConnectorPlan::BalanceSealedMerge {
                maker_tx,
                complement,
                pay_fees,
            } => balance_sealed::authorize_merge(
                chain_id,
                crypto_provider,
                &maker_tx,
                complement,
                pay_fees,
            ),
        }
    }
    /// The wallet-relative net movement authorizing this plan will have — the view the policy seam gates
    /// on, computed before any bearer instrument is built. Plan-derived for the `balance*` methods (from
    /// the inert [`BalancedPlan`] the wallet already selected) and request-derived for the `make*`
    /// methods (from the declared inputs/outputs, before any coin is chosen). One [`TransactionEffect`]
    /// per value domain that nets non-zero.
    pub fn effects(
        &self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Vec<TransactionEffect>, std::io::Error> {
        match self {
            ConnectorPlan::BalanceUnsealed(plan) | ConnectorPlan::BalanceSealed(plan) => {
                plan.effects(chain_id, crypto_provider)
            }
            ConnectorPlan::MakeTransfer(req) => {
                make_transfer::effects(chain_id, crypto_provider, req)
            }
            ConnectorPlan::MakeIntent(req) => {
                make_intent::request_effects(chain_id, crypto_provider, req)
            }
            // The wallet's movement in a merge is its own half — the `complement` it contributes and
            // receives — plus the merged DUST fee it funds; sized against the maker's sealed bytes so a
            // movement cap sees the burn (see [`balance_sealed::merge_effects`]).
            ConnectorPlan::BalanceSealedMerge {
                maker_tx,
                complement,
                pay_fees,
            } => balance_sealed::merge_effects(
                chain_id,
                crypto_provider,
                maker_tx,
                complement,
                *pay_fees,
            ),
        }
    }
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
        ConnectorMethod::MakeIntent => Ok(ConnectorPlan::MakeIntent(parse_make_intent_json(json)?)),
        ConnectorMethod::BalanceSealed => balance_sealed::plan(chain_id, crypto_provider, json),
        ConnectorMethod::Other(method) => Err(std::io::Error::other(format!(
            "Midnight DApp Connector method '{method}' is not yet implemented"
        ))),
    }
}

/// Normalize a raw `--tx` argument into a canonical DApp Connector request JSON. A JSON object passes
/// through untouched; a bare `zswapoffer…` bech32 (MIP-0005) or a bare hex transaction is wrapped into
/// the request that carries it, so the wallet accepts an offer or a proven transaction directly without
/// the caller writing the envelope. A fully sealed maker becomes a `balanceSealedTransaction` (it is
/// completed by merging, not balanced in place); any other hex a `balanceUnsealedTransaction`.
pub fn normalize_connector_request(raw: &str) -> Result<String, std::io::Error> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        return Ok(raw.to_string());
    }
    if trimmed.starts_with(mip6::ZSWAP_OFFER_BECH32_HRP) {
        return Ok(sealed_request_json(trimmed));
    }
    // Not JSON and not a bech32 offer: the only remaining accepted form is a bare hex transaction.
    let hex_body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_body).map_err(|e| {
        std::io::Error::other(format!(
            "Midnight --tx must be a DApp Connector request JSON, a zswapoffer bech32 offer, or a hex transaction: {e}"
        ))
    })?;
    // A sealed maker is completed by merging, so it rides balanceSealedTransaction; every other proven
    // shape is balanced in place by balanceUnsealedTransaction (the wallet's original method).
    if is_sealed_maker_payload(&bytes) {
        Ok(sealed_request_json(trimmed))
    } else {
        Ok(
            serde_json::json!({ "method": "balanceUnsealedTransaction", "tx": trimmed })
                .to_string(),
        )
    }
}

fn sealed_request_json(maker: &str) -> String {
    serde_json::json!({ "method": "balanceSealedTransaction", "makerTx": maker }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_of(json: &str) -> ConnectorMethod {
        parse_connector_method(json).unwrap()
    }

    fn field_of(json: &str, key: &str) -> String {
        serde_json::from_str::<serde_json::Value>(json).unwrap()[key]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn bare_zswapoffer_wraps_as_balance_sealed() {
        let out = normalize_connector_request("zswapoffer1qqqmakeroffer").unwrap();
        assert_eq!(method_of(&out), ConnectorMethod::BalanceSealed);
        assert_eq!(field_of(&out, "makerTx"), "zswapoffer1qqqmakeroffer");
    }

    #[test]
    fn bare_sealed_maker_hex_wraps_as_balance_sealed() {
        let sealed_hex =
            hex::encode(b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):body");
        let out = normalize_connector_request(&sealed_hex).unwrap();
        assert_eq!(method_of(&out), ConnectorMethod::BalanceSealed);
        assert_eq!(field_of(&out, "makerTx"), sealed_hex);
    }

    #[test]
    fn bare_unsealed_hex_wraps_as_balance_unsealed() {
        let unsealed_hex =
            hex::encode(b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):body");
        let out = normalize_connector_request(&unsealed_hex).unwrap();
        assert_eq!(method_of(&out), ConnectorMethod::BalanceUnsealed);
        assert_eq!(field_of(&out, "tx"), unsealed_hex);
    }

    #[test]
    fn json_request_passes_through_unchanged() {
        let json = r#"{"method":"makeTransfer","desiredOutputs":[]}"#;
        let out = normalize_connector_request(json).unwrap();
        assert_eq!(method_of(&out), ConnectorMethod::MakeTransfer);
    }

    #[test]
    fn neither_json_nor_bech32_nor_hex_is_rejected() {
        assert!(normalize_connector_request("not a transaction").is_err());
    }

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
