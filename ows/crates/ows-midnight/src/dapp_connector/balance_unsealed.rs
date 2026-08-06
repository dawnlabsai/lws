//! DApp Connector `balanceUnsealedTransaction` request parsing, unsealed-payload classification, and
//! planning. The dapp hands the wallet an already-**proven** (`proof,embedded-fr`) unsealed tx; the
//! wallet balances it against its own inputs, then signs and seals.

use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;

use super::ConnectorPlan;

/// Pre-seal Midnight transaction shapes the wallet can classify by tag. Per the DApp Connector spec a
/// `balanceUnsealedTransaction` arrives already **proven** (`proof,embedded-fr`) — "unsealed" means
/// signatures/binding are still pending, not that proofs are missing. A `proof-preimage` blob is
/// out-of-spec input here (the dapp is expected to prove its own part before calling the wallet); it is
/// classified only so it can be rejected with a precise error rather than a vague "unrecognized".
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnsealedKind {
    /// `proof-preimage,embedded-fr` — out-of-spec for `balanceUnsealedTransaction`; the dapp must
    /// pre-prove. Rejected by the wallet pipeline.
    ProofPreimage,
    /// `proof,embedded-fr` — the spec-conformant input; the wallet balances → signs → seals.
    Proven,
}

const TAG_PROOF_EMBEDDED_FR: &[u8] =
    b"midnight:transaction[v9](signature[v1],proof,embedded-fr[v1]):";
const TAG_PROOF_PREIMAGE_EMBEDDED_FR: &[u8] =
    b"midnight:transaction[v9](signature[v1],proof-preimage,embedded-fr[v1]):";

/// Classify a tagged v9 Midnight transaction blob, or `None` if it is already sealed (or another
/// shape the wallet pipeline does not handle).
pub fn classify_unsealed_payload(tx_bytes: &[u8]) -> Option<UnsealedKind> {
    if tx_bytes.starts_with(TAG_PROOF_PREIMAGE_EMBEDDED_FR) {
        Some(UnsealedKind::ProofPreimage)
    } else if tx_bytes.starts_with(TAG_PROOF_EMBEDDED_FR) {
        Some(UnsealedKind::Proven)
    } else {
        None
    }
}

/// A parsed `balanceUnsealedTransaction` connector request: the tagged v9 transaction to balance and
/// whether the wallet should register DUST to pay fees.
#[derive(Debug, Clone)]
pub struct BalanceUnsealedRequest {
    pub tx_bytes: Vec<u8>,
    pub pay_fees: bool,
}

fn default_pay_fees() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayFeesOptions {
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BalanceUnsealedJson {
    /// The tagged v9 transaction, hex-encoded. A top-level `method` key (if present) is used for
    /// routing upstream and ignored here.
    tx: String,
    #[serde(default)]
    options: Option<PayFeesOptions>,
}

/// Parse a stringified DApp Connector `balanceUnsealedTransaction` request into its transaction
/// bytes and fee preference. `payFees` defaults to true per the connector spec.
pub fn parse_balance_unsealed_json(json: &str) -> Result<BalanceUnsealedRequest, std::io::Error> {
    let req: BalanceUnsealedJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid balanceUnsealed request JSON: {e}")))?;
    let tx_clean = req.tx.strip_prefix("0x").unwrap_or(&req.tx);
    let tx_bytes = hex::decode(tx_clean)
        .map_err(|e| std::io::Error::other(format!("invalid transaction hex: {e}")))?;
    Ok(BalanceUnsealedRequest {
        tx_bytes,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Plan a `balanceUnsealedTransaction` request: parse it, classify its payload, and — for the
/// spec-conformant proven shape — plan the balancing inertly (sync + select shielded/dust + size the
/// fee, no proving). A proof-preimage or unrecognized payload is rejected with a precise error.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    let request = parse_balance_unsealed_json(json)?;
    match classify_unsealed_payload(&request.tx_bytes) {
        Some(UnsealedKind::Proven) => {
            // The returned plan is inert — it carries no bearer proof-preimage; `authorize_proven_tx`
            // builds and proves the wallet's shielded/dust spend witnesses later, in the signer.
            let plan = crate::plan_unsealed_proven_tx(
                chain_id,
                crypto_provider,
                &request.tx_bytes,
                request.pay_fees,
            )?;
            Ok(ConnectorPlan::BalanceUnsealed(Box::new(plan)))
        }
        Some(UnsealedKind::ProofPreimage) => Err(std::io::Error::other(
            "Midnight balanceUnsealedTransaction expects a proven (proof,embedded-fr) transaction per \
             the DApp Connector spec; received a proof-preimage transaction (the dapp must prove its \
             own part before calling the wallet)",
        )),
        None => Err(std::io::Error::other(
            "unrecognized Midnight transaction (expected an unsealed proof or proof-preimage payload)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tx_and_defaults_pay_fees_true() {
        let req =
            parse_balance_unsealed_json(r#"{"method":"balanceUnsealedTransaction","tx":"0102ab"}"#)
                .unwrap();
        assert_eq!(req.tx_bytes, vec![0x01, 0x02, 0xab]);
        assert!(req.pay_fees);
    }

    #[test]
    fn honours_pay_fees_false() {
        let req =
            parse_balance_unsealed_json(r#"{"tx":"0x00","options":{"payFees":false}}"#).unwrap();
        assert_eq!(req.tx_bytes, vec![0x00]);
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_non_hex_tx() {
        assert!(parse_balance_unsealed_json(r#"{"tx":"zz"}"#).is_err());
    }

    #[test]
    fn classify_recognizes_tags() {
        assert_eq!(
            classify_unsealed_payload(TAG_PROOF_EMBEDDED_FR),
            Some(UnsealedKind::Proven)
        );
        assert_eq!(
            classify_unsealed_payload(TAG_PROOF_PREIMAGE_EMBEDDED_FR),
            Some(UnsealedKind::ProofPreimage)
        );
        assert_eq!(
            classify_unsealed_payload(b"midnight:transaction[v9]sealed"),
            None
        );
    }
}
