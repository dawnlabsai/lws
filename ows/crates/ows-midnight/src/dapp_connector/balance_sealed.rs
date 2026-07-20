//! DApp Connector `balanceSealedTransaction` — the taker completes a maker's swap offer.
//!
//! A maker's **proven** (`proof,embedded-fr`) offer — e.g. what `makeIntent` produces — is a proven,
//! imbalanced transaction: the taker's wallet funds the imbalance with its own inputs, exactly what
//! `balanceUnsealed` does. So the proven-maker path reuses the same `plan_unsealed_proven_tx` →
//! `authorize_proven_tx` tail.
//!
//! Scope: a hex-encoded proven maker offer. A fully **sealed** maker (whose Zswap offers must be merged
//! rather than balanced), a bare `zswapoffer` bech32, and MIP-0006 offer JSON are recognized only to be
//! rejected with a precise error for now.

use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;

use super::{classify_unsealed_payload, ConnectorPlan, UnsealedKind};

/// A parsed `balanceSealedTransaction` request: the maker offer to complete (decoded bytes) and whether
/// the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct BalanceSealedRequest {
    pub maker_tx: Vec<u8>,
    pub pay_fees: bool,
}

fn default_pay_fees() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptionsJson {
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BalanceSealedJson {
    /// The maker offer, hex-encoded. Accepts `makerTx`, or `tx`/`transaction` as aliases.
    #[serde(alias = "tx", alias = "transaction")]
    maker_tx: String,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `balanceSealedTransaction` request into the maker offer bytes and
/// fee preference. `payFees` defaults to true.
pub fn parse_balance_sealed_json(json: &str) -> Result<BalanceSealedRequest, std::io::Error> {
    let req: BalanceSealedJson = serde_json::from_str(json).map_err(|e| {
        std::io::Error::other(format!(
            "invalid balanceSealedTransaction request JSON: {e}"
        ))
    })?;
    let clean = req.maker_tx.strip_prefix("0x").unwrap_or(&req.maker_tx);
    let maker_tx = hex::decode(clean)
        .map_err(|e| std::io::Error::other(format!("invalid maker transaction hex: {e}")))?;
    Ok(BalanceSealedRequest {
        maker_tx,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Plan a `balanceSealedTransaction`: decode the maker offer, and — for a proven offer — plan the
/// taker's balancing inertly via the shared tail. Sealed / preimage / non-tx payloads are rejected.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    let request = parse_balance_sealed_json(json)?;
    match classify_unsealed_payload(&request.maker_tx) {
        Some(UnsealedKind::Proven) => {
            let plan = crate::plan_unsealed_proven_tx(
                chain_id,
                crypto_provider,
                &request.maker_tx,
                request.pay_fees,
            )?;
            Ok(ConnectorPlan::BalanceSealed(Box::new(plan)))
        }
        Some(UnsealedKind::ProofPreimage) => Err(std::io::Error::other(
            "balanceSealedTransaction maker offer must be proven (proof,embedded-fr); received a \
             proof-preimage — the maker must prove its own offer first",
        )),
        None => Err(std::io::Error::other(
            "balanceSealedTransaction currently accepts only a proven (proof,embedded-fr) maker \
             offer; a fully sealed maker offer (Zswap-offer merge), a zswapoffer bech32, and MIP-0006 \
             offer JSON are not yet supported",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maker_tx_hex_and_defaults_pay_fees() {
        let req = parse_balance_sealed_json(
            r#"{"method":"balanceSealedTransaction","makerTx":"0x0102ab"}"#,
        )
        .unwrap();
        assert_eq!(req.maker_tx, vec![0x01, 0x02, 0xab]);
        assert!(req.pay_fees);
    }

    #[test]
    fn accepts_tx_alias_and_pay_fees_false() {
        let req = parse_balance_sealed_json(r#"{"tx":"00","options":{"payFees":false}}"#).unwrap();
        assert_eq!(req.maker_tx, vec![0x00]);
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_non_hex_maker_tx() {
        assert!(parse_balance_sealed_json(r#"{"makerTx":"zz"}"#).is_err());
    }
}
