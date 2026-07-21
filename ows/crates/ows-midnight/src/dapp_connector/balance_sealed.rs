//! DApp Connector `balanceSealedTransaction` — the taker completes a maker's swap offer.
//!
//! A maker's **proven** (`proof,embedded-fr`) offer — e.g. what `makeIntent` produces — is a proven,
//! imbalanced transaction: the taker's wallet funds the imbalance with its own inputs, exactly what
//! `balanceUnsealed` does. So the proven-maker path reuses the same `plan_unsealed_proven_tx` →
//! `authorize_proven_tx` tail.
//!
//! Scope: a hex-encoded proven maker offer, or a bare MIP-0005 `zswapoffer` bech32 (wrapped into a
//! proven zswap-only tx before balancing). A fully **sealed** maker (whose Zswap offers must be
//! merged rather than balanced) and MIP-0006 offer JSON are recognized only to be rejected with a
//! precise error for now.

use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;

use super::mip6;
use super::{classify_unsealed_payload, ConnectorPlan, UnsealedKind};

/// A parsed `balanceSealedTransaction` request: the maker offer to complete (the raw input string —
/// hex or a `zswapoffer` bech32) and whether the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct BalanceSealedRequest {
    pub maker_input: String,
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

/// Parse a stringified DApp Connector `balanceSealedTransaction` request into the raw maker offer
/// string and fee preference. `payFees` defaults to true. The maker string is decoded later (it may
/// be hex or a `zswapoffer` bech32), once the chain id is known.
pub fn parse_balance_sealed_json(json: &str) -> Result<BalanceSealedRequest, std::io::Error> {
    let req: BalanceSealedJson = serde_json::from_str(json).map_err(|e| {
        std::io::Error::other(format!(
            "invalid balanceSealedTransaction request JSON: {e}"
        ))
    })?;
    Ok(BalanceSealedRequest {
        maker_input: req.maker_tx,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Decode the maker input into transaction bytes: a `zswapoffer…` bech32 is wrapped into a proven
/// zswap-only tx (MIP-0005); a MIP-0006 offer JSON object is validated (gives/wants vs deltas, plus
/// optional signature) and materialized; anything else is treated as hex-encoded transaction bytes.
fn decode_maker_input(chain_id: &str, input: &str) -> Result<Vec<u8>, std::io::Error> {
    let trimmed = input.trim();
    if trimmed.starts_with(mip6::ZSWAP_OFFER_BECH32_HRP) {
        return mip6::wrap_zswap_offer_as_proven_tx(chain_id, trimmed);
    }
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| std::io::Error::other(format!("invalid maker offer JSON: {e}")))?;
        if mip6::is_mip6_offer_payload(&v) {
            return mip6::materialize_validated_offer(chain_id, &v);
        }
        return Err(std::io::Error::other(
            "maker input JSON is not a MIP-0006 offer (needs version, transaction, gives, wants)",
        ));
    }
    let clean = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(clean)
        .map_err(|e| std::io::Error::other(format!("invalid maker transaction hex: {e}")))
}

/// Plan a `balanceSealedTransaction`: decode the maker offer (hex tx or `zswapoffer` bech32) and —
/// for a proven offer — plan the taker's balancing inertly via the shared tail. Sealed / preimage /
/// non-tx payloads are rejected.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    let request = parse_balance_sealed_json(json)?;
    let maker_tx = decode_maker_input(chain_id, &request.maker_input)?;
    match classify_unsealed_payload(&maker_tx) {
        Some(UnsealedKind::Proven) => {
            let plan = crate::plan_unsealed_proven_tx(
                chain_id,
                crypto_provider,
                &maker_tx,
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
             offer or a zswapoffer bech32; a fully sealed maker offer (Zswap-offer merge) and \
             MIP-0006 offer JSON are not yet supported",
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
        assert_eq!(req.maker_input, "0x0102ab");
        assert!(req.pay_fees);
        // The raw input decodes to the hex bytes (0x prefix stripped).
        assert_eq!(
            decode_maker_input("midnight:preview", &req.maker_input).unwrap(),
            vec![0x01, 0x02, 0xab]
        );
    }

    #[test]
    fn accepts_tx_alias_and_pay_fees_false() {
        let req = parse_balance_sealed_json(r#"{"tx":"00","options":{"payFees":false}}"#).unwrap();
        assert_eq!(req.maker_input, "00");
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_non_hex_maker_tx() {
        // Parsing keeps the raw string; the hex error surfaces at decode time.
        let req = parse_balance_sealed_json(r#"{"makerTx":"zz"}"#).unwrap();
        assert!(decode_maker_input("midnight:preview", &req.maker_input).is_err());
    }

    #[test]
    fn zswapoffer_input_dispatches_to_the_offer_decoder() {
        // A zswapoffer-prefixed input routes through the bech32 wrapper (a malformed one errors
        // there, not as invalid hex — proving the dispatch).
        let err = decode_maker_input("midnight:preview", "zswapoffer1notvalid")
            .unwrap_err()
            .to_string();
        assert!(err.contains("zswap offer"), "unexpected error: {err}");
    }
}
