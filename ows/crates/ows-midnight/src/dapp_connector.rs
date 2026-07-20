//! DApp Connector `balanceUnsealedTransaction` request parsing and unsealed-payload classification.

use serde::Deserialize;

/// Pre-seal Midnight transaction shapes the wallet pipeline understands. Both carry an `embedded-fr`
/// binding (sealing is still pending); they differ only in whether the proofs are still preimages
/// (dapp pre-prove output) or full ZK proofs (dapp post-prove output).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnsealedKind {
    /// `proof-preimage,embedded-fr` — wallet performs balance → sign → prove → seal.
    ProofPreimage,
    /// `proof,embedded-fr` — wallet only needs to balance → sign → seal.
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
