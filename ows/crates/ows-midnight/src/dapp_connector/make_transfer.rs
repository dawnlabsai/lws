//! DApp Connector `makeTransfer` request parsing.
//!
//! `makeTransfer(desiredOutputs, options?)` asks the wallet to build (and then balance) a transaction
//! that sends `desiredOutputs` to their recipients. Because the wallet *constructs* this transaction,
//! every desired output is value leaving the wallet — so its wallet-relative movement is known straight
//! from the request, with no balancing or key access required. Building, balancing, proving, and sealing
//! the transaction is the `authorize` half of the diagonal (see the adapter in this module).

use ows_signer::chains::MidnightCryptoProvider;
use serde::{Deserialize, Deserializer};

/// Whether a desired output moves value in the unshielded (Night) or shielded (Zswap) domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferKind {
    Shielded,
    Unshielded,
}

/// One recipient output the wallet is asked to produce: a `value` of `token_type` in `kind`'s domain,
/// sent to `recipient`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredOutput {
    pub kind: TransferKind,
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
    pub recipient: String,
}

/// A parsed `makeTransfer` request: the outputs to send, and whether the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct MakeTransferRequest {
    pub desired_outputs: Vec<DesiredOutput>,
    pub pay_fees: bool,
}

/// Accept a u128 amount as either a JSON number or a decimal string. Routes through `serde_json::Value`
/// because serde_json cannot deserialize `u128` inside an untagged position.
pub(super) fn deserialize_u128<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = serde_json::Value::deserialize(deserializer)?;
    match v {
        serde_json::Value::String(s) => s.trim().parse().map_err(D::Error::custom),
        serde_json::Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| D::Error::custom("integer value out of range")),
        _ => Err(D::Error::custom(
            "expected string or number for token amount",
        )),
    }
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
struct MakeTransferJson {
    desired_outputs: Vec<DesiredOutput>,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `makeTransfer` request. `payFees` defaults to true.
pub fn parse_make_transfer_json(json: &str) -> Result<MakeTransferRequest, std::io::Error> {
    let req: MakeTransferJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid makeTransfer request JSON: {e}")))?;
    if req.desired_outputs.is_empty() {
        return Err(std::io::Error::other(
            "makeTransfer requires at least one desired output",
        ));
    }
    Ok(MakeTransferRequest {
        desired_outputs: req.desired_outputs,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Build, balance, prove, and seal a `makeTransfer` transaction. The wallet constructs the requested
/// outputs into an unsealed transaction, then funnels it through the same balancing + authorize tail as
/// `balanceUnsealed`: an outputs-only transaction is a wallet-funded deficit, exactly what that tail
/// covers. Runs **after** the policy seam.
pub(super) fn authorize(
    _chain_id: &str,
    _crypto_provider: &MidnightCryptoProvider,
    _req: MakeTransferRequest,
) -> Result<Vec<u8>, std::io::Error> {
    Err(std::io::Error::other(
        "Midnight makeTransfer authorize (build → balance → prove → seal) is not yet wired",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_outputs_and_defaults_pay_fees_true() {
        let req = parse_make_transfer_json(
            r#"{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"1000","recipient":"mn_addr_r"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.desired_outputs[0].value, 1000);
        assert_eq!(req.desired_outputs[0].kind, TransferKind::Unshielded);
        assert_eq!(req.desired_outputs[0].recipient, "mn_addr_r");
        assert!(req.pay_fees);
    }

    #[test]
    fn honours_pay_fees_false_and_numeric_value() {
        let req = parse_make_transfer_json(
            r#"{"desiredOutputs":[{"kind":"shielded","type":"night","value":5,"recipient":"mn_addr_r"}],"options":{"payFees":false}}"#,
        )
        .unwrap();
        assert!(!req.pay_fees);
        assert_eq!(req.desired_outputs[0].value, 5);
        assert_eq!(req.desired_outputs[0].kind, TransferKind::Shielded);
    }

    #[test]
    fn rejects_empty_outputs() {
        assert!(parse_make_transfer_json(r#"{"desiredOutputs":[]}"#).is_err());
    }
}
