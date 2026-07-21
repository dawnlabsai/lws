//! DApp Connector `makeTransfer`.
//!
//! `makeTransfer(desiredOutputs, options?)` asks the wallet to build a transaction that sends
//! `desiredOutputs` to their recipients. The wallet constructs the outputs (no inputs), proves them,
//! and — since an outputs-only proven transaction is a wallet-funded deficit — funnels it through the
//! same `plan_unsealed_proven_tx` → `authorize_proven_tx` tail as `balanceUnsealed`.

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_coin_structure::coin::Info as CoinInfo;
use midnight_ledger::structure::{
    Intent, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_signer::chains::{MidnightCryptoProvider, MidnightSigner};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::Deserialize;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::ProofPreimage;

use super::build::{
    decode_shielded_recipient, decode_unshielded_recipient, err, far_future_ttl,
    prove_to_unsealed_bytes, wire_type_to_shielded, wire_type_to_unshielded, DesiredOutput,
    PreimageTx, TransferKind,
};

/// The intent that carries the wallet's unshielded outputs keys at a fallible segment (>= 1): the
/// ledger reserves segment 0 for the guaranteed section and rejects any intent declared there
/// (`IntentAtGuaranteedSegmentId`, surfaced by the node as `Custom error: 167`). Unshielded NIGHT
/// movement rides this segment's *fallible* offer, not the guaranteed one: only the guaranteed
/// unshielded offer's cost counts toward the guaranteed section's tight `time_to_dismiss` budget, so
/// funding a multi-UTXO NIGHT move in the guaranteed section overruns it (the node dismisses the tx).
/// Shielded Zswap outputs still ride the guaranteed section. Balancing draws the wallet's own inputs
/// into this same fallible offer.
const MAKE_TRANSFER_INTENT_SEGMENT: u16 = 1;
/// Segment 0 is the transaction's guaranteed section; a transfer's shielded outputs ride it so they
/// execute unconditionally.
const GUARANTEED_SEGMENT: u16 = 0;

/// A parsed `makeTransfer` request: the outputs to send, and whether the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct MakeTransferRequest {
    pub desired_outputs: Vec<DesiredOutput>,
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

/// Build, balance, prove, and seal a `makeTransfer` transaction. Runs **after** the policy seam.
pub(super) fn authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: MakeTransferRequest,
) -> Result<Vec<u8>, std::io::Error> {
    let preimage = build_make_transfer_preimage(chain_id, &req)?;
    let proven_bytes = prove_to_unsealed_bytes(chain_id, preimage)?;
    // Reuse the balanceUnsealed diagonal: plan the balancing inertly, then authorize (sign + seal).
    let plan =
        crate::plan_unsealed_proven_tx(chain_id, crypto_provider, &proven_bytes, req.pay_fees)?;
    crate::authorize_proven_tx(chain_id, crypto_provider, plan)
}

/// Construct the `proof-preimage` transaction for a `makeTransfer`: recipient outputs and no inputs.
/// Unshielded outputs ride the fallible unshielded offer of the maker intent (see
/// [`MAKE_TRANSFER_INTENT_SEGMENT`]); shielded outputs ride the guaranteed Zswap offer. Balancing (the
/// wallet's own inputs + change + fee) comes later.
fn build_make_transfer_preimage(
    chain_id: &str,
    req: &MakeTransferRequest,
) -> Result<PreimageTx, std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);

    let unshielded_offer = build_unshielded_output_offer(&signer, &unshielded_out)?;
    let zswap_offer = build_shielded_output_offer(&signer, &shielded_out)?;
    if unshielded_offer.is_none() && zswap_offer.is_none() {
        return Err(err(
            "makeTransfer produced no unshielded or shielded output",
        ));
    }

    let mut rng = OsRng;
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: unshielded_offer.map(Sp::new),
        actions: vec![].into(),
        dust_actions: None,
        // The balancer re-aligns the TTL on the intent it owns (this one); a far-future stand-in avoids
        // a spuriously-expired intent in the meantime.
        ttl: far_future_ttl(),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> =
        MnHashMap::new().insert(MAKE_TRANSFER_INTENT_SEGMENT, intent);
    let mut stx = StandardTransaction {
        network_id: signer.ledger_network_id().to_string(),
        intents,
        guaranteed_coins: zswap_offer.map(Sp::new),
        fallible_coins: MnHashMap::new(),
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    Ok(Transaction::Standard(stx))
}

fn build_unshielded_output_offer(
    signer: &MidnightSigner,
    outputs_requested: &[&DesiredOutput],
) -> Result<Option<UnshieldedOffer<MnSig, InMemoryDB>>, std::io::Error> {
    if outputs_requested.is_empty() {
        return Ok(None);
    }
    let mut outputs = Vec::with_capacity(outputs_requested.len());
    for d in outputs_requested {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        outputs.push(UtxoOutput {
            value: d.value,
            owner: decode_unshielded_recipient(signer, &d.recipient)?,
            type_: wire_type_to_unshielded(&d.token_type)?,
        });
    }
    outputs.sort();
    Ok(Some(UnshieldedOffer {
        inputs: vec![].into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    }))
}

fn build_shielded_output_offer(
    signer: &MidnightSigner,
    outputs_requested: &[&DesiredOutput],
) -> Result<Option<ZswapOffer<ProofPreimage, InMemoryDB>>, std::io::Error> {
    if outputs_requested.is_empty() {
        return Ok(None);
    }
    let mut rng = OsRng;
    let mut outputs = Vec::with_capacity(outputs_requested.len());
    for d in outputs_requested {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        let type_ = wire_type_to_shielded(&d.token_type)?;
        let (cpk, epk) = decode_shielded_recipient(signer, &d.recipient)?;
        let coin = CoinInfo {
            nonce: rng.r#gen(),
            type_,
            value: d.value,
        };
        let out = ZswapOutput::new(&mut rng, &coin, Some(GUARANTEED_SEGMENT), &cpk, Some(epk))
            .map_err(|e| err(format!("shielded output failed: {e:?}")))?;
        outputs.push(out);
    }
    ZswapOffer::new(vec![], outputs, vec![])
        .map(Some)
        .ok_or_else(|| err("shielded Zswap offer is empty"))
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

    /// A valid preview unshielded address, derived so the recipient decode path is exercised for real.
    fn preview_unshielded_address() -> String {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        blob.extend_from_slice(&[0x33u8; 32]);
        MidnightSigner::preview()
            .derive_addresses(&blob)
            .expect("derive addresses")
            .unshielded
    }

    /// An outputs-only makeTransfer builds a well-formed transaction whose ledger balance shows a
    /// wallet-funded deficit — exactly the shape `plan_unsealed_proven_tx` balances.
    #[test]
    fn build_unshielded_transfer_leaves_a_deficit() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        assert_eq!(stx.network_id, "preview");
        let proven = tx.mock_prove().expect("mock prove");
        let has_deficit = proven
            .balance(None)
            .expect("balance")
            .into_iter()
            .any(|(_, bal)| bal < 0);
        assert!(
            has_deficit,
            "makeTransfer must leave a wallet-funded deficit"
        );
    }

    /// The ledger rejects an intent declared at segment 0 (the reserved guaranteed section) with
    /// `IntentAtGuaranteedSegmentId`, surfaced on-chain as `Custom error: 167`. Guard that makeTransfer
    /// keys its intent at a fallible segment (the unshielded NIGHT output rides that segment's fallible
    /// offer — see [`make_transfer_night_output_rides_the_fallible_offer`]).
    ///
    /// A full ledger `well_formed` check can't stand in here: an outputs-only transfer is imbalanced
    /// until the wallet funds it, and `well_formed` runs `pedersen_check` (the balance check) *before*
    /// the intent-segment check (verify.rs:605 vs :622), so an imbalanced tx fails on balance before the
    /// segment rule is ever reached. This structural assertion checks the segment invariant directly.
    #[test]
    fn make_transfer_intent_is_off_the_guaranteed_segment() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        assert!(
            stx.intents.get(&0).is_none(),
            "makeTransfer must not key an intent at segment 0 (IntentAtGuaranteedSegmentId / node error 167)"
        );
        assert!(
            stx.intents.get(&MAKE_TRANSFER_INTENT_SEGMENT).is_some(),
            "the maker intent rides the fallible segment"
        );
    }

    /// Unshielded NIGHT movement rides the *fallible* offer, never the guaranteed one: only the
    /// guaranteed offer loads the guaranteed section's `time_to_dismiss` budget, so a multi-UTXO NIGHT
    /// move funded there would overrun it and the node would dismiss the tx. The recipient output
    /// therefore sits on the maker intent's fallible offer, where the balancer funds it in-segment.
    #[test]
    fn make_transfer_night_output_rides_the_fallible_offer() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        let intent = stx
            .intents
            .get(&MAKE_TRANSFER_INTENT_SEGMENT)
            .expect("the maker intent rides the fallible segment");
        assert!(
            intent.guaranteed_unshielded_offer.is_none(),
            "unshielded NIGHT movement must not ride the guaranteed offer (time_to_dismiss budget)"
        );
        assert!(
            intent.fallible_unshielded_offer.is_some(),
            "the NIGHT output rides the maker intent's fallible offer"
        );
    }

    #[test]
    fn rejects_recipient_with_wrong_network_hrp() {
        // A mainnet-HRP address handed to a preview transfer is rejected at decode time.
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        blob.extend_from_slice(&[0x33u8; 32]);
        let mainnet_addr = MidnightSigner::mainnet()
            .derive_addresses(&blob)
            .unwrap()
            .unshielded;
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: mainnet_addr,
            }],
            pay_fees: true,
        };
        assert!(build_make_transfer_preimage("midnight:preview", &req).is_err());
    }
}
