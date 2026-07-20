//! DApp Connector `makeIntent`.
//!
//! `makeIntent(desiredInputs, desiredOutputs, options)` asks the wallet to build a **single-segment,
//! deliberately imbalanced** swap-offer intent — the maker side of a swap. The maker contributes real
//! inputs and declares the outputs it wants; a counterparty completes and balances it later
//! (`balanceSealedTransaction`). Because it is imbalanced by design, `makeIntent` does **not** run the
//! balancing tail: `authorize` builds the maker's inputs + outputs, proves them, and returns the
//! signable bytes for the downstream sign/seal.
//!
//! Scope: unshielded inputs (with change back to the maker) and unshielded/shielded outputs. Shielded
//! inputs are rejected for now — their whole-coin spend + change semantics in a cross-token swap need to
//! be pinned against the connector swap spec first.

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_coin_structure::coin::Info as CoinInfo;
use midnight_ledger::structure::{
    Intent, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput,
    UtxoSpend,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork, MidnightSigner};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::Deserialize;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::ProofPreimage;

use super::build::{
    decode_shielded_recipient, decode_unshielded_recipient, deserialize_u128, err, far_future_ttl,
    prove_to_unsealed_bytes, wire_type_to_shielded, wire_type_to_unshielded, DesiredOutput,
    PreimageTx, TransferKind,
};
use crate::parse_token_type;

/// The connector convention default when a request omits `intentSegment`.
const DEFAULT_INTENT_SEGMENT: u16 = 1;

/// One input the maker contributes: a `value` of `token_type` in `kind`'s domain (no recipient — the
/// maker spends its own coins).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredInput {
    pub kind: TransferKind,
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
}

/// A parsed `makeIntent` request: the maker's inputs and desired outputs, the intent segment, and
/// whether the (downstream) completed transaction should pay DUST fees.
#[derive(Debug, Clone)]
pub struct MakeIntentRequest {
    pub desired_inputs: Vec<DesiredInput>,
    pub desired_outputs: Vec<DesiredOutput>,
    pub intent_segment: u16,
    pub pay_fees: bool,
}

fn default_pay_fees() -> bool {
    true
}

fn default_intent_segment() -> u16 {
    DEFAULT_INTENT_SEGMENT
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptionsJson {
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeIntentJson {
    #[serde(default)]
    desired_inputs: Vec<DesiredInput>,
    #[serde(default)]
    desired_outputs: Vec<DesiredOutput>,
    #[serde(default = "default_intent_segment")]
    intent_segment: u16,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `makeIntent` request. `payFees` defaults to true; `intentSegment`
/// defaults to the connector convention.
pub fn parse_make_intent_json(json: &str) -> Result<MakeIntentRequest, std::io::Error> {
    let req: MakeIntentJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid makeIntent request JSON: {e}")))?;
    if req.desired_inputs.is_empty() && req.desired_outputs.is_empty() {
        return Err(std::io::Error::other(
            "makeIntent requires at least one desired input or output",
        ));
    }
    Ok(MakeIntentRequest {
        desired_inputs: req.desired_inputs,
        desired_outputs: req.desired_outputs,
        intent_segment: req.intent_segment,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Build the maker's imbalanced offer, prove it, and return the signable bytes. Runs **after** the
/// policy seam. No balancing: the imbalance is the offer.
pub(super) fn authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: MakeIntentRequest,
) -> Result<Vec<u8>, std::io::Error> {
    let preimage = build_make_intent_preimage(chain_id, crypto_provider, &req)?;
    prove_to_unsealed_bytes(chain_id, preimage)
}

/// Construct the single-segment `proof-preimage` maker offer: the maker's unshielded inputs (with change
/// back to the maker) + unshielded/shielded outputs, deliberately imbalanced.
fn build_make_intent_preimage(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<PreimageTx, std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);

    let (unshielded_in, shielded_in): (Vec<_>, Vec<_>) = req
        .desired_inputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);

    if !shielded_in.is_empty() {
        return Err(err(
            "makeIntent shielded inputs are not yet supported; contribute unshielded inputs",
        ));
    }

    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| err(e.to_string()))?;
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    let unshielded_offer = build_unshielded_offer(
        chain_id,
        &signer,
        &sender_addr,
        &sender_vk,
        &unshielded_in,
        &unshielded_out,
    )?;
    let zswap_offer = build_shielded_output_offer(&signer, req.intent_segment, &shielded_out)?;
    if unshielded_offer.is_none() && zswap_offer.is_none() {
        return Err(err("makeIntent produced no offer"));
    }

    let mut rng = OsRng;
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: unshielded_offer.map(Sp::new),
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        ttl: far_future_ttl(),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> =
        MnHashMap::new().insert(req.intent_segment, intent);
    let (guaranteed_coins, fallible_coins) = place_zswap_offer(req.intent_segment, zswap_offer);
    let mut stx = StandardTransaction {
        network_id: signer.ledger_network_id().to_string(),
        intents,
        guaranteed_coins,
        fallible_coins,
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    Ok(Transaction::Standard(stx))
}

/// Route the shielded offer to the segment its outputs were bound to: segment 0 → the guaranteed offer;
/// segment N ≥ 1 → `fallible_coins[N]` (mirrors the ledger's guaranteed/fallible split).
#[allow(clippy::type_complexity)]
fn place_zswap_offer(
    segment: u16,
    offer: Option<ZswapOffer<ProofPreimage, InMemoryDB>>,
) -> (
    Option<Sp<ZswapOffer<ProofPreimage, InMemoryDB>, InMemoryDB>>,
    MnHashMap<u16, ZswapOffer<ProofPreimage, InMemoryDB>, InMemoryDB>,
) {
    match offer {
        None => (None, MnHashMap::new()),
        Some(o) if segment == 0 => (Some(Sp::new(o)), MnHashMap::new()),
        Some(o) => (None, MnHashMap::new().insert(segment, o)),
    }
}

/// Build the maker's unshielded offer: select real UTXOs to cover each input, spend them (returning any
/// whole-coin excess as change back to the maker), and append the desired unshielded outputs.
fn build_unshielded_offer(
    chain_id: &str,
    signer: &MidnightSigner,
    sender_addr: &str,
    sender_vk: &VerifyingKey,
    inputs_requested: &[&DesiredInput],
    outputs_requested: &[&DesiredOutput],
) -> Result<Option<UnshieldedOffer<MnSig, InMemoryDB>>, std::io::Error> {
    if inputs_requested.is_empty() && outputs_requested.is_empty() {
        return Ok(None);
    }

    let mut inputs: Vec<UtxoSpend> = Vec::new();
    let mut outputs: Vec<UtxoOutput> = Vec::new();

    if !inputs_requested.is_empty() {
        let maker = decode_unshielded_recipient(signer, sender_addr)?;
        let utxos = crate::block_on(crate::get_unshielded_utxos_for_display(
            &crate::wallet::resolve_indexer_url(chain_id)?,
            sender_addr,
            &Default::default(),
        ))?;
        for d in inputs_requested {
            if d.value == 0 {
                return Err(err("desired input value must be greater than zero"));
            }
            let wire = parse_token_type(Some(&d.token_type))?.to_wire_token_type();
            let type_ = wire_type_to_unshielded(&d.token_type)?;
            let selected = crate::balance_tx::select_utxos_for_token(
                &utxos,
                sender_addr,
                sender_vk,
                &wire,
                d.value,
            )?;
            let mut total = 0u128;
            for u in &selected {
                total = total.saturating_add(u.value);
                inputs.push(UtxoSpend {
                    value: u.value,
                    owner: crate::balance_tx::resolve_owner_vk(&u.owner, sender_addr, sender_vk)?,
                    type_,
                    intent_hash: crate::balance_tx::parse_intent_hash_hex(&u.intent_hash)?,
                    output_no: u32::try_from(u.output_index)
                        .map_err(|_| err("output index out of range"))?,
                });
            }
            let change = total.saturating_sub(d.value);
            if change > 0 {
                outputs.push(UtxoOutput {
                    value: change,
                    owner: maker,
                    type_,
                });
            }
        }
    }

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

    inputs.sort();
    outputs.sort();
    Ok(Some(UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    }))
}

/// Build a Zswap offer of shielded outputs to their recipients, bound to `segment`.
fn build_shielded_output_offer(
    signer: &MidnightSigner,
    segment: u16,
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
        let out = ZswapOutput::new(&mut rng, &coin, Some(segment), &cpk, Some(epk))
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
    fn parses_inputs_outputs_and_defaults() {
        let req = parse_make_intent_json(
            r#"{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"100"}],"desiredOutputs":[{"kind":"shielded","type":"night","value":"50","recipient":"mn_r"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_inputs.len(), 1);
        assert_eq!(req.desired_inputs[0].value, 100);
        assert_eq!(req.desired_inputs[0].kind, TransferKind::Unshielded);
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.intent_segment, DEFAULT_INTENT_SEGMENT);
        assert!(req.pay_fees);
    }

    #[test]
    fn honours_intent_segment_and_pay_fees_false() {
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"intentSegment":3,"options":{"payFees":false}}"#,
        )
        .unwrap();
        assert_eq!(req.intent_segment, 3);
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_empty_request() {
        assert!(parse_make_intent_json(r#"{"desiredInputs":[],"desiredOutputs":[]}"#).is_err());
    }
}
