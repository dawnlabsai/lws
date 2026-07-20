//! DApp Connector `makeTransfer` request parsing.
//!
//! `makeTransfer(desiredOutputs, options?)` asks the wallet to build (and then balance) a transaction
//! that sends `desiredOutputs` to their recipients. Because the wallet *constructs* this transaction,
//! every desired output is value leaving the wallet — so its wallet-relative movement is known straight
//! from the request, with no balancing or key access required. Building, balancing, proving, and sealing
//! the transaction is the `authorize` half of the diagonal (see the adapter in this module).

use std::io::Cursor;

use bech32::Hrp;
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Info as CoinInfo, PublicKey as CoinPublicKey, ShieldedTokenType, UnshieldedTokenType,
    UserAddress, NIGHT,
};
use midnight_ledger::structure::{
    Intent, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput,
    INITIAL_PARAMETERS,
};
use midnight_serialize::{tagged_serialize, Deserializable};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::{MidnightCryptoProvider, MidnightSigner};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::{Deserialize, Deserializer};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::encryption;
use transient_crypto::proofs::ProofPreimage;

use crate::{parse_token_type, TokenType};

type PreimageTx = Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// A TTL an hour past the current wall clock — a stand-in until the balancer re-aligns it to the tip.
fn far_future_ttl() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Timestamp::from_secs(now.saturating_add(3600))
}

/// The guaranteed (segment 0) intent carries the wallet's outputs; balancing draws its own inputs
/// into this same segment, so an outputs-only transaction reads as a segment-0 deficit.
const MAKE_TRANSFER_SEGMENT: u16 = 0;

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
/// outputs into an unsealed transaction and proves them; an outputs-only proven transaction is a
/// wallet-funded deficit — structurally what `balanceUnsealed` already funds — so it then funnels
/// through the identical `plan_unsealed_proven_tx` → `authorize_proven_tx` tail. Runs **after** the
/// policy seam.
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
/// Unshielded outputs ride the guaranteed unshielded offer of a segment-0 intent; shielded outputs ride
/// the guaranteed Zswap offer. Balancing (the wallet's own inputs + change + fee) comes later.
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
        guaranteed_unshielded_offer: unshielded_offer.map(Sp::new),
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        // The balancer re-aligns the TTL on the intent it owns (this one); a far-future stand-in avoids
        // a spuriously-expired intent in the meantime.
        ttl: far_future_ttl(),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> =
        MnHashMap::new().insert(MAKE_TRANSFER_SEGMENT, intent);
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

/// Prove the wallet-constructed outputs into a proven, still-unsealed (`proof,embedded-fr`)
/// transaction and serialize it — the exact input shape `plan_unsealed_proven_tx` consumes.
fn prove_to_unsealed_bytes(
    chain_id: &str,
    preimage: PreimageTx,
) -> Result<Vec<u8>, std::io::Error> {
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let dir = crate::cache_io::proving_keys_dir(&scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    let prover = crate::Prover::new(dir);
    let cost_model = &INITIAL_PARAMETERS.cost_model.runtime_cost_model;
    let proven = crate::block_on(preimage.prove(prover, cost_model))
        .map_err(|e| err(format!("prove makeTransfer outputs: {e}")))?;
    let mut out = Vec::new();
    tagged_serialize(&proven, &mut out).map_err(|e| err(format!("serialize proven tx: {e}")))?;
    Ok(out)
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
        let out = ZswapOutput::new(
            &mut rng,
            &coin,
            Some(MAKE_TRANSFER_SEGMENT),
            &cpk,
            Some(epk),
        )
        .map_err(|e| err(format!("shielded output failed: {e:?}")))?;
        outputs.push(out);
    }
    ZswapOffer::new(vec![], outputs, vec![])
        .map(Some)
        .ok_or_else(|| err("shielded Zswap offer is empty"))
}

fn wire_type_to_unshielded(token_type: &str) -> Result<UnshieldedTokenType, std::io::Error> {
    Ok(match parse_token_type(Some(token_type))? {
        TokenType::Native => NIGHT,
        TokenType::Custom(b) => UnshieldedTokenType(HashOutput(b)),
    })
}

fn wire_type_to_shielded(token_type: &str) -> Result<ShieldedTokenType, std::io::Error> {
    Ok(match parse_token_type(Some(token_type))? {
        TokenType::Native => ShieldedTokenType(HashOutput([0u8; 32])),
        TokenType::Custom(b) => ShieldedTokenType(HashOutput(b)),
    })
}

fn decode_bech32m_payload(addr: &str, expected_hrp: &str) -> Result<Vec<u8>, std::io::Error> {
    let hrp = Hrp::parse(expected_hrp).map_err(|e| err(format!("invalid expected hrp: {e}")))?;
    let (got_hrp, payload) =
        bech32::decode(addr).map_err(|e| err(format!("invalid bech32m address: {e}")))?;
    if got_hrp != hrp {
        return Err(err(format!(
            "address HRP {got_hrp} does not match network (expected {expected_hrp})"
        )));
    }
    Ok(payload.to_vec())
}

/// Decode a connector unshielded recipient (Bech32m, this network's HRP) into a `UserAddress`.
fn decode_unshielded_recipient(
    signer: &MidnightSigner,
    recipient: &str,
) -> Result<UserAddress, std::io::Error> {
    let hrp = signer.unshielded_hrp().map_err(|e| err(e.to_string()))?;
    let payload = decode_bech32m_payload(recipient, &hrp)?;
    let bytes: [u8; 32] = payload.as_slice().try_into().map_err(|_| {
        err(format!(
            "unshielded recipient payload must be 32 bytes, got {}",
            payload.len()
        ))
    })?;
    Ok(UserAddress(HashOutput(bytes)))
}

/// Decode a connector shielded recipient (Bech32m, this network's HRP) into its coin + encryption
/// public keys.
fn decode_shielded_recipient(
    signer: &MidnightSigner,
    recipient: &str,
) -> Result<(CoinPublicKey, encryption::PublicKey), std::io::Error> {
    let hrp = signer.shielded_hrp().map_err(|e| err(e.to_string()))?;
    let payload = decode_bech32m_payload(recipient, &hrp)?;
    if payload.len() != 64 {
        return Err(err(format!(
            "shielded recipient payload must be 64 bytes, got {}",
            payload.len()
        )));
    }
    let mut cpk = [0u8; 32];
    cpk.copy_from_slice(&payload[..32]);
    let mut cur = Cursor::new(payload[32..].to_vec());
    let epk = <encryption::PublicKey as Deserializable>::deserialize(&mut cur, 0)
        .map_err(|e| err(format!("invalid shielded encryption public key: {e}")))?;
    Ok((CoinPublicKey(HashOutput(cpk)), epk))
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
