//! Shared building blocks for the wallet-constructed connector methods (`makeTransfer`, `makeIntent`,
//! `balanceSealedTransaction`): the request output/kind DTOs, token-wire mapping, recipient decoding
//! against the network's Bech32m HRPs, and proving a constructed preimage into the unsealed bytes the
//! balancing tail consumes.

use std::collections::BTreeMap;
use std::io::Cursor;

use bech32::Hrp;
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    PublicKey as CoinPublicKey, ShieldedTokenType, UnshieldedTokenType, UserAddress, NIGHT,
};
use midnight_ledger::structure::{
    ProofMarker, ProofPreimageMarker, Transaction, INITIAL_PARAMETERS,
};
use midnight_serialize::{tagged_serialize, Deserializable};
use midnight_storage::db::InMemoryDB;
use ows_core::policy::TransactionEffect;
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::midnight::MidnightAddresses;
use ows_signer::chains::MidnightSigner;
use serde::{Deserialize, Deserializer};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::encryption;

use crate::{parse_token_type, TokenType};

/// The `proof-preimage,embedded-fr` transaction a wallet-constructed method builds before proving.
pub(super) type PreimageTx =
    Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;

/// The proven (`proof,embedded-fr`) transaction a preimage becomes once proved.
pub(super) type ProvenTx = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

pub(super) fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// A TTL an hour past the current wall clock — a stand-in until the balancer re-aligns it to the tip.
pub(super) fn far_future_ttl() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Timestamp::from_secs(now.saturating_add(3600))
}

/// Whether a desired input/output moves value in the unshielded (Night) or shielded (Zswap) domain.
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

/// One wallet-relative movement a wallet-constructed request declares: a signed `value` (negative =
/// outflow the wallet funds, positive = inflow the wallet receives) of `token_type` in `kind`'s domain.
pub(super) struct Movement<'a> {
    pub kind: TransferKind,
    pub token_type: &'a str,
    pub value: i128,
}

/// Fold the declared movements of a `make*` request into one [`TransactionEffect`] per domain
/// (unshielded / shielded), keyed by the wallet's address for that domain; a domain/token that nets to
/// zero is omitted. This is the request-derived counterpart to the plan-derived effects the `balance*`
/// methods compute — the `make*` methods know their movement from the request alone, before any coin is
/// selected.
pub(super) fn effects_from_movements<'a>(
    addresses: &MidnightAddresses,
    movements: impl IntoIterator<Item = Movement<'a>>,
) -> Result<Vec<TransactionEffect>, std::io::Error> {
    let mut unshielded: BTreeMap<String, i128> = BTreeMap::new();
    let mut shielded: BTreeMap<String, i128> = BTreeMap::new();
    for m in movements {
        let wire = parse_token_type(Some(m.token_type))?.to_wire_token_type();
        let bucket = match m.kind {
            TransferKind::Unshielded => &mut unshielded,
            TransferKind::Shielded => &mut shielded,
        };
        *bucket.entry(wire).or_default() += m.value;
    }

    let mut effects = Vec::new();
    for (address, bucket) in [
        (&addresses.unshielded, unshielded),
        (&addresses.shielded, shielded),
    ] {
        let diff: Vec<(String, i64)> = bucket
            .into_iter()
            .filter(|(_, v)| *v != 0)
            .map(|(token, v)| (token, crate::balance_tx::clamp_i128_to_i64(v)))
            .collect();
        if !diff.is_empty() {
            effects.push(TransactionEffect {
                address: address.clone(),
                diff,
            });
        }
    }
    Ok(effects)
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

pub(super) fn wire_type_to_unshielded(
    token_type: &str,
) -> Result<UnshieldedTokenType, std::io::Error> {
    Ok(match parse_token_type(Some(token_type))? {
        TokenType::Native => NIGHT,
        TokenType::Custom(b) => UnshieldedTokenType(HashOutput(b)),
    })
}

pub(super) fn wire_type_to_shielded(token_type: &str) -> Result<ShieldedTokenType, std::io::Error> {
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
pub(super) fn decode_unshielded_recipient(
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
pub(super) fn decode_shielded_recipient(
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

/// Prove a wallet-constructed preimage into a proven, still-unsealed (`proof,embedded-fr`)
/// transaction. `makeIntent` keeps the proven transaction to merge authorized shielded-input
/// fragments into it; the other methods serialize it straight away via [`prove_to_unsealed_bytes`].
pub(super) fn prove_preimage(
    chain_id: &str,
    preimage: PreimageTx,
) -> Result<ProvenTx, std::io::Error> {
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let dir = crate::cache_io::proving_keys_dir(&scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    let prover = crate::Prover::new(dir);
    let cost_model = &INITIAL_PARAMETERS.cost_model.runtime_cost_model;
    crate::block_on(preimage.prove(prover, cost_model))
        .map_err(|e| err(format!("prove constructed outputs: {e}")))
}

/// Prove a wallet-constructed preimage and serialize it — the exact input shape
/// `plan_unsealed_proven_tx` consumes.
pub(super) fn prove_to_unsealed_bytes(
    chain_id: &str,
    preimage: PreimageTx,
) -> Result<Vec<u8>, std::io::Error> {
    let proven = prove_preimage(chain_id, preimage)?;
    let mut out = Vec::new();
    tagged_serialize(&proven, &mut out).map_err(|e| err(format!("serialize proven tx: {e}")))?;
    Ok(out)
}
