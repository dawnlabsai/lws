//! Wallet-side balancing of an already-proven (`proof,embedded-fr`) unsealed Midnight Standard
//! transaction against the indexer's UTXO set.
//!
//! v1 scope: the wallet injects its own **unshielded** NIGHT inputs (and a change output) to cover
//! the transaction's unshielded outputs, preserving the existing ZK proofs. Shielded-input balancing
//! and DUST fee registration are not handled yet — a transaction that needs either is rejected.

use std::io::Cursor;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_coin_structure::coin::{
    ShieldedTokenType, TokenType as LedgerTokenType, UserAddress, NIGHT,
};
use midnight_ledger::structure::{
    Intent, ProofMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput, UtxoSpend,
};
use midnight_serialize::{
    tagged_deserialize, tagged_serialize, Deserializable as _, Serializable as _,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof as ZswapProof;

use ows_core::sync_cache::SyncCacheScope;

use crate::UnshieldedUtxo;

type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

fn parse_intent_hash_hex(
    s: &str,
) -> Result<midnight_ledger::structure::IntentHash, std::io::Error> {
    use midnight_base_crypto::hash::HashOutput;
    use midnight_ledger::structure::IntentHash;
    let hex_s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_s).map_err(|e| err(format!("invalid intent hash: {e}")))?;
    if bytes.len() != 32 {
        return Err(err("intent hash must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(IntentHash(HashOutput(h)))
}

/// Resolve a UTXO owner field (32-byte hex x-only pubkey, or the sender's own address) to a
/// verifying key.
fn resolve_owner_vk(
    owner_field: &str,
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
) -> Result<VerifyingKey, std::io::Error> {
    let hex_s = owner_field.strip_prefix("0x").unwrap_or(owner_field);
    if let Ok(bytes) = hex::decode(hex_s) {
        if bytes.len() == 32 {
            let mut cur = Cursor::new(bytes);
            return VerifyingKey::deserialize(&mut cur, 0)
                .map_err(|e| err(format!("invalid owner verifying key: {e}")));
        }
    }
    if owner_field == sender_bech32 {
        return Ok(sender_vk.clone());
    }
    Err(err(
        "UTXO owner must be 32-byte hex x-only pubkey or the sender's unshielded address",
    ))
}

fn owner_matches_sender(owner: &str, sender_bech32: &str, vk_hex: &str) -> bool {
    if owner == sender_bech32 {
        return true;
    }
    let o = owner.strip_prefix("0x").unwrap_or(owner);
    o.eq_ignore_ascii_case(vk_hex)
}

/// Return sender-owned UTXOs for `token_wire`, sorted (largest first) for coin selection.
fn sender_utxos_sorted(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
    token_wire: &str,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let mut vk_raw = Vec::new();
    sender_vk
        .serialize(&mut vk_raw)
        .map_err(|e| err(e.to_string()))?;
    let vk_hex = hex::encode(&vk_raw);

    let mut cand: Vec<_> = utxos
        .iter()
        .filter(|u| owner_matches_sender(&u.owner, sender_bech32, &vk_hex))
        .filter(|u| u.token_type.eq_ignore_ascii_case(token_wire))
        .cloned()
        .collect();
    cand.sort_by(|a, b| b.value.cmp(&a.value));
    Ok(cand)
}

/// Pick just enough sender-owned UTXOs for `token_wire` to cover `need`.
fn select_utxos_for_token(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
    token_wire: &str,
    need: u128,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let cand = sender_utxos_sorted(utxos, sender_bech32, sender_vk, token_wire)?;
    let mut out = Vec::new();
    let mut sum = 0u128;
    for u in cand {
        if sum >= need {
            break;
        }
        sum = sum.saturating_add(u.value);
        out.push(u);
    }
    if sum < need {
        return Err(err(format!(
            "insufficient balance for token {token_wire}: need {need}, have {sum}"
        )));
    }
    Ok(out)
}

fn select_utxos_for_night(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
    need: u128,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let night_wire = crate::parse_token_type(Some("night"))?.to_wire_token_type();
    select_utxos_for_token(utxos, sender_bech32, sender_vk, &night_wire, need)
}

fn zswap_offer_needs_shielded_inputs(offer: &ZswapOffer<ZswapProof, InMemoryDB>) -> bool {
    offer.inputs.iter_deref().next().is_none() && offer.outputs.iter_deref().next().is_some()
}

/// Per-segment shielded token deficits (ledger `balance` negative = overspend).
fn ledger_shielded_deficits(
    tx: &TxProven,
) -> Result<Vec<(ShieldedTokenType, u128, u16)>, std::io::Error> {
    let mut out = Vec::new();
    for ((token, segment), bal) in tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
    {
        if let LedgerTokenType::Shielded(tt) = token {
            if bal < 0 {
                out.push((tt, bal.unsigned_abs(), segment));
            }
        }
    }
    Ok(out)
}

/// Return ledger per-segment imbalances (negative = overspend).
fn tx_balance_imbalances(tx: &TxProven) -> Result<Vec<String>, std::io::Error> {
    let imbalances: Vec<String> = tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
        .into_iter()
        .filter(|(_, bal)| *bal < 0)
        .map(|((_, segment), bal)| format!("segment {segment} overspent by {}", bal.unsigned_abs()))
        .collect();
    Ok(imbalances)
}

/// Reassemble a proven `StandardTransaction`, preserving shielded Zswap offers and binding
/// randomness (must already match `guaranteed_coins` / intents) and the input transaction's
/// network id.
fn wrap_proven_standard(
    stx_in: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> TxProven {
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(seg_id, intent_out);
    Transaction::Standard(StandardTransaction {
        network_id: stx_in.network_id.clone(),
        intents,
        guaranteed_coins: stx_in.guaranteed_coins.clone(),
        fallible_coins: stx_in.fallible_coins.clone(),
        binding_randomness: stx_in.binding_randomness,
    })
}

/// Resolve sender UTXOs and build the balanced unshielded offer (inputs to cover the outputs, plus a
/// NIGHT change output), sorted for ledger validity.
fn build_balanced_unshielded_offer(
    indexer_url: &str,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    has_fallible_unshielded: bool,
    outputs_in: Vec<UtxoOutput>,
    scope: &SyncCacheScope,
) -> Result<UnshieldedOffer<MnSig, InMemoryDB>, std::io::Error> {
    if has_fallible_unshielded {
        return Err(err("fallible unshielded offers are not supported yet"));
    }

    let mut need_night: u128 = 0;
    for o in &outputs_in {
        if o.type_ == NIGHT {
            need_night = need_night.saturating_add(o.value);
        }
    }

    let utxos = crate::block_on(
        crate::wallet_sync::unshielded::get_unshielded_utxos_for_display(
            indexer_url,
            sender_addr,
            scope,
        ),
    )?;

    let selected = if need_night == 0 {
        vec![]
    } else {
        select_utxos_for_night(&utxos, sender_addr, sender_vk, need_night)?
    };

    let mut total_in = 0u128;
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    for u in &selected {
        total_in = total_in.saturating_add(u.value);
        let ih = parse_intent_hash_hex(&u.intent_hash)?;
        let out_no = u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
        let vk = resolve_owner_vk(&u.owner, sender_addr, sender_vk)?;
        inputs.push(UtxoSpend {
            value: u.value,
            owner: vk,
            type_: NIGHT,
            intent_hash: ih,
            output_no: out_no,
        });
    }

    let mut outputs = outputs_in;
    let change = total_in.saturating_sub(need_night);
    if change > 0 {
        let sender_user = UserAddress::from(inputs[0].owner.clone());
        outputs.push(UtxoOutput {
            value: change,
            owner: sender_user,
            type_: NIGHT,
        });
    }

    // Ledger validity requires inputs/outputs to be sorted (MalformedError::InputsNotSorted).
    inputs.sort();
    outputs.sort();

    // Start empty: `Intent::sign` appends signatures; pre-filling breaks well-formedness.
    Ok(UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    })
}

/// Inject the wallet's unshielded inputs/change into a proven Standard transaction, preserving its
/// existing proofs and shielded coins. Rejects transactions that would require shielded inputs.
fn balance_unsealed_proven_standard_tx(
    indexer_url: &str,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    tx_bytes: &[u8],
    scope: &SyncCacheScope,
) -> Result<Vec<u8>, std::io::Error> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProven = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse proven tx bytes: {e}")))?;
    let Transaction::Standard(stx) = tx else {
        return Err(err("expected Standard transaction"));
    };

    if let Some(offer) = stx.guaranteed_coins.as_ref() {
        if zswap_offer_needs_shielded_inputs(offer.deref())
            || !ledger_shielded_deficits(&Transaction::Standard(stx.clone()))?.is_empty()
        {
            return Err(err(
                "this transaction needs shielded coin inputs to balance, which is not supported yet (unshielded-only)",
            ));
        }
    }

    let pair = stx
        .intents
        .iter()
        .next()
        .ok_or_else(|| err("expected one intent segment"))?;
    let (seg_sp, intent_sp) = pair.deref();
    let seg_id: u16 = *seg_sp.deref();
    let intent_in = intent_sp.deref().clone();

    let outputs_in: Vec<UtxoOutput> = intent_in
        .guaranteed_unshielded_offer
        .as_ref()
        .map(|sp| {
            sp.deref()
                .outputs
                .iter_deref()
                .map(|o| UtxoOutput {
                    value: o.value,
                    owner: o.owner,
                    type_: o.type_,
                })
                .collect()
        })
        .unwrap_or_default();

    let offer = build_balanced_unshielded_offer(
        indexer_url,
        sender_vk,
        sender_addr,
        intent_in.fallible_unshielded_offer.is_some(),
        outputs_in,
        scope,
    )?;

    let intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: Some(Sp::new(offer)),
        fallible_unshielded_offer: None,
        actions: intent_in.actions.clone(),
        dust_actions: None,
        ttl: intent_in.ttl,
        binding_commitment: intent_in.binding_commitment,
    };
    let tx_out = wrap_proven_standard(&stx, seg_id, intent_out);

    let imbalances = tx_balance_imbalances(&tx_out)?;
    if !imbalances.is_empty() {
        return Err(err(format!(
            "balanced transaction is still ledger-imbalanced ({})",
            imbalances.join("; ")
        )));
    }

    let mut out = Vec::new();
    tagged_serialize(&tx_out, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Balance an already-proven (`proof,embedded-fr`) unsealed connector transaction against the
/// wallet's own unshielded UTXOs, deriving the sender address/vk via the crypto provider and the
/// indexer URL and sync scope from `chain_id`.
///
/// v1 scope: unshielded-only (shielded-input balancing is rejected) and no DUST fee registration
/// (so `pay_fees` on a chain that needs DUST is rejected). Returns the balanced-but-unsealed proven
/// transaction bytes; signing and sealing are separate steps.
pub fn balance_unsealed_proven_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    tx_bytes: &[u8],
    pay_fees: bool,
) -> Result<Vec<u8>, std::io::Error> {
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| err(e.to_string()))?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;

    // Fee registration mints DUST from the wallet's own NIGHT, which the unshielded-only balancer
    // does not do. A network with a live dust ledger is one where fees are paid in DUST, so reject
    // pay_fees there rather than silently producing a fee-less tx.
    if pay_fees && crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(&indexer_url)) {
        return Err(err(
            "paying fees via DUST registration is not supported yet",
        ));
    }

    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };

    balance_unsealed_proven_standard_tx(&indexer_url, &sender_vk, &sender_addr, tx_bytes, &scope)
}
