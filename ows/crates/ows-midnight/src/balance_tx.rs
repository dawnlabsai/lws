//! Wallet-side balancing of an already-proven (`proof,embedded-fr`) unsealed Midnight Standard
//! transaction against the indexer's UTXO set.
//!
//! v1 scope: the wallet injects its own **unshielded** NIGHT inputs (and a change output) to cover
//! the transaction's unshielded outputs, preserving the existing ZK proofs, and — when asked to pay
//! fees on a chain that needs DUST — adds a signature-based **generationless** DUST fee registration
//! funded by its own unregistered NIGHT (no proving). Shielded-input balancing and proof-bearing
//! DUST spends are not handled — a transaction that needs either is rejected.

use std::io::Cursor;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    ShieldedTokenType, TokenType as LedgerTokenType, UserAddress, NIGHT,
};
use midnight_ledger::dust::{
    DustActions, DustPublicKey, DustRegistration, INITIAL_DUST_PARAMETERS,
};
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofMarker, StandardTransaction, Transaction, UnshieldedOffer,
    UtxoOutput, UtxoSpend,
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

mod fee_sizing;
use fee_sizing::{cover_dust_fee_registration, DustFeeContext};

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
/// NIGHT change output), sorted for ledger validity. Also returns the selected UTXOs so the caller
/// can size the generationless DUST fee allowance from their unregistered NIGHT.
fn build_balanced_unshielded_offer(
    indexer_url: &str,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    has_fallible_unshielded: bool,
    outputs_in: Vec<UtxoOutput>,
    scope: &SyncCacheScope,
) -> Result<(UnshieldedOffer<MnSig, InMemoryDB>, Vec<UnshieldedUtxo>), std::io::Error> {
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
    let offer = UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    };
    Ok((offer, selected))
}

/// Give the signed intent a TTL an hour past the chain tip, matching the wallet SDK.
fn chain_aligned_intent_ttl(dust_ctime: Timestamp) -> Timestamp {
    Timestamp::from_secs(dust_ctime.to_secs().saturating_add(3600))
}

/// Assemble the proven intent from the balanced offer plus optional dust actions.
fn assemble_proven_intent(
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_actions: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ttl: Timestamp,
) -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
    Intent {
        guaranteed_unshielded_offer: Some(Sp::new(offer.clone())),
        fallible_unshielded_offer: None,
        actions: intent_in.actions.clone(),
        dust_actions: dust_actions.map(Sp::new),
        ttl,
        binding_commitment: intent_in.binding_commitment,
    }
}

/// Inject the wallet's unshielded inputs/change into a proven Standard transaction, preserving its
/// existing proofs and shielded coins. Rejects transactions that would require shielded inputs.
#[allow(clippy::too_many_arguments)]
fn balance_unsealed_proven_standard_tx(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    tx_bytes: &[u8],
    pay_fees: bool,
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

    let (offer, selected) = build_balanced_unshielded_offer(
        indexer_url,
        sender_vk,
        sender_addr,
        intent_in.fallible_unshielded_offer.is_some(),
        outputs_in,
        scope,
    )?;

    // On a chain with a live dust ledger (Preview/Preprod, mainnet too), fees are paid via a
    // generationless DUST registration signed by the wallet (no proof). The registration and an
    // hour-past-tip TTL both need the chain time, so fetch the tip once (it also carries the ledger
    // parameters used to size the fee).
    let (dust_actions, intent_ttl) = if pay_fees
        && crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(indexer_url))
    {
        if intent_in.dust_actions.is_some() {
            return Err(err(
                "transaction already carries dust actions, which is unsupported",
            ));
        }
        let (ledger_params, tip_secs) =
            crate::block_on(crate::ledger_params::fetch_indexer_tip(indexer_url))?;
        let dust_ctime = Timestamp::from_secs(tip_secs);
        let dust_pk = crypto_provider
            .dust_public_key()
            .map_err(|e| err(e.to_string()))?;
        let night_vk = sender_vk.clone();
        let registration = cover_dust_fee_registration(&DustFeeContext {
            stx: &stx,
            seg_id,
            intent_in: &intent_in,
            offer: &offer,
            selected: &selected,
            dust_pk,
            night_vk,
            dust_ctime,
            ledger_params: &ledger_params,
        })?;
        (Some(registration), chain_aligned_intent_ttl(dust_ctime))
    } else {
        (None, intent_in.ttl)
    };

    let intent_out = assemble_proven_intent(&offer, &intent_in, dust_actions, intent_ttl);
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
/// v1 scope: unshielded-only (shielded-input balancing is rejected). When `pay_fees` is set on a
/// chain that needs DUST, the wallet adds a generationless DUST fee registration funded by its own
/// unregistered NIGHT (no proving). Returns the balanced-but-unsealed proven transaction bytes;
/// signing and sealing are separate steps.
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

    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };

    balance_unsealed_proven_standard_tx(
        &indexer_url,
        crypto_provider,
        &sender_vk,
        &sender_addr,
        tx_bytes,
        pay_fees,
        &scope,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger::dust::{DustActions, DustPublicKey, DustRegistration, DustSecretKey};
    use midnight_ledger::structure::IntentHash;
    use ows_signer::chains::MidnightSigner;
    use ows_signer::traits::ChainSigner;
    use ows_signer::SecretBytes;
    use transient_crypto::commitment::PureGeneratorPedersen;

    // Unshielded role-0 seed for the abandon-phrase wallet at index 0; matches the signer's
    // address vectors. A second valid seed drives the wrong-owner test.
    const UNSHIELDED_SEED_HEX: &str =
        "822fa63c57f6317cd51d12d80f0e64c2bc2164088dec1c71ca34a87a890190aa";
    const OTHER_SEED_HEX: &str = "92933dd3dff04c57c9f8950d6e08bd5c6f295655c03627a658e09b0726558cad";

    /// Pack a Midnight signing key the way `secret_to_signing_key` does: the `MNK1` magic followed
    /// by three 32-byte role seeds. Only the unshielded seed is exercised by signing, so the
    /// shielded/dust slots are filler.
    fn packed_signing_key(unshielded_seed_hex: &str) -> SecretBytes {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&hex::decode(unshielded_seed_hex).unwrap());
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        SecretBytes::new(blob)
    }

    /// A generationless dust fee registration owned by `vk` — the signature-based (no-proof) fee
    /// path. `dust_address` is arbitrary here; sign/seal don't inspect it.
    fn dust_fee_registration(vk: &VerifyingKey) -> DustActions<MnSig, ProofMarker, InMemoryDB> {
        let dust_pk = DustPublicKey::from(DustSecretKey::derive_secret_key(&[0x22u8; 32]));
        DustActions {
            spends: vec![].into(),
            registrations: vec![DustRegistration {
                night_key: vk.clone(),
                dust_address: Some(Sp::new(dust_pk)),
                allow_fee_payment: 100_000,
                signature: None,
            }]
            .into(),
            ctime: Timestamp::from_secs(0),
        }
    }

    /// Build a minimal proven (`proof,embedded-fr`) unsealed Standard tx: one guaranteed unshielded
    /// NIGHT input owned by `vk` plus a matching output, no contract calls / shielded coins, and the
    /// given optional dust actions. Structurally what the balancer emits, so it exercises sign →
    /// reattach → seal without a prover or indexer.
    fn build_proven_unshielded_tx(
        vk: &VerifyingKey,
        dust_actions: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ) -> Vec<u8> {
        let input = UtxoSpend {
            value: 1_000_000,
            owner: vk.clone(),
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([7u8; 32])),
            output_no: 0,
        };
        let output = UtxoOutput {
            value: 1_000_000,
            owner: UserAddress::from(vk.clone()),
            type_: NIGHT,
        };
        let offer = UnshieldedOffer {
            inputs: vec![input].into(),
            outputs: vec![output].into(),
            signatures: vec![].into(),
        };
        let intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(offer)),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: dust_actions.map(Sp::new),
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(0, intent);
        let stx = StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        };
        let tx: TxProven = Transaction::Standard(stx);
        let mut out = Vec::new();
        tagged_serialize(&tx, &mut out).unwrap();
        out
    }

    #[test]
    fn sign_then_encode_seals_a_tx_carrying_a_valid_signature() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, None);

        // Sign: one detached signature over the intent's signing message, no seal.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        assert!(!out.signature.is_empty(), "expected a signature blob");

        // It verifies against the intent's data_to_sign for the input owner — i.e. the detached
        // step really signs the message the ledger's own Intent::sign would.
        let mut r: &[u8] = tx_bytes.as_slice();
        let parsed: TxProven = tagged_deserialize(&mut r).unwrap();
        let Transaction::Standard(stx) = parsed else {
            panic!("standard");
        };
        let pair = stx.intents.iter().next().unwrap();
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let intent = intent_sp.deref().clone();
        let data = intent
            .erase_proofs()
            .erase_signatures()
            .data_to_sign(seg_id);
        let sig = MnSig::deserialize(&mut &out.signature[..], 0).unwrap();
        assert!(
            vk.verify(&data, &sig),
            "signature must verify over data_to_sign"
        );

        // Encode: reattach + seal (keyless). The sealed Standard tx's guaranteed offer now carries
        // the signature.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut r2: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut r2).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let sealed_pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, sealed_intent_sp) = sealed_pair.deref();
        let sig_count = sealed_intent_sp
            .deref()
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(sig_count, 1, "sealed tx should carry exactly one signature");
    }

    #[test]
    fn sign_rejects_a_tx_whose_inputs_it_does_not_own() {
        let signer = MidnightSigner::mainnet();
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, None);

        // Sign the same tx with a different wallet key — the ownership check must reject it.
        let wrong_key = packed_signing_key(OTHER_SEED_HEX);
        let err = signer
            .sign_transaction(wrong_key.expose(), &tx_bytes)
            .unwrap_err();
        assert!(
            format!("{err}").contains("owned by the signing key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sign_then_encode_signs_the_dust_fee_registration() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, Some(dust_fee_registration(&vk)));

        // Sign: one signature for the input plus one for the dust fee registration.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        let mut r: &[u8] = &out.signature[..];
        let sig_a = MnSig::deserialize(&mut r, 0).unwrap();
        let sig_b = MnSig::deserialize(&mut r, 0).unwrap();
        assert!(r.is_empty(), "expected exactly two signatures");

        // Both verify against the intent's data_to_sign.
        let mut tr: &[u8] = tx_bytes.as_slice();
        let parsed: TxProven = tagged_deserialize(&mut tr).unwrap();
        let Transaction::Standard(stx) = parsed else {
            panic!("standard");
        };
        let pair = stx.intents.iter().next().unwrap();
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let data = intent_sp
            .deref()
            .clone()
            .erase_proofs()
            .erase_signatures()
            .data_to_sign(seg_id);
        assert!(vk.verify(&data, &sig_a) && vk.verify(&data, &sig_b));

        // Seal: the sealed tx's dust registration carries a signature, and the offer has one too.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut sr: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut sr).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let sealed_pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, sealed_intent_sp) = sealed_pair.deref();
        let sealed_intent = sealed_intent_sp.deref();
        let reg_signed = sealed_intent
            .dust_actions
            .as_ref()
            .and_then(|da| da.deref().registrations.iter().next())
            .map(|reg| reg.signature.is_some())
            .unwrap_or(false);
        assert!(reg_signed, "sealed dust registration must be signed");
        let offer_sigs = sealed_intent
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(offer_sigs, 1, "the input signature stays on the offer");
    }

}
