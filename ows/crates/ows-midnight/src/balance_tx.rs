//! Wallet-side balancing of an already-proven (`proof,embedded-fr`) unsealed Midnight Standard
//! transaction against the indexer's UTXO set.
//!
//! The wallet injects its own inputs, preserving the existing ZK proofs: **shielded** coins to fund
//! a shielded deficit (e.g. a contract deposit whose Zswap offer has outputs but no inputs), then
//! **unshielded** NIGHT inputs (and a change output) to cover the transaction's unshielded outputs.
//! Each added shielded fragment is proved on its own and merged into the already-proven guaranteed
//! offer. When asked to pay fees on a chain that needs DUST, the fee is covered with either a
//! signature-based **generationless** DUST fee registration funded by its own unregistered NIGHT (no
//! proving), or, when the wallet has no unregistered NIGHT capacity (its NIGHT is all registered for
//! dust generation), a proof-bearing **DUST spend** of its generated dust.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    QualifiedInfo, ShieldedTokenType, TokenType as LedgerTokenType, UserAddress, NIGHT,
};
use midnight_ledger::dust::{
    DustActions, DustLocalState, DustPublicKey, DustRegistration, DustSpend,
    INITIAL_DUST_PARAMETERS,
};
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofKind, ProofMarker, ProofPreimageMarker, StandardTransaction,
    Transaction, UnshieldedOffer, UtxoOutput, UtxoSpend,
};
use midnight_serialize::{
    tagged_deserialize, tagged_serialize, Deserializable as _, Serializable as _,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::{
    DustSpendPlan, MidnightCryptoProvider, MidnightNetwork, ShieldedSpendPlan,
};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof as ZswapProof;

use ows_core::sync_cache::SyncCacheScope;

use crate::UnshieldedUtxo;

mod fee_sizing;
use fee_sizing::{cover_dust_fees, DustFeeContext};

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

/// Build a proof-bearing dust-action section that spends the wallet's generated dust to pay `fee`.
///
/// The dust spend witnesses are built and proved **in the signer** — this hands the crypto provider
/// its [`MidnightCryptoProvider::authorize_dust`] method, which selects dust notes against the synced
/// state, builds a dust-only proof-preimage intent, and proves it with the local
/// [`Prover`](crate::Prover) (DUST proving keys fetched on demand). Only the proven `DustActions`
/// cross back, so no dust key material leaves the signer.
fn build_proven_dust_spends(
    ctx: &DustFeeContext,
    dust_state: &DustLocalState<InMemoryDB>,
    fee_target: u128,
    intent_ttl: Timestamp,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, std::io::Error> {
    let proving_key_dir = crate::cache_io::proving_keys_dir(ctx.scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    let prover = crate::Prover::new(proving_key_dir);

    let plan = DustSpendPlan {
        fee_dust: fee_target,
        dust_ctime: ctx.dust_ctime,
        intent_ttl,
        seg_id: ctx.seg_id,
        binding_commitment: ctx.intent_in.binding_commitment,
    };
    crate::block_on(ctx.crypto_provider.authorize_dust(
        dust_state,
        &plan,
        ctx.ledger_params,
        prover,
    ))
    .map_err(|e| err(format!("prove dust spends failed: {e}")))
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

/// The wallet's inert shielded funding plan for one intent segment: the coins to spend — chosen whole
/// and largest-first to cover each per-token deficit — and the self-change to mint per token. Built
/// from the synced coin set alone (viewing + nullifier detection), it carries **no** spend witness, so
/// it is not a bearer instrument; the authorizing `spend()` happens later, in the signer's
/// [`MidnightCryptoProvider::authorize_shielded`], after the policy seam.
#[derive(Debug, Clone)]
struct SegmentPlan {
    coins: Vec<QualifiedInfo>,
    change_by_token: Vec<(ShieldedTokenType, u128)>,
}

/// Choose which of the wallet's coins to spend to cover each per-token `deficit` — whole coins,
/// largest-first — and size the self-change (selected total − deficit) per token. Pure over the synced
/// coin set: it neither spends nor proves, so it needs no spend key (only the viewing/nullifier
/// detection that produced `coins`). Errors when a token's coins cannot cover its deficit.
fn plan_shielded_inputs(
    coins: &[QualifiedInfo],
    deficits: &[(ShieldedTokenType, u128)],
) -> Result<SegmentPlan, std::io::Error> {
    let mut selected = Vec::new();
    let mut change_by_token = Vec::new();

    for (token, need) in deficits {
        if *need == 0 {
            continue;
        }
        let mut candidates: Vec<QualifiedInfo> = coins
            .iter()
            .copied()
            .filter(|c| c.type_ == *token)
            .collect();
        candidates.sort_by(|a, b| b.value.cmp(&a.value));

        let mut remaining = *need;
        let mut spent = 0u128;
        for coin in candidates {
            if remaining == 0 {
                break;
            }
            selected.push(coin);
            spent = spent.saturating_add(coin.value);
            remaining = remaining.saturating_sub(coin.value);
        }
        if remaining > 0 {
            return Err(err(format!(
                "insufficient shielded balance for token {}: need {need}, short by {remaining}",
                hex::encode(token.into_inner().0)
            )));
        }
        let change = spent.saturating_sub(*need);
        if change > 0 {
            change_by_token.push((*token, change));
        }
    }

    Ok(SegmentPlan {
        coins: selected,
        change_by_token,
    })
}

/// Fund a proven transaction's shielded deficit (e.g. a contract deposit whose Zswap offer has
/// outputs but no inputs) with the wallet's own shielded coins, preserving the existing proofs.
///
/// Mirrors how the DUST-spend fee path proves independently and folds in: per intent segment, select
/// the wallet's coins into a proof-preimage Zswap offer (inputs + self-change) via the crypto
/// provider, prove that fragment on its own with the local [`Prover`](crate::Prover), and merge the
/// proven fragment into the already-proven `guaranteed_coins`. A proven transaction can't recompute
/// its Pedersen binding, so the spent/created coins' binding randomness is added to
/// `binding_randomness` directly. A transaction with no shielded deficit is returned untouched.
fn attach_shielded_inputs(
    stx: StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    crypto_provider: &MidnightCryptoProvider,
    indexer_url: &str,
    scope: &SyncCacheScope,
) -> Result<StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>, std::io::Error>
{
    let Some(offer_sp) = stx.guaranteed_coins.as_ref() else {
        return Ok(stx);
    };
    let deficits = if zswap_offer_needs_shielded_inputs(offer_sp.deref()) {
        ledger_shielded_deficits(&Transaction::Standard(stx.clone()))?
    } else {
        Vec::new()
    };
    if deficits.is_empty() {
        return Ok(stx);
    }

    let current_block_height = crate::tip_verify::fetch_current_block_height(indexer_url);
    let wallet = crate::block_on(crate::wallet_sync::shielded::sync_wallet(
        indexer_url,
        crypto_provider,
        scope,
        current_block_height,
    ))?;
    let mut tree = wallet.zswap;
    crate::wallet_sync::shielded::ensure_shielded_merkle_ready(&mut tree)?;

    let mut by_segment: BTreeMap<u16, Vec<(ShieldedTokenType, u128)>> = BTreeMap::new();
    for (token, need, segment) in deficits {
        by_segment.entry(segment).or_default().push((token, need));
    }

    // The signer clones the tree fresh per segment, so a coin planned for one segment must not be
    // planned for another; thread the remaining coins across segments to keep the plans disjoint.
    let mut remaining: Vec<QualifiedInfo> =
        tree.coins.iter().map(|(_nul, qci)| *qci.deref()).collect();
    let mut plans = Vec::new();
    for (segment, seg_deficits) in by_segment {
        let seg_plan = plan_shielded_inputs(&remaining, &seg_deficits)?;
        if seg_plan.coins.is_empty() {
            continue;
        }
        remaining.retain(|c| !seg_plan.coins.contains(c));
        plans.push(ShieldedSpendPlan {
            segment,
            coins: seg_plan.coins,
            change: seg_plan.change_by_token,
        });
    }
    if plans.is_empty() {
        return Ok(stx);
    }

    // The signer builds the proof-preimage spend witnesses from its held shielded keys and proves each
    // fragment; only the proven offers cross back, so no key material reaches the balancer.
    let prover = midnight_prover_for_scope(scope)?;
    let authorized = crate::block_on(crypto_provider.authorize_shielded(&plans, &tree, prover))
        .map_err(|e| err(e.to_string()))?;

    let mut merged: ZswapOffer<ZswapProof, InMemoryDB> = offer_sp.deref().clone();
    for (_segment, proven) in &authorized.proven {
        merged = merged
            .merge(proven)
            .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?;
    }

    let mut stx = stx;
    stx.guaranteed_coins = Some(Sp::new(merged));
    // Proven txs cannot call `recompute_binding_randomness`; add the spend/change randomness directly.
    stx.binding_randomness = stx.binding_randomness + authorized.binding_delta;
    Ok(stx)
}

/// Build the local [`Prover`](crate::Prover) for a sync scope's vault-rooted proving-key directory.
/// Keyless: the prover holds proving/verifier keys, never a wallet secret.
fn midnight_prover_for_scope(scope: &SyncCacheScope) -> Result<crate::Prover, std::io::Error> {
    let dir = crate::cache_io::proving_keys_dir(scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    Ok(crate::Prover::new(dir))
}

/// Inject the wallet's own inputs into a proven Standard transaction, preserving its existing proofs:
/// shielded inputs to fund a contract deposit (when the tx has a shielded deficit), then unshielded
/// NIGHT inputs/change to cover the unshielded outputs.
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

    // Fund a shielded deficit (e.g. a contract deposit) with the wallet's own shielded coins before
    // unshielded balancing — a no-op when the tx has no shielded shortfall.
    let stx = attach_shielded_inputs(stx, crypto_provider, indexer_url, scope)?;

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

    // On a chain with a live dust ledger (Preview/Preprod, mainnet too), fees are paid with a DUST
    // section: a generationless registration signed by the wallet (no proof) when it has unregistered
    // NIGHT, otherwise a proof-bearing spend of its generated dust. Both that section and an
    // hour-past-tip TTL need the chain time, so fetch the tip once (it also carries the ledger
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
        let dust_section = cover_dust_fees(&DustFeeContext {
            stx: &stx,
            seg_id,
            intent_in: &intent_in,
            offer: &offer,
            selected: &selected,
            dust_pk,
            night_vk,
            crypto_provider,
            dust_ctime,
            ledger_params: &ledger_params,
            indexer_url,
            scope,
        })?;
        (Some(dust_section), chain_aligned_intent_ttl(dust_ctime))
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

    /// A synced coin of the given token and value; the nonce/mt_index don't affect selection.
    fn qci(token: ShieldedTokenType, value: u128) -> QualifiedInfo {
        use rand::Rng as _;
        let mut coin: QualifiedInfo = rand::rngs::OsRng.r#gen();
        coin.type_ = token;
        coin.value = value;
        coin
    }

    /// Whole coins are spent largest-first until the deficit is covered; the excess becomes self-change
    /// and unneeded coins are left untouched. No spend/prove — pure selection.
    #[test]
    fn plan_shielded_inputs_selects_largest_first_and_sizes_change() {
        let token = ShieldedTokenType(HashOutput([7u8; 32]));
        let coins = vec![qci(token, 100), qci(token, 30), qci(token, 40)];
        // Need 120: 100 then 40 (= 140) covers it; the 30-coin is untouched. Change = 20.
        let plan = plan_shielded_inputs(&coins, &[(token, 120)]).unwrap();
        let picked: Vec<u128> = plan.coins.iter().map(|c| c.value).collect();
        assert_eq!(picked, vec![100, 40]);
        assert_eq!(plan.change_by_token, vec![(token, 20)]);
    }

    /// A token whose coins can't cover its deficit errors before any spend/prove.
    #[test]
    fn plan_shielded_inputs_errors_when_coins_fall_short() {
        let token = ShieldedTokenType(HashOutput([3u8; 32]));
        let coins = vec![qci(token, 10), qci(token, 5)];
        let e = plan_shielded_inputs(&coins, &[(token, 100)]).unwrap_err();
        assert!(
            format!("{e}").contains("insufficient shielded balance"),
            "unexpected error: {e}"
        );
    }

    /// A zero deficit selects nothing; an exact-cover selection yields no change.
    #[test]
    fn plan_shielded_inputs_zero_and_exact_yield_no_change() {
        let token = ShieldedTokenType(HashOutput([2u8; 32]));
        let coins = vec![qci(token, 500)];
        let zero = plan_shielded_inputs(&coins, &[(token, 0)]).unwrap();
        assert!(zero.coins.is_empty() && zero.change_by_token.is_empty());
        let exact = plan_shielded_inputs(&coins, &[(token, 500)]).unwrap();
        assert_eq!(exact.coins.len(), 1);
        assert!(exact.change_by_token.is_empty());
    }
}
