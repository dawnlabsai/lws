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
use midnight_zswap::local::State as ZswapLocalState;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::midnight::MidnightAddresses;
use ows_signer::chains::{
    DustSpendPlan, MidnightCryptoProvider, MidnightNetwork, ShieldedAuthorized, ShieldedSpendPlan,
};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::{Proof as ZswapProof, ProofPreimage};

use ows_core::policy::TransactionEffect;
use ows_core::sync_cache::SyncCacheScope;

use crate::{TokenType, UnshieldedUtxo};

mod fee_sizing;
pub(crate) use fee_sizing::size_merge_dust_fee;
use fee_sizing::{DustFeeContext, DustFeePlan};

type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

/// A proven shielded Zswap offer bound to a transaction segment: `0` = guaranteed coins, `>= 1` = the
/// `fallible_coins` entry for that segment.
type ShieldedFragment = (u16, ZswapOffer<ZswapProof, InMemoryDB>);

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Saturate a wallet-relative movement into the `i64` a [`TransactionEffect`] carries. Real Midnight
/// amounts sit far below `i64::MAX`; the clamp only guards a pathological plan from wrapping.
pub(crate) fn clamp_i128_to_i64(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

pub(crate) fn parse_intent_hash_hex(
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
pub(crate) fn resolve_owner_vk(
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
pub(crate) fn select_utxos_for_token(
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

/// Route a proven shielded fragment into the offer the signer bound it to: `segment == 0` merges into
/// the guaranteed offer; `segment >= 1` merges into `fallible_coins[segment]` (creating that segment's
/// entry if absent). Placement must match the segment the fragment's spends/proofs were bound to —
/// `well_formed` verifies the guaranteed offer at a hardcoded segment 0 and each fallible offer at its
/// map-key segment, and `balance()` attributes deltas the same way — so a seg-N>=1 fragment in the
/// guaranteed offer would fail proof verification and leave the seg-N deficit uncovered.
pub(crate) fn place_shielded_fragment(
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    segment: u16,
    proven: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> Result<(), std::io::Error> {
    if segment == 0 {
        let merged = match base.guaranteed_coins.as_ref() {
            Some(sp) => sp
                .deref()
                .merge(proven)
                .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?,
            None => proven.clone(),
        };
        base.guaranteed_coins = Some(Sp::new(merged));
    } else {
        let merged = match base.fallible_coins.get(&segment) {
            Some(sp) => sp
                .deref()
                .merge(proven)
                .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?,
            None => proven.clone(),
        };
        base.fallible_coins = base.fallible_coins.insert(segment, merged);
    }
    Ok(())
}

/// Reassemble a proven `StandardTransaction`, replacing only the balanced intent (`seg_id`) and
/// preserving every other intent, the shielded Zswap offers, binding randomness (must already match
/// `guaranteed_coins` / intents), and the input transaction's network id.
fn wrap_proven_standard(
    stx_in: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> TxProven {
    // Replace only the intent the wallet balanced; the dapp's other intents carry through untouched.
    let intents = stx_in.intents.insert(seg_id, intent_out);
    Transaction::Standard(StandardTransaction {
        network_id: stx_in.network_id.clone(),
        intents,
        guaranteed_coins: stx_in.guaranteed_coins.clone(),
        fallible_coins: stx_in.fallible_coins.clone(),
        binding_randomness: stx_in.binding_randomness,
    })
}

/// The on-chain identity of an unshielded UTXO (producing intent hash + output index), used to keep the
/// guaranteed offer and each per-segment fallible offer drawing **disjoint** coins from one pool.
type UtxoKey = (String, i64);

/// Build one balancing unshielded offer from a pre-fetched UTXO `pool`: select just enough sender NIGHT
/// — skipping coins already `claimed` by another offer, so no coin is spent twice — to cover
/// `need_night`, then emit those inputs plus `outputs_in` (the offer's own outputs, re-emitted) and a
/// NIGHT change output. Records every coin it claims into `claimed` and returns the selected UTXOs so the
/// caller can size the generationless DUST fee allowance from their unregistered NIGHT. Sorted for ledger
/// validity; signatures are appended later by the signer, so the offer starts unsigned.
fn build_night_offer(
    pool: &[UnshieldedUtxo],
    claimed: &mut Vec<UtxoKey>,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    need_night: u128,
    outputs_in: Vec<UtxoOutput>,
    reserve: Option<&UnshieldedUtxo>,
) -> Result<(UnshieldedOffer<MnSig, InMemoryDB>, Vec<UnshieldedUtxo>), std::io::Error> {
    let available: Vec<UnshieldedUtxo> = pool
        .iter()
        .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
        .cloned()
        .collect();

    let mut selected = if need_night == 0 {
        vec![]
    } else {
        select_utxos_for_night(&available, sender_addr, sender_vk, need_night)?
    };

    // Reserve the best-Dust NIGHT coin for the generationless fee registration: spend it here so its
    // unregistered-NIGHT capacity backs the registration. Balance-neutral — its value returns as
    // change — and skipped when the payment already selected it or another offer claimed it, so the
    // wallet reserves exactly one coin instead of over-rotating its NIGHT.
    if let Some(r) = reserve {
        let already = claimed.contains(&(r.intent_hash.clone(), r.output_index))
            || selected
                .iter()
                .any(|u| u.intent_hash == r.intent_hash && u.output_index == r.output_index);
        if !already {
            selected.push(r.clone());
        }
    }

    let mut total_in = 0u128;
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    for u in &selected {
        claimed.push((u.intent_hash.clone(), u.output_index));
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

/// Build a fallible unshielded offer that consolidates several of the wallet's own NIGHT coins into a
/// single change output back to itself. A wallet-built fallible NIGHT offer, spent on its own segment
/// so the guaranteed section stays free for the DUST-registration cell — the mechanism behind moving
/// the wallet's NIGHT off the (budget-tight) guaranteed section. Balance-neutral: the inputs equal the
/// one change output, so the segment it is attached to nets to zero. Each spent coin is recorded in
/// `claimed` so no other offer double-spends it.
fn build_fallible_consolidation_offer(
    coins: &[UnshieldedUtxo],
    claimed: &mut Vec<UtxoKey>,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
) -> Result<UnshieldedOffer<MnSig, InMemoryDB>, std::io::Error> {
    if coins.is_empty() {
        return Err(err("fallible consolidation requires at least one coin"));
    }
    let mut total_in = 0u128;
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    for u in coins {
        claimed.push((u.intent_hash.clone(), u.output_index));
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
    let sender_user = UserAddress::from(inputs[0].owner.clone());
    let mut outputs = vec![UtxoOutput {
        value: total_in,
        owner: sender_user,
        type_: NIGHT,
    }];
    inputs.sort();
    outputs.sort();
    Ok(UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    })
}

/// Give the signed intent a TTL an hour past the chain tip, matching the wallet SDK.
fn chain_aligned_intent_ttl(dust_ctime: Timestamp) -> Timestamp {
    Timestamp::from_secs(dust_ctime.to_secs().saturating_add(3600))
}

/// Assemble the proven intent from the balanced offer plus optional dust actions.
fn assemble_proven_intent(
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
    fallible_offer: Option<&UnshieldedOffer<MnSig, InMemoryDB>>,
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_actions: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ttl: Timestamp,
) -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
    Intent {
        // An empty balancing offer (no inputs, no outputs) carries nothing in the guaranteed section —
        // e.g. a fee-less transfer whose NIGHT movement rides the fallible offer, so the wallet folds no
        // guaranteed inputs here. Drop it to None rather than hand the ledger a degenerate 0-in/0-out
        // offer; a non-empty offer (own re-emitted outputs, funding inputs, or the reserved dust coin)
        // stays as-is.
        guaranteed_unshielded_offer: (offer.inputs.iter_deref().next().is_some()
            || offer.outputs.iter_deref().next().is_some())
        .then(|| Sp::new(offer.clone())),
        // Prefer the wallet's balancing fallible offer (which already re-emits the intent's own fallible
        // outputs); otherwise carry through whatever the intent held.
        fallible_unshielded_offer: fallible_offer
            .map(|o| Sp::new(o.clone()))
            .or_else(|| intent_in.fallible_unshielded_offer.clone()),
        actions: intent_in.actions.clone(),
        // Prefer the wallet's own dust section; otherwise carry through whatever the intent already
        // held — merging into a dapp intent must never silently drop its dust.
        dust_actions: dust_actions
            .or_else(|| intent_in.dust_actions.as_ref().map(|sp| sp.deref().clone()))
            .map(Sp::new),
        ttl,
        binding_commitment: intent_in.binding_commitment,
    }
}

/// Replace the fallible unshielded offer of the intent at `seg`, preserving everything else. Unshielded
/// offers are signed (not Pedersen-committed), so this leaves the tx's `binding_randomness` untouched.
/// A no-op when no intent sits at `seg`.
fn attach_fallible_offer(
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg: u16,
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
) {
    if let Some(intent_sp) = base.intents.get(&seg) {
        let mut intent = intent_sp.deref().clone();
        intent.fallible_unshielded_offer = Some(Sp::new(offer.clone()));
        base.intents = base.intents.insert(seg, intent);
    }
}

/// An empty proven intent at zero binding randomness: no offers, actions, or dust. It carries the
/// wallet's balancing offer + a dust section that needs its own timestamp onto a **fresh** segment
/// (spec §L961-967) without disturbing the dapp's proven transaction. Zero `binding_commitment` keeps
/// the added intent binding-neutral — `recompute_binding_randomness` sums each intent's
/// `binding_commitment`, so the tx's global `binding_randomness` is unchanged.
fn empty_intent_skeleton() -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
    Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        ttl: Timestamp::from_secs(0),
        binding_commitment: PedersenRandomness::from(0),
    }
}

/// The next unused intent segment id: one past the current maximum. Intents never sit at segment 0
/// (reserved for the guaranteed section), so this is always `>= 1` and collision-free.
fn fresh_segment_id(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> u16 {
    base.intents
        .iter()
        .map(|pair| *pair.deref().0.deref())
        .max()
        .map(|m| m.saturating_add(1))
        .unwrap_or(1)
}

/// The intent's guaranteed unshielded outputs, cloned — re-emitted by the balancing offer that replaces
/// that intent's guaranteed offer when the wallet merges into it.
fn guaranteed_outputs_of(
    intent: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Vec<UtxoOutput> {
    intent
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
        .unwrap_or_default()
}

/// Pick the intent the wallet folds its balancing offer + dust fee into, or synthesize a fresh empty
/// skeleton when there is none to reuse.
///
/// Reuse the lowest-segment existing intent (re-emitting its own guaranteed outputs) unless a fresh
/// skeleton is required — which happens in two cases:
/// - the tx carries **no reusable intent** at all: a pure-shielded MIP-0005/0006 zswap offer lives
///   entirely in `guaranteed_coins`/`fallible_coins` and has an **empty** `intents` map, so the taker's
///   dust fee has nowhere to go without a new intent; or
/// - the tx **already carries a dust section**: an intent holds only one dust section and the wallet's
///   dust needs its own timestamp, so it rides a brand-new intent (spec §L961-967).
///
/// The fresh skeleton sits at a new segment with no outputs to re-emit — every existing intent keeps its
/// own guaranteed offer, so their outputs stay put — and is binding-neutral.
fn balancing_intent(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    chosen: Option<(
        u16,
        Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    )>,
    adding_dust: bool,
    has_preexisting_dust: bool,
) -> (
    u16,
    Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    Vec<UtxoOutput>,
) {
    match chosen {
        Some((seg_id, intent_in)) if !(adding_dust && has_preexisting_dust) => {
            let outputs_in = guaranteed_outputs_of(&intent_in);
            (seg_id, intent_in, outputs_in)
        }
        _ => (fresh_segment_id(base), empty_intent_skeleton(), Vec::new()),
    }
}

/// The wallet's inert shielded funding plan for one intent segment: the coins to spend — chosen whole
/// and largest-first to cover each per-token deficit — and the self-change to mint per token. Built
/// from the synced coin set alone (viewing + nullifier detection), it carries **no** spend witness, so
/// it is not a bearer instrument; the authorizing `spend()` happens later, in the signer's
/// [`MidnightCryptoProvider::authorize_shielded`], after the policy seam.
#[derive(Debug, Clone)]
pub(crate) struct SegmentPlan {
    pub(crate) coins: Vec<QualifiedInfo>,
    pub(crate) change_by_token: Vec<(ShieldedTokenType, u128)>,
}

/// Choose which of the wallet's coins to spend to cover each per-token `deficit` — whole coins,
/// largest-first — and size the self-change (selected total − deficit) per token. Pure over the synced
/// coin set: it neither spends nor proves, so it needs no spend key (only the viewing/nullifier
/// detection that produced `coins`). Errors when a token's coins cannot cover its deficit.
pub(crate) fn plan_shielded_inputs(
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

/// The wallet's shielded funding plan for an unsealed proven tx: the per-segment [`ShieldedSpendPlan`]s
/// (which coins to spend + change to mint) and the synced Zswap tree they were planned against — the
/// signer re-spends against this same tree to build the real witnesses. Inert: it carries no spend
/// witness, so it is not a bearer instrument.
pub(super) struct ShieldedFundingPlan {
    pub(super) plans: Vec<ShieldedSpendPlan>,
    pub(super) tree: ZswapLocalState<InMemoryDB>,
}

/// A balanced-but-unauthorized transaction: everything needed to authorize an unsealed proven tx,
/// minus the authorizing witnesses themselves. Produced by [`plan_unsealed_proven_tx`] (which syncs,
/// selects, and fee-sizes with **no** real proving) and consumed by [`authorize_proven_tx`] after the
/// policy seam. Carries no bearer instrument — the proof-preimage `spend()` witnesses are built later,
/// in the signer.
pub struct BalancedPlan {
    base: StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_in: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    unshielded_offer: UnshieldedOffer<MnSig, InMemoryDB>,
    /// Per-segment fallible unshielded balancing offers (each funds one intent's fallible NIGHT deficit
    /// in its own segment). Empty when no intent carries a fallible unshielded offer.
    fallible_offers: Vec<(u16, UnshieldedOffer<MnSig, InMemoryDB>)>,
    intent_ttl: Timestamp,
    shielded: Option<ShieldedFundingPlan>,
    dust: DustFeePlan,
}

impl BalancedPlan {
    /// The wallet-relative net effects authorizing this plan will have, derived from the plan alone —
    /// no re-sync, no bearer instrument — so the policy seam can gate on it *before*
    /// [`authorize_proven_tx`] builds any spend witness. One [`TransactionEffect`] per value domain the
    /// plan touches:
    ///
    /// - **unshielded NIGHT** — the wallet's balancing inputs (guaranteed and fallible) are outflow; its
    ///   own outputs (the change) are inflow; the effect is `inflow − outflow`.
    /// - **shielded**, per token — the coins the plan spends are outflow, the self-change it mints is
    ///   inflow. A shielded output the *dapp* routes to the wallet is not netted: the wallet is the
    ///   funder here, so omitting that inflow only ever over-states outflow — the safe direction for a
    ///   movement cap.
    /// - **dust** — the DUST the fee section burns (a generationless registration burns none).
    pub(crate) fn effects(
        &self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Vec<TransactionEffect>, std::io::Error> {
        let addresses = crypto_provider
            .addresses(&MidnightNetwork::from_chain_id(chain_id))
            .map_err(|e| err(e.to_string()))?;
        let wallet_ua = UserAddress::from(
            crypto_provider
                .unshielded_verifying_key()
                .map_err(|e| err(e.to_string()))?,
        );
        // The wallet funds NIGHT through the guaranteed offer and any per-segment fallible offer, so all
        // of them contribute to the unshielded movement.
        let mut offers = vec![&self.unshielded_offer];
        offers.extend(self.fallible_offers.iter().map(|(_, offer)| offer));
        let shielded_plans = self
            .shielded
            .as_ref()
            .map(|funding| funding.plans.as_slice())
            .unwrap_or(&[]);
        Ok(plan_effects(
            &addresses,
            &wallet_ua,
            &offers,
            shielded_plans,
            self.dust.dust_outflow(),
        ))
    }
}

/// Compute the wallet-relative net effects from a balanced plan's already-decided parts. Pure over its
/// inputs (no key, no network), so it is the unit-tested core of [`BalancedPlan::effects`]:
///
/// - **unshielded NIGHT** — offer inputs (all the wallet's) are outflow; offer outputs owned by the
///   wallet (its change) are inflow.
/// - **shielded**, per token — a plan's spent coins are outflow, its minted self-change is inflow.
/// - **dust** — `dust_outflow` is the DUST the fee section burns.
///
/// One [`TransactionEffect`] per domain, keyed by the wallet's address for that domain; a domain that
/// nets to zero is omitted.
fn plan_effects(
    addresses: &MidnightAddresses,
    wallet_ua: &UserAddress,
    unshielded_offers: &[&UnshieldedOffer<MnSig, InMemoryDB>],
    shielded_plans: &[ShieldedSpendPlan],
    dust_outflow: u128,
) -> Vec<TransactionEffect> {
    let mut night: i128 = 0;
    for offer in unshielded_offers {
        for i in offer.inputs.iter_deref() {
            if i.type_ == NIGHT {
                night -= i.value as i128;
            }
        }
        for o in offer.outputs.iter_deref() {
            if o.type_ == NIGHT && o.owner == *wallet_ua {
                night += o.value as i128;
            }
        }
    }

    let mut shielded: BTreeMap<ShieldedTokenType, i128> = BTreeMap::new();
    for plan in shielded_plans {
        for coin in &plan.coins {
            *shielded.entry(coin.type_).or_default() -= coin.value as i128;
        }
        for (token, change) in &plan.change {
            *shielded.entry(*token).or_default() += *change as i128;
        }
    }

    let mut effects = Vec::new();
    if night != 0 {
        effects.push(TransactionEffect {
            address: addresses.unshielded.clone(),
            diff: vec![(
                TokenType::Native.to_wire_token_type(),
                clamp_i128_to_i64(night),
            )],
        });
    }
    let shielded_diff: Vec<(String, i64)> = shielded
        .into_iter()
        .filter(|(_, v)| *v != 0)
        .map(|(token, v)| (hex::encode(token.into_inner().0), clamp_i128_to_i64(v)))
        .collect();
    if !shielded_diff.is_empty() {
        effects.push(TransactionEffect {
            address: addresses.shielded.clone(),
            diff: shielded_diff,
        });
    }
    if dust_outflow != 0 {
        effects.push(TransactionEffect {
            address: addresses.dust.clone(),
            diff: vec![(
                "dust".to_string(),
                clamp_i128_to_i64(-(dust_outflow as i128)),
            )],
        });
    }
    effects
}

/// Plan the wallet's shielded funding for a proven tx's shielded deficit (e.g. a contract deposit
/// whose Zswap offer has outputs but no inputs): sync the wallet, then per intent segment choose the
/// coins to spend (whole, largest-first) and the self-change to mint — threading coin consumption
/// across segments so no coin is planned twice. Pure selection over the synced coin set — no spend,
/// no proving. Returns `None` when the tx has no shielded shortfall.
fn plan_shielded_funding(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    crypto_provider: &MidnightCryptoProvider,
    indexer_url: &str,
    scope: &SyncCacheScope,
) -> Result<Option<ShieldedFundingPlan>, std::io::Error> {
    // A shielded shortfall can sit in the guaranteed offer (segment 0) or in any fallible offer
    // (segment N>=1); gate on either needing inputs. `ledger_shielded_deficits` then reports the
    // per-segment deficits across the whole tx via `balance()`.
    let guaranteed_needs = base
        .guaranteed_coins
        .as_ref()
        .is_some_and(|sp| zswap_offer_needs_shielded_inputs(sp.deref()));
    let fallible_needs = base
        .fallible_coins
        .iter()
        .any(|entry| zswap_offer_needs_shielded_inputs(entry.1.deref()));
    let deficits = if guaranteed_needs || fallible_needs {
        ledger_shielded_deficits(&Transaction::Standard(base.clone()))?
    } else {
        Vec::new()
    };
    if deficits.is_empty() {
        return Ok(None);
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
        return Ok(None);
    }
    Ok(Some(ShieldedFundingPlan { plans, tree }))
}

/// One intent's fallible unshielded NIGHT deficit: the segment it sits in, the NIGHT the wallet must
/// supply there, and that offer's own outputs (re-emitted by the balancing offer that replaces it).
struct FallibleNightDeficit {
    seg_id: u16,
    need_night: u128,
    outputs: Vec<UtxoOutput>,
}

/// Build the local [`Prover`](crate::Prover) for a chain's vault-rooted proving-key directory.
/// Keyless: the prover holds proving/verifier keys, never a wallet secret. A fresh one is built per
/// authorized section so their proving randomness is independent.
pub(crate) fn midnight_prover(chain_id: &str) -> Result<crate::Prover, std::io::Error> {
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let dir = crate::cache_io::proving_keys_dir(&scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    Ok(crate::Prover::new(dir))
}

/// Plan (but do not authorize) the balancing of an already-proven (`proof,embedded-fr`) unsealed
/// Standard transaction: parse it, plan the wallet's shielded funding, build the balanced unshielded
/// offer, and size the DUST fee — all without real proving. The returned [`BalancedPlan`] carries no
/// bearer instrument; the authorizing `spend()`/`prove()` happen later, in the signer, past the seam.
#[allow(clippy::too_many_arguments)]
/// Reject a transaction whose ledger network id does not match the chain we're signing for, so a
/// mainnet tx can never be balanced/signed while pointed at a testnet (or an ad-hoc feature testnet
/// at another). Matched case-insensitively: a Midnight tx body may carry a capitalized network name.
fn ensure_tx_network_id_matches_chain(
    chain_id: &str,
    tx_network_id: &str,
) -> Result<(), std::io::Error> {
    let expected = MidnightNetwork::from_chain_id(chain_id);
    let expected = expected.ledger_network_id();
    if !tx_network_id.eq_ignore_ascii_case(expected) {
        return Err(err(format!(
            "transaction network id {tx_network_id:?} does not match chain {chain_id} \
             (expected {expected:?})"
        )));
    }
    Ok(())
}

fn plan_unsealed_proven_standard_tx(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    tx_bytes: &[u8],
    pay_fees: bool,
    scope: &SyncCacheScope,
) -> Result<BalancedPlan, std::io::Error> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProven = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse proven tx bytes: {e}")))?;
    let Transaction::Standard(mut base) = tx else {
        // The only other Transaction variant is ClaimRewards — a system-issued mint claim that is
        // claimed, not balanced with counter-offers, so it is not a balancing target.
        return Err(err(
            "balanceUnsealedTransaction expects a Standard transaction; a ClaimRewards mint claim \
             is not a balancing target",
        ));
    };

    if let Some(chain_id) = scope.chain_id.as_deref() {
        ensure_tx_network_id_matches_chain(chain_id, &base.network_id)?;
    }

    // Plan a shielded deficit (e.g. a contract deposit) against the wallet's own shielded coins — a
    // no-op when the tx has no shielded shortfall. Pure selection: no spend, no prove.
    let shielded = plan_shielded_funding(&base, crypto_provider, indexer_url, scope)?;

    // The guaranteed unshielded section aggregates one offer from each intent, so balancing spans every
    // intent: sum the NIGHT the wallet must supply across all of them, reject shapes it cannot authorize,
    // and fold its inputs + change into a single chosen intent (the lowest segment) while leaving the
    // others intact.
    // Fees are paid from a DUST section, so one is added only on a live-DUST chain. When fees are
    // requested but liveness can't be confirmed, fail loud rather than silently emit a fee-less tx the
    // node would reject — the probe is fail-safe and cannot tell a genuinely fee-less network from a
    // flaky probe, so on a fee-less network the caller opts out with `payFees: false`.
    let adding_dust = if pay_fees {
        if crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(indexer_url)) {
            true
        } else {
            return Err(err(
                "could not confirm the network's DUST ledger is live; refusing to build a fee-less \
                 transaction the node may reject — retry, or pass payFees:false if this network has no \
                 DUST fees",
            ));
        }
    } else {
        false
    };
    let mut need_night: u128 = 0;
    let mut fallible_deficits: Vec<FallibleNightDeficit> = Vec::new();
    let mut has_preexisting_dust = false;
    let mut chosen: Option<(
        u16,
        Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    )> = None;
    for pair in base.intents.iter() {
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let intent = intent_sp.deref();
        // A dust section the tx already carries is fine — the wallet's own dust rides a fresh intent
        // below, since an intent holds only one dust section (spec §L961-967). But it must not carry a
        // dust *registration*: unlike a proof-authorized dust *spend* (which passes through untouched), a
        // registration is signature-authorized, so a foreign one needs a signer the wallet lacks, and one
        // for the wallet's own key is redundant with the dust the wallet adds here and muddies the fee
        // accounting.
        if let Some(da) = intent.dust_actions.as_ref() {
            has_preexisting_dust = true;
            if adding_dust && !da.deref().registrations.is_empty() {
                return Err(err(
                    "transaction already carries a dust fee registration, which is unsupported",
                ));
            }
        }
        if let Some(offer_sp) = intent.guaranteed_unshielded_offer.as_ref() {
            let offer = offer_sp.deref();
            // The wallet supplies (and signs) the balancing inputs; it cannot sign inputs the dapp put
            // in an intent, so reject any that are already present.
            if offer.inputs.iter_deref().next().is_some() {
                return Err(err(
                    "transaction carries dapp-provided unshielded inputs, which is unsupported",
                ));
            }
            for o in offer.outputs.iter_deref() {
                if o.type_ == NIGHT {
                    need_night = need_night.saturating_add(o.value);
                }
            }
        }
        // A fallible unshielded offer is balanced in its own segment (each is checked independently), so
        // its NIGHT deficit is collected per-segment rather than folded into `need_night`.
        if let Some(foffer_sp) = intent.fallible_unshielded_offer.as_ref() {
            let foffer = foffer_sp.deref();
            if foffer.inputs.iter_deref().next().is_some() {
                return Err(err(
                    "transaction carries dapp-provided fallible unshielded inputs, which is unsupported",
                ));
            }
            let mut fneed = 0u128;
            let outputs: Vec<UtxoOutput> = foffer
                .outputs
                .iter_deref()
                .map(|o| {
                    if o.type_ == NIGHT {
                        fneed = fneed.saturating_add(o.value);
                    }
                    UtxoOutput {
                        value: o.value,
                        owner: o.owner,
                        type_: o.type_,
                    }
                })
                .collect();
            if fneed > 0 {
                fallible_deficits.push(FallibleNightDeficit {
                    seg_id,
                    need_night: fneed,
                    outputs,
                });
            }
        }
        let is_lower = match &chosen {
            Some((s, _)) => seg_id < *s,
            None => true,
        };
        if is_lower {
            chosen = Some((seg_id, intent.clone()));
        }
    }

    // Where the wallet folds its balancing inputs + dust: an existing intent when there is one to reuse,
    // else a fresh skeleton — a pure-shielded zswap offer (MIP-0005/0006) has empty intents, and a
    // preexisting dust section blocks reuse (see `balancing_intent`).
    let (seg_id, intent_in, outputs_in) =
        balancing_intent(&base, chosen, adding_dust, has_preexisting_dust);

    // Fetch the wallet's UTXOs once; the guaranteed offer and each per-segment fallible offer draw
    // disjoint coins from this pool so no coin is spent twice.
    let pool = crate::block_on(
        crate::wallet_sync::unshielded::get_unshielded_utxos_for_display(
            indexer_url,
            sender_addr,
            scope,
        ),
    )?;
    let mut claimed: Vec<UtxoKey> = Vec::new();

    // When paying a DUST fee, fetch the chain tip up front so the best-Dust NIGHT coin can be reserved
    // for the generationless registration before the balancing inputs are selected. Reusing this tip
    // in the dust-sizing block below keeps it to a single fetch.
    let dust_tip = if adding_dust {
        Some(crate::block_on(crate::ledger_params::fetch_indexer_tip(
            indexer_url,
        ))?)
    } else {
        None
    };
    let registration_reserve = match &dust_tip {
        Some((_, tip_secs)) => {
            fee_sizing::pick_best_unregistered_for_dust(&pool, Timestamp::from_secs(*tip_secs))?
        }
        None => None,
    };

    let (offer, selected) = build_night_offer(
        &pool,
        &mut claimed,
        sender_vk,
        sender_addr,
        need_night,
        outputs_in,
        registration_reserve.as_ref(),
    )?;

    // Fund each fallible unshielded offer in its own segment from the same (now-partly-claimed) pool.
    let mut fallible_offers: Vec<(u16, UnshieldedOffer<MnSig, InMemoryDB>)> = Vec::new();
    for fd in &fallible_deficits {
        let (foffer, _fselected) = build_night_offer(
            &pool,
            &mut claimed,
            sender_vk,
            sender_addr,
            fd.need_night,
            fd.outputs.clone(),
            None,
        )?;
        fallible_offers.push((fd.seg_id, foffer));
    }

    // On DUST-fee chains, rotate the wallet's remaining unregistered NIGHT (beyond the coin reserved
    // for the registration) onto a fresh fallible segment: consolidate it into a single self-output so
    // it is spent off the budget-tight guaranteed section. Balance-neutral (inputs equal the one
    // change output), so it cannot unbalance the transaction; gated on a reservation existing and at
    // least two leftover coins to fold.
    //
    // NOTE: structurally sound and balance-neutral (covered by tx_balance tests), but the submit-path
    // interaction with DUST-generation registration has not been validated against a live prover /
    // indexer — validate before relying on it for real NIGHT movement.
    if adding_dust && registration_reserve.is_some() {
        let night_wire = crate::parse_token_type(Some("night"))?.to_wire_token_type();
        let leftovers: Vec<UnshieldedUtxo> = pool
            .iter()
            .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
            .filter(|u| !u.registered_for_dust_generation)
            .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
            .cloned()
            .collect();
        if leftovers.len() >= 2 {
            let coffer = build_fallible_consolidation_offer(
                &leftovers,
                &mut claimed,
                sender_vk,
                sender_addr,
            )?;
            // A fresh segment distinct from every existing intent and the chosen balancing segment.
            let seg = fresh_segment_id(&base).max(seg_id.saturating_add(1));
            let tip_secs = dust_tip.as_ref().map(|(_, t)| *t).unwrap_or(0);
            let mut consolidation_intent = empty_intent_skeleton();
            consolidation_intent.fallible_unshielded_offer = Some(Sp::new(coffer));
            consolidation_intent.ttl = chain_aligned_intent_ttl(Timestamp::from_secs(tip_secs));
            base.intents = base.intents.insert(seg, consolidation_intent);
        }
    }

    // Size the DUST fee against a stand-in tx that already carries the shielded section (mock-proved,
    // fixed-size) and the fallible balancing offers, so the fee — which covers the whole tx — is right
    // even though the real shielded proving is deferred past the seam.
    let mut stx_for_sizing = match &shielded {
        Some(s) => fee_sizing::splice_mock_shielded_for_sizing(&base, crypto_provider, s)?,
        None => base.clone(),
    };
    for (seg, foffer) in &fallible_offers {
        attach_fallible_offer(&mut stx_for_sizing, *seg, foffer);
    }
    // The chosen intent is rebuilt (guaranteed offer + dust) during sizing and authorization, so its
    // own fallible offer, if any, must be threaded into that rebuild rather than left where the rebuild
    // would drop it.
    let chosen_fallible = fallible_offers
        .iter()
        .find(|(s, _)| *s == seg_id)
        .map(|(_, o)| o.clone());

    // On a chain with a live dust ledger (Preview/Preprod, mainnet too), fees are paid with a DUST
    // section: a generationless registration signed by the wallet (no proof) when it has unregistered
    // NIGHT, otherwise a proof-bearing spend of its generated dust. Both that section and an
    // hour-past-tip TTL need the chain time, so fetch the tip once (it also carries the ledger
    // parameters used to size the fee). The fee is sized here without real proving; the proof-bearing
    // spend is realized post-seam by the signer.
    let (dust, intent_ttl) = if adding_dust {
        let (ledger_params, tip_secs) = dust_tip.expect("dust tip fetched above when adding_dust");
        let dust_ctime = Timestamp::from_secs(tip_secs);
        let dust_pk = crypto_provider
            .dust_public_key()
            .map_err(|e| err(e.to_string()))?;
        let night_vk = sender_vk.clone();
        let dust = fee_sizing::size_dust_fee(&DustFeeContext {
            stx: &stx_for_sizing,
            seg_id,
            intent_in: &intent_in,
            offer: &offer,
            fallible_offer: chosen_fallible.as_ref(),
            selected: &selected,
            dust_pk,
            night_vk,
            crypto_provider,
            dust_ctime,
            ledger_params: &ledger_params,
            indexer_url,
            scope,
        })?;
        (dust, chain_aligned_intent_ttl(dust_ctime))
    } else {
        (DustFeePlan::None, intent_in.ttl)
    };

    Ok(BalancedPlan {
        base,
        seg_id,
        intent_in,
        unshielded_offer: offer,
        fallible_offers,
        intent_ttl,
        shielded,
        dust,
    })
}

/// Authorize a [`BalancedPlan`] into balanced-but-unsealed proven transaction bytes. The wallet's
/// shielded/dust spend witnesses are built and proved **in the signer** — this hands the
/// `crypto_provider` its [`MidnightCryptoProvider::authorize_shielded`] / `authorize_dust` methods,
/// which build and consume the bearer preimage internally; only proven sections cross back. So this
/// runs **after** the policy seam. The proven shielded fragments are merged into the guaranteed offer
/// (folding in their binding-randomness delta, since a proven tx can't recompute its own Pedersen
/// binding) and the DUST section attached; the tx is then serialized. Signing and sealing are separate
/// downstream steps.
pub fn authorize_proven_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    plan: BalancedPlan,
) -> Result<Vec<u8>, std::io::Error> {
    let mut base = plan.base;

    // Shielded: the signer builds + proves the witnesses; route each proven fragment to the offer the
    // signer bound it to — segment 0 into the guaranteed offer, segment N>=1 into `fallible_coins[N]`.
    if let Some(shielded) = plan.shielded {
        let prover = midnight_prover(chain_id)?;
        let authorized: ShieldedAuthorized = crate::block_on(crypto_provider.authorize_shielded(
            &shielded.plans,
            &shielded.tree,
            prover,
        ))
        .map_err(|e| err(e.to_string()))?;
        for (segment, proven) in &authorized.proven {
            place_shielded_fragment(&mut base, *segment, proven)?;
        }
        // Binding randomness is tx-global (placement-independent), so add the whole delta once.
        base.binding_randomness = base.binding_randomness + authorized.binding_delta;
    }

    // DUST: the registration was finalized during planning (keyless, no bearer instrument); the
    // proof-bearing spend is realized here, in the signer.
    let dust_actions = match plan.dust {
        DustFeePlan::None => None,
        DustFeePlan::Registration(reg) => Some(reg),
        DustFeePlan::Spend {
            plan: dust_plan,
            dust_state,
            ledger_params,
        } => {
            let prover = midnight_prover(chain_id)?;
            let section = crate::block_on(crypto_provider.authorize_dust(
                &dust_state,
                &dust_plan,
                &ledger_params,
                prover,
            ))
            .map_err(|e| err(e.to_string()))?;
            Some(section)
        }
    };

    // Fallible unshielded offers: attach each to the intent in its own segment. The chosen intent is
    // rebuilt just below (guaranteed offer + dust), so its fallible offer is threaded into that rebuild
    // instead; every other fallible offer is attached here directly.
    let chosen_fallible = plan
        .fallible_offers
        .iter()
        .find(|(s, _)| *s == plan.seg_id)
        .map(|(_, o)| o.clone());
    for (seg, foffer) in &plan.fallible_offers {
        if *seg != plan.seg_id {
            attach_fallible_offer(&mut base, *seg, foffer);
        }
    }

    let intent_out = assemble_proven_intent(
        &plan.unshielded_offer,
        chosen_fallible.as_ref(),
        &plan.intent_in,
        dust_actions,
        plan.intent_ttl,
    );
    let tx_out = wrap_proven_standard(&base, plan.seg_id, intent_out);

    let imbalances = tx_balance_imbalances(&tx_out)?;
    if !imbalances.is_empty() {
        return Err(err(format!(
            "authorized transaction is still ledger-imbalanced ({})",
            imbalances.join("; ")
        )));
    }

    let mut out = Vec::new();
    tagged_serialize(&tx_out, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Plan the balancing of an already-proven (`proof,embedded-fr`) unsealed connector transaction
/// against the wallet's own UTXOs, deriving the sender address/vk via the crypto provider and the
/// indexer URL and sync scope from `chain_id`. The returned [`BalancedPlan`] is inert (no bearer
/// instrument) — it is authorized into signable bytes by [`authorize_proven_tx`] after the policy seam.
pub fn plan_unsealed_proven_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    tx_bytes: &[u8],
    pay_fees: bool,
) -> Result<BalancedPlan, std::io::Error> {
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

    plan_unsealed_proven_standard_tx(
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

    /// An empty unshielded offer (no inputs/outputs/signatures) — a placeholder for tests that only
    /// exercise intent structure, not balancing.
    fn empty_offer() -> UnshieldedOffer<MnSig, InMemoryDB> {
        UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![].into(),
            signatures: vec![].into(),
        }
    }

    /// A proven intent carrying `offer` as its guaranteed offer plus optional dust, at a **nonzero**
    /// binding commitment so tests can observe whether it is perturbed.
    fn intent_with(
        offer: Option<UnshieldedOffer<MnSig, InMemoryDB>>,
        dust: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ) -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
        Intent {
            guaranteed_unshielded_offer: offer.map(Sp::new),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: dust.map(Sp::new),
            ttl: Timestamp::from_secs(0),
            binding_commitment: PedersenRandomness::from(7),
        }
    }

    fn base_with_intents(
        intents: Vec<(
            u16,
            Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
        )>,
    ) -> StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
        let mut map: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new();
        for (seg, intent) in intents {
            map = map.insert(seg, intent);
        }
        StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents: map,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: PedersenRandomness::from(0),
        }
    }

    /// The fresh segment is one past the current maximum, and 1 when there are no intents — never 0
    /// (reserved for the guaranteed section).
    #[test]
    fn fresh_segment_id_is_one_past_the_max() {
        let base = base_with_intents(vec![
            (2, intent_with(None, None)),
            (5, intent_with(None, None)),
        ]);
        assert_eq!(fresh_segment_id(&base), 6);
        assert_eq!(fresh_segment_id(&base_with_intents(vec![])), 1);
    }

    /// The skeleton that carries a wallet dust section onto a fresh segment is empty and
    /// binding-neutral (zero `binding_commitment`), so adding it leaves the tx's `binding_randomness`
    /// untouched.
    #[test]
    fn empty_intent_skeleton_is_empty_and_binding_neutral() {
        let s = empty_intent_skeleton();
        assert_eq!(s.binding_commitment, PedersenRandomness::from(0));
        assert!(s.guaranteed_unshielded_offer.is_none());
        assert!(s.fallible_unshielded_offer.is_none());
        assert!(s.dust_actions.is_none());
        assert_eq!(s.actions.len(), 0);
    }

    /// A pure-shielded tx (a MIP-0005/0006 `zswapoffer` wraps into a Standard tx with an **empty**
    /// `intents` map) has no intent to fold the taker's dust fee into. The balancer must synthesize a
    /// fresh binding-neutral skeleton at segment 1 rather than error "expected at least one intent
    /// segment" — this is the fix for balancing a bare zswap offer.
    #[test]
    fn empty_intents_get_a_fresh_balancing_skeleton() {
        let base = base_with_intents(vec![]);
        let (seg_id, intent_in, outputs_in) = balancing_intent(&base, None, true, false);
        assert_eq!(
            seg_id, 1,
            "first fresh segment, never the guaranteed section 0"
        );
        assert!(intent_in.guaranteed_unshielded_offer.is_none());
        assert!(intent_in.dust_actions.is_none());
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(0),
            "a synthesized skeleton is binding-neutral"
        );
        assert!(outputs_in.is_empty());
    }

    /// With a reusable intent and no preexisting dust, the wallet folds into that intent (keeping its
    /// segment and re-emitting its outputs) instead of synthesizing a new one.
    #[test]
    fn balancing_intent_reuses_an_existing_intent() {
        let base = base_with_intents(vec![(3, intent_with(None, None))]);
        let (seg_id, intent_in, _outputs) =
            balancing_intent(&base, Some((3, intent_with(None, None))), true, false);
        assert_eq!(seg_id, 3, "reused, not a fresh segment");
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(7),
            "the existing intent, not a fresh skeleton"
        );
    }

    /// A preexisting dust section forces a fresh skeleton even when a reusable intent exists, because an
    /// intent holds only one dust section and the wallet's dust needs its own timestamp.
    #[test]
    fn preexisting_dust_forces_a_fresh_skeleton() {
        let base = base_with_intents(vec![(3, intent_with(None, None))]);
        let (seg_id, intent_in, _outputs) =
            balancing_intent(&base, Some((3, intent_with(None, None))), true, true);
        assert_eq!(seg_id, 4, "fresh, one past the existing max segment (3)");
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(0),
            "a fresh skeleton, not the existing intent"
        );
    }

    /// Merging into a dapp intent that already carries its own dust must not drop it when the wallet
    /// supplies no dust of its own; the wallet's dust wins when it does.
    #[test]
    fn assemble_preserves_a_dapp_intents_own_dust() {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let intent_in = intent_with(None, Some(dust_fee_registration(&vk)));

        // No dust of our own → the intent's existing dust survives.
        let kept = assemble_proven_intent(
            &empty_offer(),
            None,
            &intent_in,
            None,
            Timestamp::from_secs(0),
        );
        assert!(
            kept.dust_actions.is_some(),
            "merging must not drop the intent's own dust"
        );

        // Our own dust replaces it when supplied.
        let ours = dust_fee_registration(&vk);
        let replaced = assemble_proven_intent(
            &empty_offer(),
            None,
            &intent_in,
            Some(ours.clone()),
            Timestamp::from_secs(0),
        );
        assert_eq!(
            replaced.dust_actions.as_ref().unwrap().deref().ctime,
            ours.ctime
        );
    }

    /// Placing the wallet's balancing offer at a fresh segment (the Gap C new-intent path) adds an
    /// intent without touching the existing ones or the tx's binding randomness.
    #[test]
    fn wrap_at_a_fresh_segment_adds_without_disturbing_the_rest() {
        let base = base_with_intents(vec![(2, intent_with(Some(empty_offer()), None))]);
        let orig_binding = base.binding_randomness;
        let fresh = fresh_segment_id(&base);
        assert_eq!(fresh, 3);

        let new_intent = assemble_proven_intent(
            &empty_offer(),
            None,
            &empty_intent_skeleton(),
            None,
            Timestamp::from_secs(0),
        );
        let Transaction::Standard(stx) = wrap_proven_standard(&base, fresh, new_intent) else {
            panic!("standard");
        };

        let segs: Vec<u16> = stx.intents.iter().map(|p| *p.deref().0.deref()).collect();
        assert_eq!(
            stx.intents.iter().count(),
            2,
            "the original intent survives"
        );
        assert!(segs.contains(&2) && segs.contains(&3));
        assert_eq!(
            stx.binding_randomness, orig_binding,
            "a binding-neutral intent leaves binding_randomness untouched"
        );
    }

    /// The wallet's verifying-key as the lowercase hex the indexer reports for a UTXO owner.
    fn sender_vk_hex() -> String {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let mut raw = Vec::new();
        vk.serialize(&mut raw).unwrap();
        hex::encode(raw)
    }

    /// A sender-owned NIGHT UTXO for the coin pool; `ih_byte` makes each one a distinct coin.
    fn night_pool_utxo(vk_hex: &str, value: u128, ih_byte: u8, out_idx: i64) -> UnshieldedUtxo {
        UnshieldedUtxo {
            token_type: "00".repeat(32),
            value,
            intent_hash: hex::encode([ih_byte; 32]),
            output_index: out_idx,
            owner: vk_hex.to_string(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    /// Two offers drawn from the same pool never spend the same coin: the second call skips the coin the
    /// first claimed.
    #[test]
    fn build_night_offer_claims_disjoint_coins() {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let vk_hex = sender_vk_hex();
        let pool = vec![
            night_pool_utxo(&vk_hex, 100, 1, 0),
            night_pool_utxo(&vk_hex, 100, 2, 0),
        ];
        let mut claimed: Vec<UtxoKey> = Vec::new();

        let (_o1, s1) =
            build_night_offer(&pool, &mut claimed, &vk, "sender", 60, vec![], None).unwrap();
        let (_o2, s2) =
            build_night_offer(&pool, &mut claimed, &vk, "sender", 60, vec![], None).unwrap();

        assert_eq!(s1.len(), 1);
        assert_eq!(s2.len(), 1);
        assert_ne!(
            s1[0].intent_hash, s2[0].intent_hash,
            "coins must be disjoint"
        );
        assert_eq!(claimed.len(), 2);
    }

    /// With no NIGHT payment (need_night = 0) a reserved best-Dust coin is still spent — so its
    /// unregistered-NIGHT capacity can back the generationless registration — and its value returns
    /// as change, so the offer nets to zero (one input, matching output value).
    #[test]
    fn build_night_offer_reserves_the_dust_coin_balance_neutrally() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        let reserve = night_pool_utxo(&vk_hex, 5_000_000, 7, 0);
        let pool = vec![reserve.clone()];
        let mut claimed = Vec::new();
        let (offer, selected) = build_night_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            0,
            vec![],
            Some(&reserve),
        )
        .unwrap();

        assert_eq!(selected.len(), 1, "the reserved coin is spent");
        assert_eq!(selected[0].intent_hash, reserve.intent_hash);
        assert_eq!(claimed.len(), 1);
        assert_eq!(offer.inputs.iter_deref().count(), 1);
        let out_total: u128 = offer.outputs.iter_deref().map(|o| o.value).sum();
        assert_eq!(
            out_total, reserve.value,
            "change returns the full input value"
        );
    }

    /// A balancing offer with no inputs and no outputs carries nothing in the guaranteed section, so the
    /// assembled intent drops it to None rather than emitting a degenerate 0-in/0-out offer — the shape a
    /// fee-less transfer takes once its NIGHT movement rides the fallible offer.
    #[test]
    fn assemble_proven_intent_drops_an_empty_guaranteed_offer_to_none() {
        let empty: UnshieldedOffer<MnSig, InMemoryDB> = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![].into(),
            signatures: vec![].into(),
        };
        let intent = assemble_proven_intent(
            &empty,
            None,
            &empty_intent_skeleton(),
            None,
            Timestamp::from_secs(0),
        );
        assert!(
            intent.guaranteed_unshielded_offer.is_none(),
            "an empty balancing offer must not become a guaranteed offer"
        );
    }

    /// Consolidating several of the wallet's own NIGHT coins into one self-output is balance-neutral:
    /// attached to a fresh fallible segment, that segment nets to zero per the ledger's own balance().
    #[test]
    fn fallible_consolidation_offer_nets_the_segment_to_zero() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        let coins = vec![
            night_pool_utxo(&vk_hex, 100, 1, 0),
            night_pool_utxo(&vk_hex, 250, 2, 0),
        ];
        let mut claimed = Vec::new();
        let offer =
            build_fallible_consolidation_offer(&coins, &mut claimed, &vk, "sender").unwrap();

        // Both coins are spent and folded into a single change output of their full value.
        assert_eq!(offer.inputs.iter_deref().count(), 2);
        let out_total: u128 = offer.outputs.iter_deref().map(|o| o.value).sum();
        assert_eq!(out_total, 350);
        assert_eq!(claimed.len(), 2);

        // On a fresh fallible segment, the ledger sees the segment as balanced.
        let mut intent = empty_intent_skeleton();
        intent.fallible_unshielded_offer = Some(Sp::new(offer));
        let base = base_with_intents(vec![(3, intent)]);
        let imbalances = tx_balance_imbalances(&Transaction::Standard(base)).unwrap();
        assert!(
            imbalances.is_empty(),
            "consolidation must net to zero: {imbalances:?}"
        );
    }

    /// Funding a fallible unshielded offer in its own segment nets that segment to zero — the core Gap B
    /// invariant, checked via the ledger's own `balance()`.
    #[test]
    fn fallible_balancing_nets_the_segment_to_zero() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        // A dapp fallible offer at segment 2: a 100-NIGHT output, no inputs (the deficit).
        let dapp_out = UtxoOutput {
            value: 100,
            owner: UserAddress::from(vk.clone()),
            type_: NIGHT,
        };
        let dapp_fallible = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![dapp_out.clone()].into(),
            signatures: vec![].into(),
        };
        let mut intent = intent_with(None, None);
        intent.fallible_unshielded_offer = Some(Sp::new(dapp_fallible));
        let base = base_with_intents(vec![(2, intent)]);

        // Before balancing, segment 2 is overspent by the 100-NIGHT output.
        assert!(!tx_balance_imbalances(&Transaction::Standard(base.clone()))
            .unwrap()
            .is_empty());

        // Build the wallet's fallible balancing offer (a 100-coin covers the 100 deficit; the dapp's
        // output is re-emitted), attach it to segment 2, and confirm the segment nets to zero.
        let pool = vec![night_pool_utxo(&vk_hex, 100, 1, 0)];
        let mut claimed = Vec::new();
        let (foffer, _) = build_night_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            100,
            vec![dapp_out],
            None,
        )
        .unwrap();
        let mut balanced = base;
        attach_fallible_offer(&mut balanced, 2, &foffer);

        let imbalances = tx_balance_imbalances(&Transaction::Standard(balanced)).unwrap();
        assert!(
            imbalances.is_empty(),
            "fallible segment must be balanced: {imbalances:?}"
        );
    }

    /// A proven tx whose single intent carries both a guaranteed and a fallible wallet input, at a
    /// non-zero segment — the shape the signer must sign across both offers.
    fn build_proven_tx_with_fallible(vk: &VerifyingKey) -> Vec<u8> {
        let night_offer = |value: u128, ih: u8| UnshieldedOffer {
            inputs: vec![UtxoSpend {
                value,
                owner: vk.clone(),
                type_: NIGHT,
                intent_hash: IntentHash(HashOutput([ih; 32])),
                output_no: 0,
            }]
            .into(),
            outputs: vec![UtxoOutput {
                value,
                owner: UserAddress::from(vk.clone()),
                type_: NIGHT,
            }]
            .into(),
            signatures: vec![].into(),
        };
        let intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(night_offer(1_000_000, 7))),
            fallible_unshielded_offer: Some(Sp::new(night_offer(500_000, 8))),
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1, intent);
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

    /// Sign + seal a tx with both a guaranteed and a fallible wallet input: the sealed tx carries a
    /// signature on *each* offer (the ledger's `Intent::sign` signs both).
    #[test]
    fn sign_and_seal_covers_the_fallible_offer_inputs() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_tx_with_fallible(&vk);

        // Two signatures: one guaranteed input, one fallible input.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        let mut r: &[u8] = &out.signature[..];
        let _a = MnSig::deserialize(&mut r, 0).unwrap();
        let _b = MnSig::deserialize(&mut r, 0).unwrap();
        assert!(r.is_empty(), "expected exactly two signatures");

        // Seal: each offer carries its own input's signature.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut sr: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut sr).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, intent_sp) = pair.deref();
        let intent = intent_sp.deref();
        let g_sigs = intent
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        let f_sigs = intent
            .fallible_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(g_sigs, 1, "guaranteed input must be signed");
        assert_eq!(f_sigs, 1, "fallible input must be signed");
    }

    #[test]
    fn tx_network_id_must_match_chain() {
        // Exact and case-insensitive matches pass; a custom feature testnet matches its reference.
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "preview").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "Preview").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:mainnet", "mainnet").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:feature-x", "feature-x").is_ok());

        // Mismatches are rejected — never balance a mainnet tx while pointed at a testnet, or a
        // tx built for one custom net while signing for another.
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "mainnet").is_err());
        assert!(ensure_tx_network_id_matches_chain("midnight:mainnet", "preview").is_err());
        assert!(ensure_tx_network_id_matches_chain("midnight:feature-x", "preview").is_err());
    }

    // --- plan_effects: the wallet-relative effects the policy seam gates on ---

    fn addrs() -> MidnightAddresses {
        MidnightAddresses {
            unshielded: "mn_addr_unshielded".into(),
            shielded: "mn_shield_addr".into(),
            dust: "mn_dust_addr".into(),
        }
    }

    fn vk_of(seed_hex: &str) -> VerifyingKey {
        MidnightSigningKey::from_bytes(&hex::decode(seed_hex).unwrap())
            .unwrap()
            .verifying_key()
    }

    fn night_input(value: u128, owner: VerifyingKey) -> UtxoSpend {
        UtxoSpend {
            value,
            owner,
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([9u8; 32])),
            output_no: 0,
        }
    }

    fn night_output(value: u128, owner: UserAddress) -> UtxoOutput {
        UtxoOutput {
            value,
            owner,
            type_: NIGHT,
        }
    }

    fn offer(
        inputs: Vec<UtxoSpend>,
        outputs: Vec<UtxoOutput>,
    ) -> UnshieldedOffer<MnSig, InMemoryDB> {
        UnshieldedOffer {
            inputs: inputs.into(),
            outputs: outputs.into(),
            signatures: vec![].into(),
        }
    }

    /// Unshielded balancing: the wallet's input is outflow, its own change is inflow, and the dapp's
    /// output (not the wallet's) is excluded — so the net is exactly the NIGHT the wallet funded.
    #[test]
    fn plan_effects_unshielded_nets_input_minus_wallet_outputs() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let dapp_ua = UserAddress::from(vk_of(OTHER_SEED_HEX));
        let offer = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![
                night_output(300_000, wallet_ua), // wallet change
                night_output(700_000, dapp_ua),   // dapp recipient — excluded
            ],
        );
        let effects = plan_effects(&addrs(), &wallet_ua, &[&offer], &[], 0);
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].address, "mn_addr_unshielded");
        assert_eq!(
            effects[0].diff,
            vec![(TokenType::Native.to_wire_token_type(), -700_000)]
        );
    }

    /// A fallible per-segment offer funds NIGHT too, so its inputs and self-change net into the same
    /// unshielded effect as the guaranteed offer.
    #[test]
    fn plan_effects_sums_guaranteed_and_fallible_offers() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let guaranteed = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![night_output(400_000, wallet_ua)],
        );
        let fallible = offer(vec![night_input(200_000, wallet.clone())], vec![]);
        let effects = plan_effects(&addrs(), &wallet_ua, &[&guaranteed, &fallible], &[], 0);
        assert_eq!(effects.len(), 1);
        // -(1_000_000 + 200_000) + 400_000 = -800_000
        assert_eq!(
            effects[0].diff,
            vec![(TokenType::Native.to_wire_token_type(), -800_000)]
        );
    }

    /// Shielded funding nets spent coins against minted self-change, per token.
    #[test]
    fn plan_effects_shielded_nets_spend_minus_change() {
        let token = ShieldedTokenType(HashOutput([7u8; 32]));
        let plans = vec![ShieldedSpendPlan {
            segment: 0,
            coins: vec![qci(token, 100), qci(token, 40)],
            change: vec![(token, 20)],
        }];
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let effects = plan_effects(&addrs(), &wallet_ua, &[&offer(vec![], vec![])], &plans, 0);
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].address, "mn_shield_addr");
        assert_eq!(
            effects[0].diff,
            vec![(hex::encode(token.into_inner().0), -120)]
        );
    }

    /// A proof-bearing dust fee shows up as a negative `dust` movement.
    #[test]
    fn plan_effects_dust_outflow_is_negative_fee() {
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let effects = plan_effects(&addrs(), &wallet_ua, &[&offer(vec![], vec![])], &[], 50_000);
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].address, "mn_dust_addr");
        assert_eq!(effects[0].diff, vec![("dust".to_string(), -50_000)]);
    }

    /// All three domains at once, with a token spent across two segments summed into one effect.
    #[test]
    fn plan_effects_combines_domains_and_sums_segments() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let token = ShieldedTokenType(HashOutput([5u8; 32]));
        let offer = offer(
            vec![night_input(2_000_000, wallet.clone())],
            vec![night_output(500_000, wallet_ua)],
        );
        let plans = vec![
            ShieldedSpendPlan {
                segment: 0,
                coins: vec![qci(token, 100)],
                change: vec![(token, 30)],
            },
            ShieldedSpendPlan {
                segment: 1,
                coins: vec![qci(token, 50)],
                change: vec![],
            },
        ];
        let effects = plan_effects(&addrs(), &wallet_ua, &[&offer], &plans, 12_345);
        assert_eq!(effects.len(), 3);
        let night = effects
            .iter()
            .find(|e| e.address == "mn_addr_unshielded")
            .unwrap();
        assert_eq!(
            night.diff,
            vec![(TokenType::Native.to_wire_token_type(), -1_500_000)]
        );
        let shielded = effects
            .iter()
            .find(|e| e.address == "mn_shield_addr")
            .unwrap();
        // -(100 + 50) + 30 = -120
        assert_eq!(
            shielded.diff,
            vec![(hex::encode(token.into_inner().0), -120)]
        );
        let dust = effects
            .iter()
            .find(|e| e.address == "mn_dust_addr")
            .unwrap();
        assert_eq!(dust.diff, vec![("dust".to_string(), -12_345)]);
    }

    /// A domain that nets to zero (input fully returned as change) yields no effect.
    #[test]
    fn plan_effects_omits_zero_net_domains() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let offer = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![night_output(1_000_000, wallet_ua)],
        );
        assert!(plan_effects(&addrs(), &wallet_ua, &[&offer], &[], 0).is_empty());
    }
}
