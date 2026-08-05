//! DApp Connector `makeIntent`.
//!
//! `makeIntent(desiredInputs, desiredOutputs, options)` asks the wallet to build a **single-segment,
//! deliberately imbalanced** swap-offer intent — the maker side of a swap. The maker contributes real
//! inputs and declares the outputs it wants; a counterparty completes and balances it later
//! (`balanceSealedTransaction`). Because it is imbalanced by design, `makeIntent` does **not** run the
//! balancing tail: `authorize` builds the maker's inputs + outputs, proves them, and returns the
//! signable bytes for the downstream sign/seal.
//!
//! Scope: unshielded and shielded inputs (whole coins, with change back to the maker) and
//! unshielded/shielded outputs. The maker declares how much of a token it contributes; the wallet spends
//! whole coins covering that amount and returns the excess as change to the maker — so a shielded input
//! contributes exactly its declared value regardless of what token the offer wants back. The shielded
//! spend witnesses are built and proved in the signer ([`MidnightCryptoProvider::authorize_shielded`])
//! and the proved fragment is merged into the proved maker frame, so the bearer preimage never leaves the
//! signer.
//!
//! The offer's **expiry** is load-bearing in a way it is not for the other methods. `Intent.ttl` sits
//! inside the seal cover, and makeIntent runs no balancing tail, so nothing after this module can move
//! it — not the taker, not a service relaying the offer. It is also the maker's only unilateral way out:
//! a sealed offer is a bearer artifact, cancellable only by letting it expire or by double-spending one
//! of its inputs. Left at the wallet default it is the widest window the ledger allows, which is a free
//! option written against the maker's quoted price; `options.ttl` lets a maker that re-quotes often say
//! how long its price stands.
//!
//! Both the shielded and unshielded legs ride the transaction's **guaranteed section** (segment 0),
//! and — unlike `makeTransfer` — a swap keeps its NIGHT there rather than steering it to a fallible
//! segment. The ledger balances value **per segment**: every `(token, segment)` cell must net on its
//! own (a negative cell is `BalanceCheckOverspend`), and two parties' intents cannot share a segment
//! (`IntentSegmentIdCollision`). A swap is inherently cross-party, so the maker's unshielded spend and
//! the taker's unshielded receipt can only meet — and net — in segment 0, the one intent-free shared
//! section; steered to a fallible segment they would land in different segments and overspend.
//! (`makeTransfer` *can* ride a fallible segment precisely because it is single-party self-funded and
//! nets within its own segment.) Only a pure shielded↔shielded swap could anchor a fallible segment —
//! its zswap legs pool in `fallible_coins` — but that saves nothing (only the guaranteed *unshielded*
//! offer loads the segment-0 `time_to_dismiss` budget) and weakens the swap's all-or-nothing atomicity,
//! so makeIntent keeps every leg guaranteed. The maker's intent still keys at a fallible segment
//! (`intentSegment`); only the coins settle guaranteed. See [`GUARANTEED_SEGMENT`].

use std::collections::BTreeMap;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Info as CoinInfo, QualifiedInfo, ShieldedTokenType, UserAddress,
};
use midnight_ledger::structure::{
    Intent, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer,
    UtxoOutput, UtxoSpend,
};
use midnight_serialize::tagged_serialize;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::{
    MidnightCryptoProvider, MidnightNetwork, MidnightSigner, ShieldedSpendPlan,
};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::Deserialize;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::ProofPreimage;

use super::build::{
    decode_shielded_recipient, decode_unshielded_recipient, default_intent_ttl, deserialize_u128,
    effects_from_movements, err, max_ttl_secs, mock_prove_unsealed, now_secs, prove_preimage,
    prove_to_unsealed_bytes, wire_type_to_shielded, wire_type_to_unshielded, DesiredOutput,
    Movement, PreimageTx, TransferKind,
};
use crate::parse_token_type;
use ows_core::policy::TransactionEffect;

/// The connector convention default when a request omits `intentSegment`.
const DEFAULT_INTENT_SEGMENT: u16 = 1;

/// Segment 0 is the transaction's guaranteed section. A swap offer's shielded coins ride it — like
/// `makeTransfer` and `mip6` place theirs — so both legs of the swap sit in **one** segment. The ledger
/// applies each segment atomically (a segment-0 failure reverts the whole tx; a fallible segment fails
/// alone), so a swap split across the guaranteed and a fallible section could settle one leg and drop
/// the other. The intent itself still keys at a fallible segment (`intentSegment`); only the coins move.
/// The merge path reuses this for the taker complement's own coins, which settle guaranteed the same way.
pub(super) const GUARANTEED_SEGMENT: u16 = 0;

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

/// A parsed `makeIntent` request: the maker's inputs and desired outputs, the intent segment, and the
/// offer's expiry. Unlike the balancing methods, makeIntent builds a deliberately imbalanced maker offer
/// and never pays fees — the taker completes and balances the swap — so there is no `payFees` option here.
/// `ttl` is `None` when the request names no expiry, leaving the wallet's [`default_intent_ttl`].
#[derive(Debug, Clone)]
pub struct MakeIntentRequest {
    pub desired_inputs: Vec<DesiredInput>,
    pub desired_outputs: Vec<DesiredOutput>,
    pub intent_segment: u16,
    pub ttl: Option<Timestamp>,
}

fn default_intent_segment() -> u16 {
    DEFAULT_INTENT_SEGMENT
}

/// The `options` bag of a `makeIntent` request. Only `ttl` is read here: `payFees` does not apply to a
/// maker offer (the taker pays), and the segment is taken from the top-level `intentSegment`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeIntentOptions {
    ttl: Option<u64>,
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
    options: Option<MakeIntentOptions>,
}

/// Parse a stringified DApp Connector `makeIntent` request. `intentSegment` defaults to the connector
/// convention (segment 1) and must be >= 1; `options.ttl` defaults to the wallet's own
/// [`default_intent_ttl`] and must name an instant the ledger will still accept (see
/// [`parse_intent_ttl`]).
pub fn parse_make_intent_json(json: &str) -> Result<MakeIntentRequest, std::io::Error> {
    let req: MakeIntentJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid makeIntent request JSON: {e}")))?;
    if req.desired_inputs.is_empty() && req.desired_outputs.is_empty() {
        return Err(std::io::Error::other(
            "makeIntent requires at least one desired input or output",
        ));
    }
    // The ledger reserves segment 0 for the guaranteed section and rejects any intent declared there
    // (`IntentAtGuaranteedSegmentId`, surfaced by the node as `Custom error: 167`), so the maker's
    // intent must key at a fallible segment >= 1. makeTransfer hardcodes segment 1; makeIntent lets the
    // dapp choose, so guard the lower bound here rather than build an offer the node will reject.
    if req.intent_segment == 0 {
        return Err(std::io::Error::other(
            "makeIntent intentSegment must be >= 1: segment 0 is the guaranteed section, where the ledger rejects an intent",
        ));
    }
    Ok(MakeIntentRequest {
        desired_inputs: req.desired_inputs,
        desired_outputs: req.desired_outputs,
        intent_segment: req.intent_segment,
        ttl: parse_intent_ttl(req.options.and_then(|o| o.ttl), now_secs())?,
    })
}

/// Validate a requested expiry (Unix epoch seconds) against the window the ledger will accept for an
/// offer built *now*. Both bounds are the ledger's own, measured against the block the offer lands in
/// (`tblock`): it rejects `ttl < tblock` (`IntentTtlExpired`) and `ttl > tblock + global_ttl`
/// (`IntentTtlTooFarInFuture`). `tblock` is unknowable at build time but is never earlier than now, so
/// `now` is the conservative stand-in — an offer inside this window is acceptable whenever it settles,
/// and one outside it is rejected at build rather than after the maker has paid to prove it.
fn parse_intent_ttl(ttl: Option<u64>, now: u64) -> Result<Option<Timestamp>, std::io::Error> {
    let Some(ttl) = ttl else {
        return Ok(None);
    };
    if ttl <= now {
        return Err(std::io::Error::other(format!(
            "makeIntent options.ttl {ttl} is not in the future (now {now}): the offer would be born expired"
        )));
    }
    let max = now.saturating_add(max_ttl_secs());
    if ttl > max {
        return Err(std::io::Error::other(format!(
            "makeIntent options.ttl {ttl} is further ahead than the ledger's global_ttl ({}s) allows: at most {max}",
            max_ttl_secs()
        )));
    }
    Ok(Some(Timestamp::from_secs(ttl)))
}

/// The wallet-relative effects a `makeIntent` maker offer will have, derived from the request alone: the
/// maker contributes each desired input (outflow), and receives each desired output routed back to its
/// own address (inflow) — an output to some other recipient is not the maker's movement. The policy seam
/// gates on this before [`authorize`] proves anything.
pub(super) fn request_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<Vec<TransactionEffect>, std::io::Error> {
    let addresses = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?;
    let inputs = req.desired_inputs.iter().map(|i| Movement {
        kind: i.kind,
        token_type: &i.token_type,
        value: -(i.value as i128),
    });
    let outputs = req.desired_outputs.iter().filter_map(|o| {
        let self_addr = match o.kind {
            TransferKind::Unshielded => &addresses.unshielded,
            TransferKind::Shielded => &addresses.shielded,
        };
        (o.recipient == *self_addr).then_some(Movement {
            kind: o.kind,
            token_type: &o.token_type,
            value: o.value as i128,
        })
    });
    effects_from_movements(&addresses, inputs.chain(outputs))
}

/// The `makeIntent` maker offer's wallet-relative effects as [`request_effects`] computes them, all in
/// the transaction's guaranteed section ([`GUARANTEED_SEGMENT`]): a swap keeps every leg guaranteed — the
/// maker's coins settle in segment 0 even though its intent keys at a fallible `intentSegment` — so the
/// movement a policy sees is a guaranteed one. An offer that nets nothing yields no segment entry.
pub(super) fn request_segment_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<Vec<crate::balance_tx::SegmentEffects>, std::io::Error> {
    let effects = request_effects(chain_id, crypto_provider, req)?;
    Ok(crate::balance_tx::single_segment(
        GUARANTEED_SEGMENT,
        effects,
    ))
}

/// Build the maker's imbalanced offer, prove it, and return the signable bytes. Runs **after** the
/// policy seam. No balancing: the imbalance is the offer. When the maker contributes shielded inputs,
/// the frame (unshielded offer + shielded outputs) is proved first, then the signer builds and proves
/// the shielded spend witnesses and the proved fragment is merged in.
pub(super) fn authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: MakeIntentRequest,
) -> Result<Vec<u8>, std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);

    let (unshielded_in, shielded_in): (Vec<_>, Vec<_>) = req
        .desired_inputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);

    let frame = build_make_intent_frame(
        chain_id,
        &signer,
        crypto_provider,
        req.intent_segment,
        &unshielded_in,
        &unshielded_out,
        &shielded_out,
        !shielded_in.is_empty(),
        req.ttl,
    )?;

    // No shielded inputs: the frame is the whole maker offer; prove and return it.
    if shielded_in.is_empty() {
        return prove_to_unsealed_bytes(chain_id, frame);
    }

    // Shielded inputs: prove the frame, then have the signer build + prove the maker's shielded spend
    // witnesses (the bearer preimage is born and consumed there) and merge the proved fragment in.
    let proven = prove_preimage(chain_id, frame)?;
    let Transaction::Standard(mut base) = proven else {
        return Err(err("makeIntent frame is not a Standard transaction"));
    };
    authorize_shielded_inputs(
        chain_id,
        crypto_provider,
        GUARANTEED_SEGMENT,
        &shielded_in,
        &mut base,
    )?;

    let mut out = Vec::new();
    tagged_serialize(&Transaction::Standard(base), &mut out)
        .map_err(|e| err(format!("serialize proven tx: {e}")))?;
    Ok(out)
}

/// Build the same maker offer as [`authorize`] — same frame, same real coin selection — but **mock-prove**
/// it instead of really proving: the proofs are fixed-size, non-verifying stand-ins that serialize to the
/// exact length of the real ones, so a transaction sized against this offer gets the real fee. No real
/// proving happens, so it is safe to call **before** the policy seam. The sealed-merge effects path uses
/// it to size the merged DUST fee against a mock-proven taker complement, leaving the real spend proving to
/// [`authorize`] post-seam.
pub(super) fn mock_authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>, std::io::Error>
{
    let signer = MidnightSigner::from_chain_id(chain_id);

    let (unshielded_in, shielded_in): (Vec<_>, Vec<_>) = req
        .desired_inputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);

    let frame = build_make_intent_frame(
        chain_id,
        &signer,
        crypto_provider,
        req.intent_segment,
        &unshielded_in,
        &unshielded_out,
        &shielded_out,
        !shielded_in.is_empty(),
        req.ttl,
    )?;
    // Mock-prove into the *unsealed* proven form: `mock_prove` would seal the taker, but the merge fee
    // sizing seals the taker itself (once the DUST section is spliced in), so it needs the unsealed taker.
    let unsealed = mock_prove_unsealed(frame)?;
    let Transaction::Standard(base) = unsealed else {
        return Err(err(
            "mock-proven makeIntent frame is not a Standard transaction",
        ));
    };

    // No shielded inputs: the mock-proven frame is the whole offer. Otherwise select the maker's shielded
    // coins (the same selection the real path makes) and splice a mock-proven spend section in.
    if shielded_in.is_empty() {
        return Ok(base);
    }
    let funding =
        plan_shielded_input_funding(chain_id, crypto_provider, GUARANTEED_SEGMENT, &shielded_in)?;
    crate::balance_tx::splice_mock_shielded_for_sizing(&base, crypto_provider, &funding)
}

/// Construct the `proof-preimage` maker frame: the maker's unshielded inputs (with change back to the
/// maker) + unshielded/shielded outputs, deliberately imbalanced. The intent keys at `segment`
/// (`intentSegment`), but the shielded outputs ride the guaranteed section (see [`GUARANTEED_SEGMENT`]).
/// Shielded *inputs* are authorized separately, after proving, so `has_shielded_in` keeps the empty-offer
/// guard from firing when the maker's only contribution is shielded inputs.
#[allow(clippy::too_many_arguments)]
fn build_make_intent_frame(
    chain_id: &str,
    signer: &MidnightSigner,
    crypto_provider: &MidnightCryptoProvider,
    segment: u16,
    unshielded_in: &[&DesiredInput],
    unshielded_out: &[&DesiredOutput],
    shielded_out: &[&DesiredOutput],
    has_shielded_in: bool,
    ttl: Option<Timestamp>,
) -> Result<PreimageTx, std::io::Error> {
    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| err(e.to_string()))?;
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    let unshielded_offer = build_unshielded_offer(
        chain_id,
        signer,
        &sender_addr,
        &sender_vk,
        unshielded_in,
        unshielded_out,
    )?;
    let zswap_offer = build_shielded_output_offer(signer, GUARANTEED_SEGMENT, shielded_out)?;
    if unshielded_offer.is_none() && zswap_offer.is_none() && !has_shielded_in {
        return Err(err("makeIntent produced no offer"));
    }

    let mut rng = OsRng;
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: unshielded_offer.map(Sp::new),
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        // Unlike the balancing methods, makeIntent never runs the balancing tail, so nothing downstream
        // re-aligns this TTL to the chain tip — and it is inside the seal cover, so no later holder of
        // the offer can change it either. Whatever is chosen here is the offer's real expiry.
        ttl: ttl.unwrap_or_else(default_intent_ttl),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(segment, intent);
    let (guaranteed_coins, fallible_coins) = place_zswap_offer(GUARANTEED_SEGMENT, zswap_offer);
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

/// Sync the wallet's shielded coins and select whole coins covering each declared shielded input,
/// returning a fee-sizeable funding plan: the selected spend plan bound to `segment`, plus the synced,
/// merkle-ready coin tree. Shared by [`authorize_shielded_inputs`] (which really proves the spend) and
/// [`mock_authorize`] (which mock-proves it for effect sizing), so both select the same coins.
fn plan_shielded_input_funding(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    segment: u16,
    shielded_in: &[&DesiredInput],
) -> Result<crate::balance_tx::ShieldedFundingPlan, std::io::Error> {
    let deficits = shielded_input_deficits(shielded_in)?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let block_height = crate::tip_verify::fetch_current_block_height(&indexer_url);
    let synced = crate::block_on(crate::wallet_sync::shielded::sync_wallet(
        &indexer_url,
        crypto_provider,
        &scope,
        block_height,
    ))?;
    let mut tree = synced.zswap;
    crate::wallet_sync::shielded::ensure_shielded_merkle_ready(&mut tree)?;

    let coins: Vec<QualifiedInfo> = tree.coins.iter().map(|(_nul, qci)| *qci.deref()).collect();
    let selection = crate::balance_tx::plan_shielded_inputs(&coins, &deficits)?;
    let plan = ShieldedSpendPlan {
        segment,
        coins: selection.coins,
        change: selection.change_by_token,
    };
    Ok(crate::balance_tx::ShieldedFundingPlan {
        plans: vec![plan],
        tree,
    })
}

/// Authorize the maker's shielded inputs into the already-proved frame: select whole coins covering each
/// token's declared amount (via [`plan_shielded_input_funding`]) and hand them to
/// [`MidnightCryptoProvider::authorize_shielded`], which builds + proves the spend witnesses and the
/// self-change, both in the guaranteed section (see [`GUARANTEED_SEGMENT`]). The proved fragment is merged
/// into `base`'s guaranteed coins and its Pedersen binding delta folded in (a proved tx can't recompute
/// its own).
fn authorize_shielded_inputs(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    segment: u16,
    shielded_in: &[&DesiredInput],
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Result<(), std::io::Error> {
    let funding = plan_shielded_input_funding(chain_id, crypto_provider, segment, shielded_in)?;

    let prover = crate::balance_tx::midnight_prover(chain_id)?;
    let authorized =
        crate::block_on(crypto_provider.authorize_shielded(&funding.plans, &funding.tree, prover))
            .map_err(|e| err(e.to_string()))?;

    for (seg, proven_offer) in &authorized.proven {
        crate::balance_tx::place_shielded_fragment(base, *seg, proven_offer)?;
    }
    base.binding_randomness = base.binding_randomness + authorized.binding_delta;
    Ok(())
}

/// Aggregate the declared shielded inputs into one whole-coin deficit per token (summing repeats), so a
/// token's coins are selected once and the change is `selected total − declared total`.
fn shielded_input_deficits(
    inputs: &[&DesiredInput],
) -> Result<Vec<(ShieldedTokenType, u128)>, std::io::Error> {
    let mut by_token: BTreeMap<ShieldedTokenType, u128> = BTreeMap::new();
    for d in inputs {
        if d.value == 0 {
            return Err(err("desired input value must be greater than zero"));
        }
        let token = wire_type_to_shielded(&d.token_type)?;
        let entry = by_token.entry(token).or_insert(0);
        *entry = entry.saturating_add(d.value);
    }
    Ok(by_token.into_iter().collect())
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
        let (mut selected_inputs, mut change_outputs) =
            select_unshielded_inputs(&utxos, inputs_requested, sender_addr, sender_vk, maker)?;
        inputs.append(&mut selected_inputs);
        outputs.append(&mut change_outputs);
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

/// Select the maker's unshielded input coins for each requested input from `utxos`, plus the per-row
/// whole-coin change back to `maker`.
///
/// A `claimed` set threads across rows so a coin picked for one row is excluded from the next — without
/// it, two rows of the same token both select the same largest coin and the offer double-spends it (the
/// balancer's `build_night_offer` uses the same guard). Pure over `utxos` — no network — so it is unit
/// testable.
fn select_unshielded_inputs(
    utxos: &[crate::UnshieldedUtxo],
    inputs_requested: &[&DesiredInput],
    sender_addr: &str,
    sender_vk: &VerifyingKey,
    maker: UserAddress,
) -> Result<(Vec<UtxoSpend>, Vec<UtxoOutput>), std::io::Error> {
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    let mut change: Vec<UtxoOutput> = Vec::new();
    let mut claimed: Vec<(String, i64)> = Vec::new();
    for d in inputs_requested {
        if d.value == 0 {
            return Err(err("desired input value must be greater than zero"));
        }
        let wire = parse_token_type(Some(&d.token_type))?.to_wire_token_type();
        let type_ = wire_type_to_unshielded(&d.token_type)?;
        let available: Vec<crate::UnshieldedUtxo> = utxos
            .iter()
            .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
            .cloned()
            .collect();
        let selected = crate::balance_tx::select_utxos_for_token(
            &available,
            sender_addr,
            sender_vk,
            &wire,
            d.value,
        )?;
        let mut total = 0u128;
        for u in &selected {
            claimed.push((u.intent_hash.clone(), u.output_index));
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
        let owed = total.saturating_sub(d.value);
        if owed > 0 {
            change.push(UtxoOutput {
                value: owed,
                owner: maker,
                type_,
            });
        }
    }
    Ok((inputs, change))
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
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;

    /// A sender-owned NIGHT UTXO. `owner == "sender"` matches the sender address directly (no vk hex
    /// needed), and `token_type` is the NIGHT wire (32 zero bytes).
    fn night_utxo(value: u128, ih_byte: u8, out_idx: i64) -> crate::UnshieldedUtxo {
        crate::UnshieldedUtxo {
            token_type: "00".repeat(32),
            value,
            intent_hash: hex::encode([ih_byte; 32]),
            output_index: out_idx,
            owner: "sender".to_string(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    fn night_input(value: u128) -> DesiredInput {
        DesiredInput {
            kind: TransferKind::Unshielded,
            token_type: "night".to_string(),
            value,
        }
    }

    /// Two `desiredInputs` rows for the same token must select DISTINCT coins: the `claimed` set stops
    /// the second row from re-picking the first row's coin, which would double-spend it.
    #[test]
    fn same_token_desired_inputs_claim_disjoint_coins() {
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let vk = MidnightSigningKey::from_bytes(&hex::decode(seed).unwrap())
            .unwrap()
            .verifying_key();
        // Two equal NIGHT coins; each row needs one coin's worth.
        let pool = vec![night_utxo(100, 1, 0), night_utxo(100, 2, 1)];
        let d1 = night_input(60);
        let d2 = night_input(60);
        let (inputs, _change) =
            select_unshielded_inputs(&pool, &[&d1, &d2], "sender", &vk, vk.clone().into()).unwrap();
        assert_eq!(inputs.len(), 2, "one coin selected per row");
        assert_ne!(
            inputs[0].output_no, inputs[1].output_no,
            "the two rows must not double-select the same coin"
        );
    }

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
        assert_eq!(req.ttl, None);
    }

    #[test]
    fn honours_requested_ttl() {
        let ttl = now_secs() + 30;
        let req = parse_make_intent_json(&format!(
            r#"{{"desiredInputs":[{{"kind":"unshielded","type":"night","value":1}}],"options":{{"ttl":{ttl}}}}}"#
        ))
        .unwrap();
        assert_eq!(req.ttl, Some(Timestamp::from_secs(ttl)));
    }

    #[test]
    fn rejects_ttl_at_or_before_now() {
        // The ledger rejects an intent whose ttl is behind the block it lands in, and that block is never
        // earlier than now — so an already-past ttl can only ever produce a dead offer.
        let now = 1_000_000;
        assert!(parse_intent_ttl(Some(now), now).is_err());
        assert!(parse_intent_ttl(Some(now - 1), now).is_err());
        assert!(parse_intent_ttl(Some(now + 1), now).is_ok());
    }

    #[test]
    fn rejects_ttl_beyond_the_ledger_window() {
        // `ttl > tblock + global_ttl` is IntentTtlTooFarInFuture; measured from now, the furthest expiry
        // guaranteed to be accepted whenever the offer settles is now + global_ttl.
        let now = 1_000_000;
        let max = now + max_ttl_secs();
        assert!(parse_intent_ttl(Some(max), now).is_ok());
        assert!(parse_intent_ttl(Some(max + 1), now).is_err());
    }

    #[test]
    fn omitted_ttl_leaves_the_wallet_default() {
        // A spec-shaped request that names no ttl must behave exactly as before the option existed.
        assert_eq!(parse_intent_ttl(None, now_secs()).unwrap(), None);
        let default = default_intent_ttl().to_secs();
        let now = now_secs();
        assert!(default >= now + max_ttl_secs() && default <= now + max_ttl_secs() + 2);
    }

    #[test]
    fn honours_intent_segment_and_ignores_legacy_options() {
        // makeIntent no longer honours `options.payFees` (the maker never pays fees); a legacy request
        // that still carries it must be accepted with the field ignored, not rejected.
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"intentSegment":3,"options":{"payFees":false}}"#,
        )
        .unwrap();
        assert_eq!(req.intent_segment, 3);
    }

    #[test]
    fn rejects_intent_segment_zero() {
        // Segment 0 is the transaction's guaranteed section; the ledger rejects an intent declared
        // there, so the parse must reject it up front instead of building a doomed offer.
        assert!(parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"intentSegment":0}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_empty_request() {
        assert!(parse_make_intent_json(r#"{"desiredInputs":[],"desiredOutputs":[]}"#).is_err());
    }

    #[test]
    fn parses_shielded_inputs() {
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"shielded","type":"night","value":"100"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_inputs.len(), 1);
        assert_eq!(req.desired_inputs[0].kind, TransferKind::Shielded);
    }

    fn shielded_input(value: u128) -> DesiredInput {
        DesiredInput {
            kind: TransferKind::Shielded,
            token_type: "night".into(),
            value,
        }
    }

    #[test]
    fn aggregates_repeated_shielded_inputs_of_one_token() {
        let a = shielded_input(100);
        let b = shielded_input(50);
        let deficits = shielded_input_deficits(&[&a, &b]).expect("aggregate");
        assert_eq!(deficits.len(), 1, "the same token collapses to one deficit");
        assert_eq!(
            deficits[0].1, 150,
            "declared amounts sum, so coins are selected once"
        );
    }

    #[test]
    fn shielded_input_deficits_rejects_zero_value() {
        let z = shielded_input(0);
        assert!(shielded_input_deficits(&[&z]).is_err());
    }
}
