//! DApp Connector `balanceSealedTransaction` — the taker completes a maker's swap offer.
//!
//! A maker's **proven** (`proof,embedded-fr`) offer — e.g. what `makeIntent` produces — is a proven,
//! imbalanced transaction: the taker's wallet funds the imbalance with its own inputs, exactly what
//! `balanceUnsealed` does. So the proven-maker path reuses the same `plan_unsealed_proven_tx` →
//! `authorize_proven_tx` tail.
//!
//! Scope: a hex-encoded proven maker offer, a bare MIP-0005 `zswapoffer` bech32 (wrapped into a proven
//! zswap-only tx before balancing), or a MIP-0006 offer JSON (validated and materialized). A fully
//! **sealed** maker cannot be balanced in place (its binding fixes the value balance), so it is
//! completed by MERGING the taker's complementary half onto it — see `authorize_merge`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref as _;

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::TokenType as LedgerTokenType;
use midnight_ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork};
use serde::Deserialize;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};

use super::build::{DesiredOutput, TransferKind};
use super::make_intent::{DesiredInput, MakeIntentRequest};
use super::mip6;
use super::{classify_unsealed_payload, ConnectorPlan, UnsealedKind};

/// A fully sealed (`proof,pedersen-schnorr`) Midnight transaction — the form a maker offer arrives in.
type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// A proven, unsealed (`proof,embedded-fr`) transaction — the taker's half before it is sealed to merge.
type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

/// A parsed `balanceSealedTransaction` request: the maker offer to complete (the raw input string —
/// hex or a `zswapoffer` bech32) and whether the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct BalanceSealedRequest {
    pub maker_input: String,
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
struct BalanceSealedJson {
    /// The maker offer, hex-encoded. Accepts `makerTx`, or `tx`/`transaction` as aliases.
    #[serde(alias = "tx", alias = "transaction")]
    maker_tx: String,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `balanceSealedTransaction` request into the raw maker offer
/// string and fee preference. `payFees` defaults to true. The maker string is decoded later (it may
/// be hex or a `zswapoffer` bech32), once the chain id is known.
pub fn parse_balance_sealed_json(json: &str) -> Result<BalanceSealedRequest, std::io::Error> {
    let req: BalanceSealedJson = serde_json::from_str(json).map_err(|e| {
        std::io::Error::other(format!(
            "invalid balanceSealedTransaction request JSON: {e}"
        ))
    })?;
    Ok(BalanceSealedRequest {
        maker_input: req.maker_tx,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Decode the maker input into transaction bytes: a `zswapoffer…` bech32 is wrapped into a proven
/// zswap-only tx (MIP-0005); a MIP-0006 offer JSON object is validated (gives/wants vs deltas, plus
/// optional signature) and materialized; anything else is treated as hex-encoded transaction bytes.
fn decode_maker_input(chain_id: &str, input: &str) -> Result<Vec<u8>, std::io::Error> {
    let trimmed = input.trim();
    if trimmed.starts_with(mip6::ZSWAP_OFFER_BECH32_HRP) {
        return mip6::wrap_zswap_offer_as_proven_tx(chain_id, trimmed);
    }
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| std::io::Error::other(format!("invalid maker offer JSON: {e}")))?;
        if mip6::is_mip6_offer_payload(&v) {
            return mip6::materialize_validated_offer(chain_id, &v);
        }
        return Err(std::io::Error::other(
            "maker input JSON is not a MIP-0006 offer (needs version, transaction, gives, wants)",
        ));
    }
    let clean = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(clean)
        .map_err(|e| std::io::Error::other(format!("invalid maker transaction hex: {e}")))
}

/// Plan a `balanceSealedTransaction`: decode the maker offer (hex tx or `zswapoffer` bech32) and —
/// for a proven offer — plan the taker's balancing inertly via the shared tail. Sealed / preimage /
/// non-tx payloads are rejected.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    let request = parse_balance_sealed_json(json)?;
    let maker_tx = decode_maker_input(chain_id, &request.maker_input)?;
    match classify_unsealed_payload(&maker_tx) {
        Some(UnsealedKind::Proven) => {
            let plan = crate::plan_unsealed_proven_tx(
                chain_id,
                crypto_provider,
                &maker_tx,
                request.pay_fees,
            )?;
            Ok(ConnectorPlan::BalanceSealed(Box::new(plan)))
        }
        Some(UnsealedKind::ProofPreimage) => Err(std::io::Error::other(
            "balanceSealedTransaction maker offer must be proven (proof,embedded-fr); received a \
             proof-preimage — the maker must prove its own offer first",
        )),
        None if super::is_sealed_maker_payload(&maker_tx) => {
            // A sealed maker cannot be balanced in place — complete it by merging. Derive the taker's
            // complementary half here (inert, for the seam); it is built, sealed, and merged with the
            // maker in `authorize_merge`.
            let addrs = crypto_provider
                .addresses(&MidnightNetwork::from_chain_id(chain_id))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let complement =
                sealed_maker_complement(&maker_tx, &addrs.unshielded, &addrs.shielded)?;
            Ok(ConnectorPlan::BalanceSealedMerge {
                maker_tx,
                complement,
                pay_fees: request.pay_fees,
            })
        }
        None => Err(std::io::Error::other(
            "balanceSealedTransaction accepts a proven (proof,embedded-fr) maker offer, a \
             zswapoffer bech32, or a MIP-0006 offer JSON object",
        )),
    }
}

// ── Sealed-maker merge (the taker's complementary half) ──────────────────────────────────────────
//
// A fully sealed maker offer cannot be balanced in place (its Pedersen-Schnorr binding fixes its value
// balance). Per the DApp Connector spec, `balanceSealed` completes it by MERGING: the taker builds its
// own imbalanced half whose per-token deltas are the exact complement of the maker's, seals it, and
// `Transaction::merge`s the two — the summed (public, in-the-clear) `binding_randomness` opens the
// summed value commitments, so the merged whole is balanced and submittable with no re-seal.
//
// This module owns the first step: reading the maker's imbalance and deriving the taker's complementary
// `makeIntent`. Building/sealing/merging that half (reusing `make_intent::authorize`) is wired in below.

/// Derive the taker's complementary `makeIntent` from the maker's per-token imbalance, as returned by
/// `Transaction::balance` (positive = maker surplus, negative = maker shortage). Each entry is negated:
/// a maker surplus of a token is one the taker RECEIVES (a desired output to the taker's own address in
/// that domain); a maker shortage is one the taker SUPPLIES (a desired input). The DUST dimension is
/// skipped — the taker's own dust pays fees. The taker's intent keys on a segment disjoint from the
/// maker's, since `Transaction::merge` rejects colliding intent segment ids.
pub(super) fn complement_from_balance(
    imbalance: BTreeMap<(LedgerTokenType, u16), i128>,
    maker_segments: &BTreeSet<u16>,
    taker_unshielded_addr: &str,
    taker_shielded_addr: &str,
) -> MakeIntentRequest {
    // The taker balances the whole tx, so net each token across the maker's segments first.
    let mut per_token: BTreeMap<LedgerTokenType, i128> = BTreeMap::new();
    for ((token, _segment), bal) in imbalance {
        *per_token.entry(token).or_default() += bal;
    }

    let mut desired_inputs = Vec::new();
    let mut desired_outputs = Vec::new();
    for (token, bal) in per_token {
        let (kind, wire) = match token {
            LedgerTokenType::Unshielded(tt) => (TransferKind::Unshielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Shielded(tt) => (TransferKind::Shielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Dust => continue,
        };
        if bal > 0 {
            let recipient = match kind {
                TransferKind::Unshielded => taker_unshielded_addr,
                TransferKind::Shielded => taker_shielded_addr,
            }
            .to_string();
            desired_outputs.push(DesiredOutput {
                kind,
                token_type: wire,
                value: bal as u128,
                recipient,
            });
        } else if bal < 0 {
            desired_inputs.push(DesiredInput {
                kind,
                token_type: wire,
                value: bal.unsigned_abs(),
            });
        }
    }

    MakeIntentRequest {
        desired_inputs,
        desired_outputs,
        intent_segment: first_disjoint_segment(maker_segments),
    }
}

/// The lowest fallible segment (>= 1) the maker did not use. Segment 0 is the guaranteed section, where
/// the ledger rejects an intent; a collision with a maker segment fails `Transaction::merge`.
fn first_disjoint_segment(maker_segments: &BTreeSet<u16>) -> u16 {
    let mut seg = 1u16;
    while maker_segments.contains(&seg) {
        seg = seg.saturating_add(1);
    }
    seg
}

/// Deserialize a sealed maker offer and derive the taker's complementary `makeIntent`. The maker's tx
/// is read in its sealed form (its value balance is fixed by the binding signature); `Transaction::balance`
/// reports the per-token surplus/shortage, which [`complement_from_balance`] negates into the taker's half.
pub(super) fn sealed_maker_complement(
    maker_bytes: &[u8],
    taker_unshielded_addr: &str,
    taker_shielded_addr: &str,
) -> Result<MakeIntentRequest, std::io::Error> {
    let mut r: &[u8] = maker_bytes;
    let tx: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
    let imbalance = tx
        .balance(None)
        .map_err(|e| std::io::Error::other(format!("maker balance check failed: {e:?}")))?;
    let Transaction::Standard(base) = &tx else {
        return Err(std::io::Error::other(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    let maker_segments: BTreeSet<u16> = base
        .intents
        .iter()
        .map(|pair| {
            let (seg_sp, _intent_sp) = pair.deref();
            *seg_sp.deref()
        })
        .collect();
    Ok(complement_from_balance(
        imbalance,
        &maker_segments,
        taker_unshielded_addr,
        taker_shielded_addr,
    ))
}

/// The contract actions a sealed maker offer carries. A merge preserves both halves' intents verbatim,
/// so the maker's contract actions — the taker's complement adds none — are exactly what the submitted
/// transaction performs, at the maker's own segments.
pub(super) fn maker_contracts(
    maker_bytes: &[u8],
) -> Result<Vec<crate::contracts::ContractInteraction>, std::io::Error> {
    let mut r: &[u8] = maker_bytes;
    let tx: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
    let Transaction::Standard(base) = &tx else {
        return Err(std::io::Error::other(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    Ok(crate::contracts::contract_interactions(base.actions()))
}

/// Authorize the sealed-maker merge: build the taker's complementary half from its own coins, fold in a
/// DUST fee that covers the whole *merged* tx, and return a [merge envelope](ows_signer::chains::wrap_merge_envelope)
/// of the (proven, unsealed) taker half plus the sealed maker. The sign pipeline then signs the taker's
/// own inputs, seals it, and `Transaction::merge`s it onto the maker in `encode_signed_transaction` — so
/// the taker is signed before it is sealed, and both halves are sealed for the merge, whose summed
/// in-the-clear `binding_randomness` cancels the imbalances into a balanced, submittable whole.
///
/// The maker never pays fees (`makeIntent` is imbalanced by design), so on a live-DUST chain the taker
/// funds the merged tx's fee from its own dust — sized against the merged tx and folded into the taker's
/// complement intent before it is sealed. With `pay_fees` off (or a fee-less chain) the merged tx is
/// value-balanced but fee-less, and a live-DUST network rejects the submit.
pub(super) fn authorize_merge(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_bytes: &[u8],
    complement: MakeIntentRequest,
    pay_fees: bool,
) -> Result<Vec<u8>, std::io::Error> {
    // The taker's imbalanced complementary half rides a segment disjoint from the maker's (picked in
    // `complement_from_balance`); that intent carries the DUST fee below.
    let taker_seg = complement.intent_segment;

    // The taker's imbalanced complementary half, built from its own coins (proven, still unsealed).
    let taker_unsealed = super::make_intent::authorize(chain_id, crypto_provider, complement)?;
    let mut tr: &[u8] = &taker_unsealed;
    let taker: TxProven = tagged_deserialize(&mut tr)
        .map_err(|e| std::io::Error::other(format!("failed to parse taker half: {e}")))?;
    let Transaction::Standard(mut taker_base) = taker else {
        return Err(std::io::Error::other(
            "taker complement is not a Standard transaction",
        ));
    };

    // On a live-DUST chain, size + realize the taker's DUST fee against the merged tx and fold it into
    // the taker's complement intent before the taker is sealed downstream.
    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let adding_dust =
        pay_fees && crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(&indexer_url));
    if adding_dust {
        // The maker (sealed) is needed only to size the DUST fee against the merged tx.
        let mut mr: &[u8] = maker_bytes;
        let maker: TxSealed = tagged_deserialize(&mut mr)
            .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
        attach_merge_dust_fee(
            chain_id,
            crypto_provider,
            &maker,
            &mut taker_base,
            taker_seg,
            &indexer_url,
            &scope,
        )?;
    }

    // Return a merge envelope carrying the (proven-unsealed) taker half and the sealed maker. The sign
    // pipeline signs the taker's own inputs, seals it, and `Transaction::merge`s it onto the maker in
    // `encode_signed_transaction` — reusing the exact sign/seal machinery a plain makeIntent uses, so the
    // taker is never sealed before it is signed. (`extract_signable_bytes` returns the taker to sign.)
    let mut taker_bytes = Vec::new();
    tagged_serialize(&Transaction::Standard(taker_base), &mut taker_bytes)
        .map_err(|e| std::io::Error::other(format!("serialize taker half: {e}")))?;
    Ok(ows_signer::chains::wrap_merge_envelope(
        &taker_bytes,
        maker_bytes,
    ))
}

/// The wallet-relative effects a sealed-maker MERGE will have — the taker's own half **plus** the merged
/// DUST fee it funds — all in the transaction's guaranteed section (segment 0): the taker's coins settle
/// guaranteed just like a plain makeIntent (see [`super::make_intent::GUARANTEED_SEGMENT`]), and the fee
/// is a guaranteed cost. The token movement is request-derived from the taker's
/// [complement](sealed_maker_complement), exactly as a plain makeIntent. On a live-DUST chain, when the
/// taker pays fees, the fee covers the whole merged tx (the maker contributes bytes but never pays), so
/// it is sized against a **mock-proven** taker complement — fixed-size proofs give the exact fee with no
/// real proving — and folded in as a DUST outflow, so a `sum(|diff|)` cap at the policy seam sees the
/// burn. Sizing needs the same tip + spendable-dust sync the real merge uses; the real, submittable spend
/// is proved only post-seam in [`authorize_merge`], so a merge denied at the seam never reaches a real
/// proof.
pub(super) fn merge_segment_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_bytes: &[u8],
    complement: &MakeIntentRequest,
    pay_fees: bool,
) -> Result<Vec<crate::balance_tx::SegmentEffects>, std::io::Error> {
    let mut effects = super::make_intent::request_effects(chain_id, crypto_provider, complement)?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;
    let adding_dust =
        pay_fees && crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(&indexer_url));
    if !adding_dust {
        return Ok(crate::balance_tx::single_segment(
            super::make_intent::GUARANTEED_SEGMENT,
            effects,
        ));
    }

    // Size the merged DUST fee against the taker's mock-proven complement — same coin selection as the
    // real merge, fixed-size mock proofs, no real proving. The maker (sealed) is needed only to size the
    // fee against the merged tx.
    let taker_base = super::make_intent::mock_authorize(chain_id, crypto_provider, complement)?;
    let taker_seg = complement.intent_segment;
    let binding_commitment = taker_base
        .intents
        .get(&taker_seg)
        .ok_or_else(|| std::io::Error::other("taker complement missing its intent segment"))?
        .deref()
        .binding_commitment;

    let mut mr: &[u8] = maker_bytes;
    let maker: TxSealed = tagged_deserialize(&mut mr)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;

    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let (ledger_params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(&indexer_url))?;
    let dust_ctime = Timestamp::from_secs(tip_secs);

    // Discard the synced dust state — that is only needed to prove the real, submittable spend post-seam.
    let (plan, _dust_state) = crate::balance_tx::size_merge_dust_fee(
        &maker,
        &taker_base,
        taker_seg,
        binding_commitment,
        crypto_provider,
        dust_ctime,
        &ledger_params,
        &indexer_url,
        &scope,
    )?;

    let addresses = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(effect) = crate::balance_tx::dust_outflow_effect(addresses.dust, plan.fee_dust) {
        effects.push(effect);
    }
    Ok(crate::balance_tx::single_segment(
        super::make_intent::GUARANTEED_SEGMENT,
        effects,
    ))
}

/// Size + realize the taker's DUST fee for the merge and splice it into the taker's complement intent
/// (at `dust_seg`) before sealing. The fee covers the whole *merged* tx (the maker contributes bytes but
/// never pays), so it is sized against the merged tx in [`crate::balance_tx::size_merge_dust_fee`]; the
/// converged spend is then proved in the signer ([`MidnightCryptoProvider::authorize_dust`]) and the
/// proven section attached to the taker's complement intent, whose TTL is aligned to the chain tip.
fn attach_merge_dust_fee(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker: &TxSealed,
    taker_base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_seg: u16,
    indexer_url: &str,
    scope: &SyncCacheScope,
) -> Result<(), std::io::Error> {
    // Chain time + ledger parameters fix the DUST fee and the intent's TTL.
    let (ledger_params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(indexer_url))?;
    let dust_ctime = Timestamp::from_secs(tip_secs);

    // The DUST section rides the taker's complement intent (which carries none), proved against that
    // intent's own binding commitment so the two stay bound together through the merge.
    let binding_commitment = taker_base
        .intents
        .get(&dust_seg)
        .ok_or_else(|| std::io::Error::other("taker half missing the complement intent segment"))?
        .deref()
        .binding_commitment;

    // Size against the merged tx (offline, mock-proved), then prove the real, submittable spend.
    let (plan, dust_state) = crate::balance_tx::size_merge_dust_fee(
        maker,
        taker_base,
        dust_seg,
        binding_commitment,
        crypto_provider,
        dust_ctime,
        &ledger_params,
        indexer_url,
        scope,
    )?;
    let prover = crate::balance_tx::midnight_prover(chain_id)?;
    let dust_actions =
        crate::block_on(crypto_provider.authorize_dust(&dust_state, &plan, &ledger_params, prover))
            .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Splice the proven DUST section into the taker's complement intent, aligning its TTL to the tip
    // (the section's fee window is anchored at `dust_ctime`).
    let mut intent = taker_base
        .intents
        .get(&dust_seg)
        .ok_or_else(|| std::io::Error::other("taker half missing the complement intent segment"))?
        .deref()
        .clone();
    intent.dust_actions = Some(Sp::new(dust_actions));
    intent.ttl = plan.intent_ttl;
    taker_base.intents = taker_base.intents.insert(dust_seg, intent);
    Ok(())
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::{ShieldedTokenType, UnshieldedTokenType};

    fn shielded(b: u8) -> LedgerTokenType {
        LedgerTokenType::Shielded(ShieldedTokenType(HashOutput([b; 32])))
    }
    fn unshielded(b: u8) -> LedgerTokenType {
        LedgerTokenType::Unshielded(UnshieldedTokenType(HashOutput([b; 32])))
    }

    #[test]
    fn complement_negates_imbalance_and_maps_domains() {
        // Maker gives 100 of a shielded token (surplus, +) and wants 50 unshielded NIGHT (shortage, -).
        let mut bal = BTreeMap::new();
        bal.insert((shielded(0xAA), 1u16), 100i128);
        bal.insert((unshielded(0x00), 1u16), -50i128);

        let req = complement_from_balance(
            bal,
            &BTreeSet::from([1u16]),
            "taker_unshielded",
            "taker_shielded",
        );

        // The taker RECEIVES the maker's surplus as an output to its own shielded address.
        assert_eq!(req.desired_outputs.len(), 1);
        let out = &req.desired_outputs[0];
        assert_eq!(out.kind, TransferKind::Shielded);
        assert_eq!(out.value, 100);
        assert_eq!(out.recipient, "taker_shielded");
        assert_eq!(out.token_type, hex::encode([0xAAu8; 32]));

        // The taker SUPPLIES the maker's shortage as an input.
        assert_eq!(req.desired_inputs.len(), 1);
        let inp = &req.desired_inputs[0];
        assert_eq!(inp.kind, TransferKind::Unshielded);
        assert_eq!(inp.value, 50);
        assert_eq!(inp.token_type, hex::encode([0x00u8; 32]));

        // The taker's intent must not collide with the maker's segment (maker used 1 → taker gets 2).
        assert_eq!(req.intent_segment, 2);
    }

    #[test]
    fn nets_a_token_across_segments() {
        // Same token, split across two maker segments: +100 and -30 net to +70 (a single taker output).
        let mut bal = BTreeMap::new();
        bal.insert((shielded(0x01), 1u16), 100i128);
        bal.insert((shielded(0x01), 2u16), -30i128);

        let req = complement_from_balance(bal, &BTreeSet::from([1u16, 2u16]), "u", "s");

        assert_eq!(req.desired_inputs.len(), 0);
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.desired_outputs[0].value, 70);
        // Maker used 1 and 2 → the taker's disjoint segment is 3.
        assert_eq!(req.intent_segment, 3);
    }

    #[test]
    fn dust_dimension_is_skipped() {
        let mut bal = BTreeMap::new();
        bal.insert((LedgerTokenType::Dust, 1u16), -1000i128);

        let req = complement_from_balance(bal, &BTreeSet::new(), "u", "s");

        assert!(req.desired_inputs.is_empty());
        assert!(req.desired_outputs.is_empty());
        assert_eq!(req.intent_segment, 1);
    }

    #[test]
    fn complement_of_a_real_sealed_maker_negates_its_balance() {
        // A real preprod makeIntent output — proof,pedersen-schnorr, sealed and imbalanced.
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex");
        let hex_str = hex_str.trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();

        // The maker's own imbalance, straight from the ledger (balance() works on the sealed marker).
        let mut r: &[u8] = &bytes;
        let tx: TxSealed = tagged_deserialize(&mut r).unwrap();
        let mut maker: BTreeMap<String, i128> = BTreeMap::new();
        for ((token, _seg), bal) in tx.balance(None).unwrap() {
            let wire = match token {
                LedgerTokenType::Unshielded(tt) => hex::encode(tt.0 .0),
                LedgerTokenType::Shielded(tt) => hex::encode(tt.0 .0),
                LedgerTokenType::Dust => continue,
            };
            *maker.entry(wire).or_default() += bal;
        }
        assert!(!maker.is_empty(), "the fixture must carry a real imbalance");

        // The taker's complement, netted back per token in balance() convention: input supplies (+),
        // output absorbs (-). Merging it onto the maker must zero every token, i.e. taker == -maker.
        let req = sealed_maker_complement(&bytes, "taker_unshielded", "taker_shielded").unwrap();
        let mut taker: BTreeMap<String, i128> = BTreeMap::new();
        for inp in &req.desired_inputs {
            *taker.entry(inp.token_type.clone()).or_default() += inp.value as i128;
        }
        for out in &req.desired_outputs {
            *taker.entry(out.token_type.clone()).or_default() -= out.value as i128;
        }
        for (token, m) in &maker {
            assert_eq!(
                taker.get(token).copied().unwrap_or(0),
                -*m,
                "token {token}: taker must negate the maker's imbalance"
            );
        }
    }

    #[test]
    fn contracts_of_a_real_sealed_maker_are_read_from_its_intents() {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex");
        let hex_str = hex_str.trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();

        // The fixture is a plain token swap, so it names no contract — what matters here is that a
        // sealed maker's actions are readable at all, i.e. the seam reports `contracts` for a merge
        // instead of failing to parse the maker it already balances against.
        assert_eq!(maker_contracts(&bytes).unwrap(), Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maker_tx_hex_and_defaults_pay_fees() {
        let req = parse_balance_sealed_json(
            r#"{"method":"balanceSealedTransaction","makerTx":"0x0102ab"}"#,
        )
        .unwrap();
        assert_eq!(req.maker_input, "0x0102ab");
        assert!(req.pay_fees);
        // The raw input decodes to the hex bytes (0x prefix stripped).
        assert_eq!(
            decode_maker_input("midnight:preview", &req.maker_input).unwrap(),
            vec![0x01, 0x02, 0xab]
        );
    }

    #[test]
    fn accepts_tx_alias_and_pay_fees_false() {
        let req = parse_balance_sealed_json(r#"{"tx":"00","options":{"payFees":false}}"#).unwrap();
        assert_eq!(req.maker_input, "00");
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_non_hex_maker_tx() {
        // Parsing keeps the raw string; the hex error surfaces at decode time.
        let req = parse_balance_sealed_json(r#"{"makerTx":"zz"}"#).unwrap();
        assert!(decode_maker_input("midnight:preview", &req.maker_input).is_err());
    }

    #[test]
    fn zswapoffer_input_dispatches_to_the_offer_decoder() {
        // A zswapoffer-prefixed input routes through the bech32 wrapper (a malformed one errors
        // there, not as invalid hex — proving the dispatch).
        let err = decode_maker_input("midnight:preview", "zswapoffer1notvalid")
            .unwrap_err()
            .to_string();
        assert!(err.contains("zswap offer"), "unexpected error: {err}");
    }

    #[test]
    fn sealed_maker_input_is_recognized_as_sealed() {
        // A fully sealed maker blob (proof,pedersen-schnorr tag) decodes as raw bytes and is
        // recognized as sealed, so plan() takes the precise sealed-merge error path rather than the
        // generic fallthrough.
        let sealed_tag = b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";
        let mut blob = sealed_tag.to_vec();
        blob.extend_from_slice(&[0u8; 8]);
        let json = format!(r#"{{"makerTx":"{}"}}"#, hex::encode(&blob));
        let req = parse_balance_sealed_json(&json).unwrap();
        let decoded = decode_maker_input("midnight:preview", &req.maker_input).unwrap();
        assert!(super::super::is_sealed_maker_payload(&decoded));
        assert_eq!(classify_unsealed_payload(&decoded), None);
    }
}
