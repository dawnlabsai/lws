//! DUST fee sizing for the balancer: how much fee the wallet's inputs can cover and the
//! iterative sizing of the DUST fee section that balances a proven Standard transaction.

use super::*;

/// Generationless DUST fee capacity from the selected UTXOs' *unregistered* NIGHT — how much fee the
/// ledger will let those inputs pay without a dust spend. Mirrors the ledger's
/// `generationless_fee_availability`: capped at `value * night_dust_ratio`, growing at
/// `value * generation_decay_rate` per second since the UTXO's block time.
fn dust_allowance_from_night_inputs(
    selected: &[UnshieldedUtxo],
    dust_ctime: Timestamp,
) -> Result<u128, std::io::Error> {
    let params = &INITIAL_DUST_PARAMETERS;
    let night_wire = crate::parse_token_type(Some("night"))?.to_wire_token_type();

    let mut sum = 0u128;
    for u in selected {
        if !u.token_type.eq_ignore_ascii_case(&night_wire) || u.registered_for_dust_generation {
            continue;
        }
        let vfull = u.value.saturating_mul(params.night_dust_ratio as u128);
        let rate = u.value.saturating_mul(params.generation_decay_rate as u128);
        let Some(ts) = u.ctime_unix_secs else {
            return Err(err(
                "indexer did not provide block timestamp for unshielded UTXOs; cannot size DUST allowance",
            ));
        };
        let dt = (dust_ctime - Timestamp::from_secs(ts)).as_seconds();
        let dt = if dt < 0 { 0 } else { dt as u128 };
        sum = sum.saturating_add(u128::min(vfull, dt.saturating_mul(rate)));
    }
    Ok(sum)
}

/// Cap the generationless allowance to a safe headroom over the fee estimate, erroring if the
/// available allowance can't cover the fee.
fn cap_allow_fee_payment(dust_allow: u128, fee_dust: u128) -> Result<u128, std::io::Error> {
    let allow_fee_payment = u128::min(
        dust_allow,
        fee_dust
            .saturating_mul(GENERATIONLESS_FEE_HEADROOM_MULT)
            .max(fee_dust.saturating_add(GENERATIONLESS_FEE_HEADROOM_ABS)),
    );
    if allow_fee_payment < fee_dust {
        return Err(err(format!(
            "generationless DUST allowance {dust_allow} (capped to {allow_fee_payment}) is below the estimated fee {fee_dust}"
        )));
    }
    Ok(allow_fee_payment)
}

/// Headroom `cap_allow_fee_payment` reserves over the sized fee, so a modest fee re-size during
/// convergence stays covered without over-committing the wallet's NIGHT: the allowance is capped at
/// the larger of `MULT ×` the estimate or the estimate plus `ABS` stars. An intentional fixed policy
/// (exercised by the headroom unit test) — do not "simplify" it to the bare fee.
const GENERATIONLESS_FEE_HEADROOM_MULT: u128 = 4;
const GENERATIONLESS_FEE_HEADROOM_ABS: u128 = 50_000;

/// A proven-flow dust-action section carrying one generationless registration (no spends → no proof).
fn registration_dust_actions(
    dust_pk: DustPublicKey,
    night_vk: VerifyingKey,
    allow_fee_payment: u128,
    dust_ctime: Timestamp,
) -> DustActions<MnSig, ProofMarker, InMemoryDB> {
    DustActions {
        spends: vec![].into(),
        registrations: vec![DustRegistration {
            allow_fee_payment,
            dust_address: Some(Sp::new(dust_pk)),
            night_key: night_vk,
            signature: None,
        }]
        .into(),
        ctime: dust_ctime,
    }
}

/// Build a generationless fee registration sized to `fee_dust`, or `None` when the selected inputs
/// have no unregistered NIGHT capacity.
fn try_registration_dust_actions(
    selected: &[UnshieldedUtxo],
    fee_dust: u128,
    dust_pk: DustPublicKey,
    night_vk: VerifyingKey,
    dust_ctime: Timestamp,
) -> Result<Option<DustActions<MnSig, ProofMarker, InMemoryDB>>, std::io::Error> {
    let dust_allow = dust_allowance_from_night_inputs(selected, dust_ctime)?;
    if dust_allow == 0 {
        return Ok(None);
    }
    let allow_fee_payment = cap_allow_fee_payment(dust_allow, fee_dust)?;
    Ok(Some(registration_dust_actions(
        dust_pk,
        night_vk,
        allow_fee_payment,
        dust_ctime,
    )))
}

/// Sum the fee value carried by a set of dust spends.
fn sum_dust_v_fee<P: ProofKind<InMemoryDB>>(
    spends: impl IntoIterator<Item = impl std::borrow::Borrow<DustSpend<P, InMemoryDB>>>,
) -> u128 {
    spends
        .into_iter()
        .map(|s| s.borrow().v_fee)
        .fold(0u128, |a, v| a.saturating_add(v))
}

/// Sync a spendable [`DustLocalState`] for the wallet's dust key, verifying the disk snapshot against
/// the indexer HTTP tip (reusing the same cache the fund-balance path fills). The dust key stays in
/// the crypto provider.
fn sync_spendable_dust_state(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
) -> Result<DustLocalState<InMemoryDB>, std::io::Error> {
    let current_block_height = crate::tip_verify::fetch_current_block_height(indexer_url);
    crate::block_on(crate::wallet_sync::dust::sync_spendable_dust_state(
        indexer_url,
        crypto_provider,
        scope,
        current_block_height,
    ))
}

/// Fee-sizing twin of the signer's `authorize_dust`: build the same proof-preimage DUST spends via the
/// crypto provider, then `mock_prove` the dust intent instead of really proving it. `mock_prove` yields
/// a correctly-sized (but non-verifying, non-submittable) `ProofMarker` section whose fee and serialized
/// size match the real proof's **exactly** — proofs are fixed-size — so the fee-convergence loop can
/// size the section **offline, with no real proving keys**. The real, submittable section is built
/// post-seam by the signer's [`MidnightCryptoProvider::authorize_dust`]; this only produces the number
/// the fee loop needs.
#[allow(dead_code)] // used by the deferred fee-sizing path wired in a later commit
fn build_mock_dust_spends(
    ctx: &DustFeeContext,
    dust_state: &DustLocalState<InMemoryDB>,
    fee_target: u128,
    intent_ttl: Timestamp,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, std::io::Error> {
    let spends = ctx
        .crypto_provider
        .build_preimage_dust_spends(dust_state.clone(), fee_target, ctx.dust_ctime)
        .map_err(|e| err(e.to_string()))?;

    let dust_preimage: DustActions<MnSig, ProofPreimageMarker, InMemoryDB> = DustActions {
        spends: spends.into_iter().collect(),
        registrations: vec![].into(),
        ctime: ctx.dust_ctime,
    };
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: Some(Sp::new(dust_preimage)),
        ttl: intent_ttl,
        binding_commitment: ctx.intent_in.binding_commitment,
    };
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(ctx.seg_id, intent);
    let stx: StandardTransaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        StandardTransaction {
            network_id: ctx.stx.network_id.clone(),
            intents,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        };
    let tx: Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Transaction::Standard(stx);

    let mock = tx
        .mock_prove()
        .map_err(|e| err(format!("mock-prove dust spends failed: {e:?}")))?;
    let Transaction::Standard(mstx) = mock else {
        return Err(err("mock-proven dust transaction was not Standard"));
    };
    let pair = mstx
        .intents
        .iter()
        .next()
        .ok_or_else(|| err("mock-proven dust transaction has no intent"))?;
    let (_seg, intent) = pair.deref();
    intent
        .deref()
        .dust_actions
        .as_ref()
        .map(|sp| sp.deref().clone())
        .ok_or_else(|| err("mock-proven dust intent did not contain dust actions"))
}

/// The transaction context a DUST fee section is sized against: the proven standard tx and its
/// single intent segment, the balanced unshielded offer and the UTXOs funding it, the wallet's
/// dust key / night key, the crypto provider + indexer + scope (to sync a spendable dust state and
/// prove dust spends), and the chain time plus ledger parameters that fix the fee.
pub(super) struct DustFeeContext<'a> {
    pub(super) stx: &'a StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    pub(super) seg_id: u16,
    pub(super) intent_in: &'a Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    pub(super) offer: &'a UnshieldedOffer<MnSig, InMemoryDB>,
    /// The chosen intent's own fallible balancing offer, if any — spliced into the sizing tx so the
    /// fee covers the whole (guaranteed + fallible) intent the rebuild produces.
    pub(super) fallible_offer: Option<&'a UnshieldedOffer<MnSig, InMemoryDB>>,
    pub(super) selected: &'a [UnshieldedUtxo],
    pub(super) dust_pk: DustPublicKey,
    pub(super) night_vk: VerifyingKey,
    pub(super) crypto_provider: &'a MidnightCryptoProvider,
    pub(super) dust_ctime: Timestamp,
    pub(super) ledger_params: &'a LedgerParameters,
    pub(super) indexer_url: &'a str,
    pub(super) scope: &'a SyncCacheScope,
}

/// The wallet's planned DUST fee section, in one of three shapes that mirror how it is realized
/// post-seam. Sized offline during planning (via `mock_prove`), so no real proving happens here.
pub(super) enum DustFeePlan {
    /// No DUST fee section (fee payment off, or the chain does not require DUST fees).
    None,
    /// A signature-based generationless registration — final and submittable, carrying no ZK proof and
    /// no bearer preimage, so it is built during planning and attached as-is.
    Registration(DustActions<MnSig, ProofMarker, InMemoryDB>),
    /// A proof-bearing DUST spend, deferred past the policy seam to the signer: the converged fee plus
    /// the synced dust state and ledger parameters the signer needs to build and prove the section.
    /// Boxed — the synced state dwarfs the other variants.
    Spend {
        plan: DustSpendPlan,
        dust_state: Box<DustLocalState<InMemoryDB>>,
        ledger_params: Box<LedgerParameters>,
    },
}

/// Whether `tx`'s DUST section covers the fee the node will charge. Mirrors the node's fee gate
/// (`well_formed` computes `fees(params, true)` then rejects any segment/token whose `balance` of that
/// fee goes negative): unlike `tx_balance_imbalances` (which uses `balance(None)` and so ignores the
/// fee entirely), this charges the real fee, so a DUST section that only satisfies structural balance
/// but under-covers the fee is correctly rejected. `fees(_, true)` enforces the guaranteed-compute
/// time-to-dismiss bound; a tx still too small to satisfy it is reported as not-covered so the caller
/// keeps growing the section (the proof-bearing spend adds the bytes that lift the bound).
fn dust_section_covers_fee(
    tx: &TxProven,
    params: &LedgerParameters,
) -> Result<bool, std::io::Error> {
    use midnight_ledger::error::FeeCalculationError;
    let fee = match tx.fees(params, true) {
        Ok(f) => f,
        // `OutsideTimeToDismiss` means the tx's guaranteed compute exceeds the size-derived
        // time-to-dismiss bound — not coverable by more dust as-is, so report not-covered and let the
        // caller grow the section (the proof-bearing spend adds the bytes that lift the bound).
        Err(FeeCalculationError::OutsideTimeToDismiss { .. }) => return Ok(false),
        Err(e) => return Err(err(format!("DUST fee check failed: {e:?}"))),
    };
    let balances = tx
        .balance(Some(fee))
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?;
    Ok(balances.into_iter().all(|(_, bal)| bal >= 0))
}

/// Size the DUST fee section that balances the transaction, **without** real proving. The fee depends
/// on the tx (dust-section bytes included), so estimate → build section → re-check, converging within
/// a few iterations.
///
/// Each iteration prefers a signature-based **generationless registration** funded by the wallet's
/// unregistered NIGHT (no proving). When the wallet has no unregistered NIGHT capacity — a normal
/// funded wallet registers all its NIGHT for dust generation — it falls back to a **DUST spend** of
/// its generated dust, syncing the spendable dust state once and sizing the spends with `mock_prove`
/// (fixed-size proofs → the mock section's fee matches the real one exactly). The registration is
/// finalized here; the proof-bearing spend is realized post-seam by
/// [`MidnightCryptoProvider::authorize_dust`].
pub(super) fn size_dust_fee(ctx: &DustFeeContext) -> Result<DustFeePlan, std::io::Error> {
    const MAX_FEE_ITERS: usize = 8;
    let intent_ttl = chain_aligned_intent_ttl(ctx.dust_ctime);

    // First pass: a zero-allowance registration only to size the fee.
    let first = registration_dust_actions(ctx.dust_pk, ctx.night_vk.clone(), 0, ctx.dust_ctime);
    let tx_first = wrap_proven_standard(
        ctx.stx,
        ctx.seg_id,
        assemble_proven_intent(
            ctx.offer,
            ctx.fallible_offer,
            ctx.intent_in,
            Some(first),
            intent_ttl,
        ),
    );
    let mut fee_target = tx_first
        .fees(ctx.ledger_params, false)
        .map_err(|e| err(format!("DUST fee estimate failed: {e:?}")))?;

    // The dust state is expensive to sync, so pull it only when the spend fallback is first needed.
    let mut dust_state: Option<DustLocalState<InMemoryDB>> = None;

    for attempt in 0..MAX_FEE_ITERS {
        if let Some(reg) = try_registration_dust_actions(
            ctx.selected,
            fee_target,
            ctx.dust_pk,
            ctx.night_vk.clone(),
            ctx.dust_ctime,
        )? {
            let tx_check = wrap_proven_standard(
                ctx.stx,
                ctx.seg_id,
                assemble_proven_intent(
                    ctx.offer,
                    ctx.fallible_offer,
                    ctx.intent_in,
                    Some(reg.clone()),
                    intent_ttl,
                ),
            );
            if dust_section_covers_fee(&tx_check, ctx.ledger_params)? {
                return Ok(DustFeePlan::Registration(reg));
            }
        }

        if dust_state.is_none() {
            dust_state = Some(sync_spendable_dust_state(
                ctx.indexer_url,
                ctx.crypto_provider,
                ctx.scope,
            )?);
        }
        let synced = dust_state.as_ref().expect("dust state synced above");
        let dust_actions = build_mock_dust_spends(ctx, synced, fee_target, intent_ttl)?;
        let tx_check = wrap_proven_standard(
            ctx.stx,
            ctx.seg_id,
            assemble_proven_intent(
                ctx.offer,
                ctx.fallible_offer,
                ctx.intent_in,
                Some(dust_actions.clone()),
                intent_ttl,
            ),
        );
        if dust_section_covers_fee(&tx_check, ctx.ledger_params)? {
            return Ok(DustFeePlan::Spend {
                plan: DustSpendPlan {
                    fee_dust: fee_target,
                    dust_ctime: ctx.dust_ctime,
                    intent_ttl,
                    seg_id: ctx.seg_id,
                    binding_commitment: ctx.intent_in.binding_commitment,
                },
                dust_state: Box::new(synced.clone()),
                ledger_params: Box::new(ctx.ledger_params.clone()),
            });
        }

        let actual_fee = tx_check
            .fees(ctx.ledger_params, true)
            .map_err(|e| err(format!("DUST fee re-estimate failed: {e:?}")))?;
        let dust_paid = sum_dust_v_fee(dust_actions.spends.iter_deref());
        fee_target = actual_fee
            .max(fee_target.saturating_add(1))
            .max(dust_paid.saturating_add(1));
        if attempt + 1 == MAX_FEE_ITERS {
            return Err(err(format!(
                "failed to cover the DUST fee after {MAX_FEE_ITERS} attempts \
                 (target={fee_target}, paid={dust_paid}, fee={actual_fee})"
            )));
        }
    }
    Err(err("failed to cover the DUST fee"))
}

/// Fee-sizing twin of the signer's [`MidnightCryptoProvider::authorize_shielded`]: build the same
/// proof-preimage spend witnesses + self-change for each planned segment via the crypto provider, then
/// `mock_prove` each fragment instead of really proving it. `mock_prove` yields a correctly-sized
/// (non-verifying, non-submittable) `ProofMarker` offer whose serialized size — hence fee contribution
/// — matches the real proof's exactly (ZK proofs are fixed-size). Discarded after sizing; the real,
/// submittable offer is built post-seam by the signer. Returns the per-segment mock-proven fragments
/// (so the caller can route each to the offer bound to its segment, matching the real placement) plus
/// their summed binding-randomness delta, to splice into the fee-sizing transaction.
fn build_mock_shielded(
    network_id: String,
    crypto_provider: &MidnightCryptoProvider,
    plans: &[ShieldedSpendPlan],
    tree: &ZswapLocalState<InMemoryDB>,
) -> Result<(Vec<ShieldedFragment>, PedersenRandomness), std::io::Error> {
    let (preimages, binding_delta) = crypto_provider
        .build_preimage_shielded_offers(plans, tree)
        .map_err(|e| err(e.to_string()))?;

    let mut fragments = Vec::with_capacity(preimages.len());
    for (segment, preimage) in preimages {
        let proven = mock_prove_shielded_offer(network_id.clone(), preimage)?;
        fragments.push((segment, proven));
    }

    if fragments.is_empty() {
        return Err(err("no shielded segments to mock-prove"));
    }
    Ok((fragments, binding_delta))
}

/// Mock-prove a single proof-preimage Zswap offer into a fixed-size `ProofMarker` offer. `mock_prove`
/// operates on a whole transaction, so the offer is wrapped as the guaranteed coins of a throwaway
/// standard tx (one trivial intent — the shape `mock_prove` accepts) and the proven offer is lifted
/// back out.
fn mock_prove_shielded_offer(
    network_id: String,
    preimage: ZswapOffer<ProofPreimage, InMemoryDB>,
) -> Result<ZswapOffer<ZswapProof, InMemoryDB>, std::io::Error> {
    let binding_randomness = preimage.binding_randomness();
    let trivial_intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Intent {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(0, trivial_intent);
    let stx: StandardTransaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        StandardTransaction {
            network_id,
            intents,
            guaranteed_coins: Some(Sp::new(preimage)),
            fallible_coins: MnHashMap::new(),
            binding_randomness,
        };
    let tx: Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Transaction::Standard(stx);
    let mock = tx
        .mock_prove()
        .map_err(|e| err(format!("mock-prove shielded inputs failed: {e:?}")))?;
    let Transaction::Standard(mstx) = mock else {
        return Err(err("mock-proven shielded transaction was not Standard"));
    };
    mstx.guaranteed_coins
        .as_ref()
        .map(|sp| sp.deref().clone())
        .ok_or_else(|| err("mock-proven shielded transaction has no guaranteed coins"))
}

/// Splice a mock-proven shielded section into a copy of `base` for DUST fee sizing. The DUST fee
/// covers the whole tx, shielded proofs included, but the real shielded proving is deferred past the
/// seam — so size the fee against a `mock_prove`d stand-in of the shielded section (same fixed-size
/// proofs → same fee) and discard it. Each fragment is routed to the offer bound to its segment
/// (segment 0 → guaranteed, segment N>=1 → `fallible_coins[N]`), mirroring the real placement in
/// [`authorize_proven_tx`] so the sized fee matches the real tx's serialized byte length. Returns
/// `base` untouched when there is no shielded funding.
pub(super) fn splice_mock_shielded_for_sizing(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    crypto_provider: &MidnightCryptoProvider,
    shielded: &ShieldedFundingPlan,
) -> Result<StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>, std::io::Error>
{
    let (fragments, binding_delta) = build_mock_shielded(
        base.network_id.clone(),
        crypto_provider,
        &shielded.plans,
        &shielded.tree,
    )?;
    let mut sized = base.clone();
    for (segment, proven) in &fragments {
        place_shielded_fragment(&mut sized, *segment, proven)?;
    }
    sized.binding_randomness = sized.binding_randomness + binding_delta;
    Ok(sized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;
    use midnight_coin_structure::coin::Info as CoinInfo;
    use midnight_ledger::dust::DustSecretKey;
    use midnight_zswap::keys::SecretKeys;
    use midnight_zswap::Output as ZswapOutput;

    // Unshielded role-0 seed for the abandon-phrase wallet at index 0; matches the signer's
    // address vectors.
    const UNSHIELDED_SEED_HEX: &str =
        "822fa63c57f6317cd51d12d80f0e64c2bc2164088dec1c71ca34a87a890190aa";

    fn night_utxo(value: u128, registered: bool, ctime: Option<u64>) -> UnshieldedUtxo {
        UnshieldedUtxo {
            token_type: "00".repeat(32), // NIGHT wire id = 64 hex zeros
            value,
            intent_hash: "00".into(),
            output_index: 0,
            owner: "sender".into(),
            ctime_unix_secs: ctime,
            registered_for_dust_generation: registered,
        }
    }

    #[test]
    fn dust_allowance_counts_only_unregistered_night_with_a_timestamp() {
        let ctime = 1_000u64;
        let now = Timestamp::from_secs(ctime + 100);

        // Registered NIGHT and non-NIGHT are both excluded from generationless capacity.
        let mut non_night = night_utxo(1_000_000, false, Some(ctime));
        non_night.token_type = "ff".repeat(32);
        let zero = dust_allowance_from_night_inputs(
            &[night_utxo(1_000_000, true, Some(ctime)), non_night],
            now,
        )
        .unwrap();
        assert_eq!(zero, 0);

        // An unregistered NIGHT input with a block timestamp yields capacity.
        let some =
            dust_allowance_from_night_inputs(&[night_utxo(1_000_000, false, Some(ctime))], now)
                .unwrap();
        assert!(some > 0);

        // Without a block timestamp we can't size it — that's an error, not a silent zero.
        assert!(
            dust_allowance_from_night_inputs(&[night_utxo(1_000_000, false, None)], now).is_err()
        );
    }

    #[test]
    fn cap_allow_fee_payment_adds_headroom_or_errors() {
        // fee=10_000 → headroom max(4×, +50_000) = 60_000, clamped by available allowance.
        assert_eq!(cap_allow_fee_payment(1_000_000, 10_000).unwrap(), 60_000);
        assert_eq!(cap_allow_fee_payment(55_000, 10_000).unwrap(), 55_000);
        // Allowance below the fee cannot cover it.
        assert!(cap_allow_fee_payment(5_000, 10_000).is_err());
    }

    /// A dust spend with only `v_fee` set — the rest are placeholders (`sum_dust_v_fee` reads only
    /// `v_fee`), so we use the `()` proof kind to avoid constructing a real ZK proof.
    fn dust_spend_v_fee(v_fee: u128) -> DustSpend<(), InMemoryDB> {
        use midnight_ledger::dust::{DustCommitment, DustNullifier};
        use transient_crypto::curve::Fr;
        DustSpend {
            v_fee,
            old_nullifier: DustNullifier(Fr::default()),
            new_commitment: DustCommitment(Fr::default()),
            proof: (),
        }
    }

    #[test]
    fn sum_dust_v_fee_saturates_over_all_spends() {
        let empty: [DustSpend<(), InMemoryDB>; 0] = [];
        assert_eq!(sum_dust_v_fee(empty.iter()), 0);
        let spends = [
            dust_spend_v_fee(1_000),
            dust_spend_v_fee(2_500),
            dust_spend_v_fee(7),
        ];
        assert_eq!(sum_dust_v_fee(spends.iter()), 3_507);
    }

    /// The live-run trigger for the proof-bearing fallback: a fully dust-registered wallet has no
    /// generationless capacity, so `try_registration_dust_actions` yields `None` and the caller must
    /// fall back to proving a DUST spend.
    #[test]
    fn all_registered_night_yields_no_registration_forcing_the_spend_fallback() {
        let dust_pk = DustPublicKey::from(DustSecretKey::derive_secret_key(&[0x22u8; 32]));
        let night_vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let now = Timestamp::from_secs(2_000);

        // All NIGHT registered for dust generation → zero generationless allowance → no registration.
        let none = try_registration_dust_actions(
            &[night_utxo(1_000_000, true, Some(1_000))],
            10_000,
            dust_pk,
            night_vk.clone(),
            now,
        )
        .unwrap();
        assert!(
            none.is_none(),
            "registered NIGHT must not fund a registration"
        );

        // An unregistered NIGHT input keeps the (non-proving) registration path available.
        let some = try_registration_dust_actions(
            &[night_utxo(1_000_000, false, Some(1_000))],
            10_000,
            dust_pk,
            night_vk,
            now,
        )
        .unwrap();
        assert!(
            some.is_some(),
            "unregistered NIGHT should fund a registration"
        );
    }

    /// Verifies the fee-sizing assumption the deferred-dust path relies on: `mock_prove` (offline, no
    /// real proving keys) yields a transaction whose ledger fee equals the real-proven transaction's
    /// fee — because ZK proofs are fixed-size, so the fee depends only on tx structure. Ignored by
    /// default because real proving uses the (cached) CDN proving keys; run with `--ignored`.
    #[test]
    #[ignore = "real-proves with the cached/CDN proving keys; run explicitly"]
    fn mock_prove_fee_matches_real_prove_fee() {
        use midnight_ledger::structure::INITIAL_PARAMETERS;
        use rand::rngs::{OsRng, StdRng};
        use rand::{Rng as _, SeedableRng as _};

        // A preimage tx with a few shielded outputs to a throwaway recipient (outputs need only a
        // public key, so no funded wallet is required).
        let mut rng = OsRng;
        let keys = SecretKeys::from_rng_seed(&mut rng);
        let cpk = keys.coin_public_key();
        let token = ShieldedTokenType(HashOutput([9u8; 32]));
        let outputs: Vec<_> = (0..3u128)
            .map(|i| {
                let coin = CoinInfo {
                    nonce: rng.r#gen(),
                    type_: token,
                    value: 1_000 + i,
                };
                ZswapOutput::new(&mut rng, &coin, Some(1), &cpk, Some(keys.enc_public_key()))
                    .expect("build output")
            })
            .collect();
        let offer = ZswapOffer::new(vec![], outputs, vec![]).expect("build offer");
        let binding_randomness = offer.binding_randomness();

        let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1, intent);
        let stx: StandardTransaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
            StandardTransaction {
                network_id: "preview".to_string(),
                intents,
                guaranteed_coins: Some(Sp::new(offer)),
                fallible_coins: MnHashMap::new(),
                binding_randomness,
            };
        let tx: Transaction<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
            Transaction::Standard(stx);

        // Mock prove — offline; fee-accurate by construction.
        let tx_mock = tx.mock_prove().expect("mock_prove");
        let fee_mock = tx_mock.fees(&INITIAL_PARAMETERS, false).expect("mock fees");

        // Real prove with the local prover, then seal to the same binding form as mock_prove.
        let scope = SyncCacheScope {
            chain_id: Some("midnight:preview".to_string()),
            ..Default::default()
        };
        let dir = crate::cache_io::proving_keys_dir(&scope).expect("proving-key dir");
        let prover = crate::Prover::new(dir);
        let cost_model = &INITIAL_PARAMETERS.cost_model.runtime_cost_model;
        let tx_real = crate::block_on(tx.prove(prover, cost_model)).expect("real prove");
        let tx_real = tx_real.seal(StdRng::from_entropy());
        let fee_real = tx_real.fees(&INITIAL_PARAMETERS, false).expect("real fees");

        let mut mb = Vec::new();
        tagged_serialize(&tx_mock, &mut mb).unwrap();
        let mut rb = Vec::new();
        tagged_serialize(&tx_real, &mut rb).unwrap();
        eprintln!(
            "mock: fee={fee_mock} size={} | real: fee={fee_real} size={}",
            mb.len(),
            rb.len()
        );
        assert_eq!(
            fee_mock, fee_real,
            "mock_prove fee must equal real-prove fee (fixed-size proofs)"
        );
    }
}
