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

/// The transaction context a DUST fee section is sized against: the proven standard tx and its
/// single intent segment, the balanced unshielded offer and the UTXOs funding it, the wallet's
/// dust key / night key, the crypto provider + indexer + scope (to sync a spendable dust state and
/// prove dust spends), and the chain time plus ledger parameters that fix the fee.
pub(super) struct DustFeeContext<'a> {
    pub(super) stx: &'a StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    pub(super) seg_id: u16,
    pub(super) intent_in: &'a Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    pub(super) offer: &'a UnshieldedOffer<MnSig, InMemoryDB>,
    pub(super) selected: &'a [UnshieldedUtxo],
    pub(super) dust_pk: DustPublicKey,
    pub(super) night_vk: VerifyingKey,
    pub(super) crypto_provider: &'a MidnightCryptoProvider,
    pub(super) dust_ctime: Timestamp,
    pub(super) ledger_params: &'a LedgerParameters,
    pub(super) indexer_url: &'a str,
    pub(super) scope: &'a SyncCacheScope,
}

/// Size a DUST fee section that balances the transaction. The fee depends on the tx (dust-section
/// bytes included), so estimate → build section → re-check, converging within a few iterations.
///
/// Each iteration prefers a signature-based **generationless registration** funded by the wallet's
/// unregistered NIGHT (no proving). When the wallet has no unregistered NIGHT capacity — a normal
/// funded wallet registers all its NIGHT for dust generation — it falls back to a proof-bearing
/// **DUST spend** of its generated dust, syncing the spendable dust state once and proving the
/// spends via the crypto provider's local prover.
pub(super) fn cover_dust_fees(
    ctx: &DustFeeContext,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, std::io::Error> {
    const MAX_FEE_ITERS: usize = 8;
    let intent_ttl = chain_aligned_intent_ttl(ctx.dust_ctime);

    // First pass: a zero-allowance registration only to size the fee.
    let first = registration_dust_actions(ctx.dust_pk, ctx.night_vk.clone(), 0, ctx.dust_ctime);
    let tx_first = wrap_proven_standard(
        ctx.stx,
        ctx.seg_id,
        assemble_proven_intent(ctx.offer, ctx.intent_in, Some(first), intent_ttl),
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
                assemble_proven_intent(ctx.offer, ctx.intent_in, Some(reg.clone()), intent_ttl),
            );
            if tx_balance_imbalances(&tx_check)?.is_empty() {
                return Ok(reg);
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
        let dust_actions = build_proven_dust_spends(ctx, synced, fee_target, intent_ttl)?;
        let tx_check = wrap_proven_standard(
            ctx.stx,
            ctx.seg_id,
            assemble_proven_intent(
                ctx.offer,
                ctx.intent_in,
                Some(dust_actions.clone()),
                intent_ttl,
            ),
        );
        if tx_balance_imbalances(&tx_check)?.is_empty() {
            return Ok(dust_actions);
        }

        let actual_fee = tx_check
            .fees(ctx.ledger_params, false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;
    use midnight_ledger::dust::DustSecretKey;

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
}
