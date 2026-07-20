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

/// Size a generationless DUST fee registration that balances the transaction. The fee depends on the
/// tx (registration bytes included), so estimate → build registration → re-check, converging within
/// a few iterations. Registration-only (no proof); a wallet with no unregistered NIGHT capacity is
/// an error here rather than falling back to proof-bearing dust spends.
#[allow(clippy::too_many_arguments)]
pub(super) fn cover_dust_fee_registration(
    stx: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
    selected: &[UnshieldedUtxo],
    dust_pk: DustPublicKey,
    night_vk: VerifyingKey,
    dust_ctime: Timestamp,
    ledger_params: &LedgerParameters,
) -> Result<DustActions<MnSig, ProofMarker, InMemoryDB>, std::io::Error> {
    const MAX_FEE_ITERS: usize = 8;
    let intent_ttl = chain_aligned_intent_ttl(dust_ctime);

    // First pass: a zero-allowance registration only to size the fee.
    let first = registration_dust_actions(dust_pk, night_vk.clone(), 0, dust_ctime);
    let tx_first = wrap_proven_standard(
        stx,
        seg_id,
        assemble_proven_intent(offer, intent_in, Some(first), intent_ttl),
    );
    let mut fee_target = tx_first
        .fees(ledger_params, false)
        .map_err(|e| err(format!("DUST fee estimate failed: {e:?}")))?;

    for attempt in 0..MAX_FEE_ITERS {
        let Some(reg) = try_registration_dust_actions(
            selected,
            fee_target,
            dust_pk,
            night_vk.clone(),
            dust_ctime,
        )?
        else {
            return Err(err(
                "no unregistered NIGHT inputs to fund the DUST fee via a generationless registration",
            ));
        };
        let tx_check = wrap_proven_standard(
            stx,
            seg_id,
            assemble_proven_intent(offer, intent_in, Some(reg.clone()), intent_ttl),
        );
        if tx_balance_imbalances(&tx_check)?.is_empty() {
            return Ok(reg);
        }
        let actual_fee = tx_check
            .fees(ledger_params, false)
            .map_err(|e| err(format!("DUST fee re-estimate failed: {e:?}")))?;
        fee_target = actual_fee.max(fee_target.saturating_add(1));
        if attempt + 1 == MAX_FEE_ITERS {
            return Err(err(format!(
                "failed to cover the DUST fee after {MAX_FEE_ITERS} attempts (target {fee_target})"
            )));
        }
    }
    Err(err("failed to cover the DUST fee"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
