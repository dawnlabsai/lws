//! `ows fund balance --chain midnight:*` display (unshielded balances + dust fee status).

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Chain;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork, MidnightSigner};

use super::dust_sync;
use super::wallet::{resolve_indexer_url, sync_scope_for_wallet};
use super::{
    block_on, format_dust_specks, get_dust_balance_for_display, get_unshielded_utxos_for_display,
    parse_token_type, UnshieldedUtxo,
};

/// Print the wallet's Midnight addresses: unshielded always, shielded/dust only when the
/// crypto provider is available (no passphrase, or a raw imported key, leaves them out).
fn print_addresses(
    network: &MidnightNetwork,
    unshielded_address: &str,
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<(), std::io::Error> {
    eprintln!("Addresses:");
    eprintln!("  Unshielded: {unshielded_address}");

    if let Some(provider) = crypto_provider {
        let addrs = provider
            .addresses(network)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        eprintln!("  Shielded:   {}", addrs.shielded);
        eprintln!("  Dust:       {}", addrs.dust);
    } else {
        eprintln!("  Shielded:   (unavailable)");
        eprintln!("  Dust:       (unavailable)");
    }
    eprintln!();
    Ok(())
}

/// Print DUST fee status: the NIGHT-UTXO registration summary (derived from the public
/// unshielded UTXOs, so always available) and, when the dust seed is available, the synced
/// DUST balance. Without the seed the balance reports as unavailable rather than failing.
fn print_dust_status(
    indexer_url: &str,
    unshielded_utxos: &[UnshieldedUtxo],
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<(), std::io::Error> {
    eprintln!("Dust status (fees):");

    let night_wire = parse_token_type(Some("night"))
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .to_wire_token_type();
    let total_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .count();
    let registered_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .filter(|u| u.registered_for_dust_generation)
        .count();
    let unregistered_night = total_night.saturating_sub(registered_night);

    if total_night == 0 {
        eprintln!("  NIGHT UTXOs: none found (dust generation uses NIGHT inputs)");
    } else {
        eprintln!(
            "  NIGHT UTXOs: total={total_night} registered={registered_night} unregistered={unregistered_night}"
        );
        if unregistered_night > 0 {
            eprintln!(
                "  Fee mode: generationless DUST (can be derived from unregistered NIGHT inputs)"
            );
        } else {
            eprintln!("  Fee mode: DUST spend proofs (all NIGHT inputs already registered)");
        }
    }

    let Some(provider) = crypto_provider else {
        eprintln!("  DUST seed: unavailable (can't sync dust ledger state)");
        eprintln!();
        return Ok(());
    };

    eprintln!("  DUST seed: available");
    eprintln!("  Syncing DUST ledger (replaying from genesis; progress below)...");
    let chain_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    match block_on(get_dust_balance_for_display(
        indexer_url,
        provider,
        chain_time,
    )) {
        Ok((dust_utxo_count, dust_sum)) => {
            eprintln!("  DUST UTXOs: {dust_utxo_count}");
            eprintln!(
                "  DUST balance: {} (best-effort, wall-clock time)",
                format_dust_specks(dust_sum)
            );
        }
        Err(e) => eprintln!("  DUST: unavailable ({e})"),
    }
    eprintln!();
    Ok(())
}

/// Indexer-backed balance display for `ows fund balance --chain midnight:*`.
///
/// The stored unshielded address is re-encoded for the target network's bech32 HRP and its
/// UTXO set is summed per token. The optional `crypto_provider` (built by the caller from the
/// owner passphrase) additionally derives the shielded/dust addresses; a raw imported key whose
/// bytes carry no packed Midnight roles yields no provider and is treated the same as no key.
pub fn print_fund_balance(
    wallet_id: &str,
    stored_unshielded_address: &str,
    chain: &Chain,
    vault_path: Option<&Path>,
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<(), std::io::Error> {
    let chain_id = chain.chain_id;
    let address = MidnightSigner::from_chain_id(chain_id)
        .reencode_unshielded_address(stored_unshielded_address)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let indexer_url = resolve_indexer_url(chain_id)?;
    let sync_scope = sync_scope_for_wallet(wallet_id, Some(chain_id), vault_path);

    eprintln!("[ows-midnight] syncing unshielded balance from indexer…");
    let unshielded_utxos = block_on(get_unshielded_utxos_for_display(
        &indexer_url,
        &address,
        &sync_scope,
    ))
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut unshielded: BTreeMap<String, u128> = BTreeMap::new();
    for u in &unshielded_utxos {
        *unshielded.entry(u.token_type.clone()).or_insert(0) += u.value;
    }

    print_addresses(
        &MidnightNetwork::from_chain_id(chain_id),
        &address,
        crypto_provider,
    )?;

    if unshielded.is_empty() {
        eprintln!("No Midnight unshielded tokens found for {address} on {chain_id}");
        eprintln!();
    } else {
        eprintln!("Unshielded balances:");
        for (token_type, amount) in unshielded {
            println!("{amount:>24} {token_type}");
        }
        eprintln!();
    }

    // Whether to show the dust-fee section is a runtime property of the network, not its name:
    // probe the indexer's dust ledger and show dust only when its stream reports a live tip. A
    // network activates dust automatically here — no code change when a new one (mainnet included)
    // turns it on.
    if block_on(dust_sync::dust_ledger_is_live(&indexer_url)) {
        print_dust_status(&indexer_url, &unshielded_utxos, crypto_provider)?;
    }

    Ok(())
}
