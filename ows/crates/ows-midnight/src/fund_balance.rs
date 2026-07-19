//! `ows fund balance --chain midnight:*` display (unshielded indexer balances).

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Chain;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork, MidnightSigner};

use super::wallet::{resolve_indexer_url, sync_scope_for_wallet};
use super::{block_on, get_unshielded_utxos_for_display};

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
        return Ok(());
    }

    eprintln!("Unshielded balances:");
    for (token_type, amount) in unshielded {
        println!("{amount:>24} {token_type}");
    }
    Ok(())
}
