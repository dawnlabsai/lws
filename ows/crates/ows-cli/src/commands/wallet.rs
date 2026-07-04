use std::io::IsTerminal;

use crate::audit;
use crate::CliError;
use zeroize::Zeroize;

pub fn create(name: &str, words: u32, show_mnemonic: bool) -> Result<(), CliError> {
    // Generate mnemonic, then import it to create the wallet
    let mut mnemonic_phrase = ows_lib::generate_mnemonic(words)?;
    let info = ows_lib::import_wallet_mnemonic(name, &mnemonic_phrase, None, Some(0), None)?;

    audit::log_wallet_created(&info);

    println!("Wallet created: {}", info.id);
    println!("Name:           {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    if show_mnemonic {
        eprintln!();
        eprintln!("⚠️  WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
        eprintln!("⚠️  Store it securely offline. It will NOT be shown again.");
        eprintln!();
        println!("{mnemonic_phrase}");
    } else {
        eprintln!();
        eprintln!("Mnemonic encrypted and saved to vault.");
        eprintln!("Use --show-mnemonic at creation time if you need a backup copy.");
    }

    mnemonic_phrase.zeroize();
    Ok(())
}

pub fn import(
    name: &str,
    use_mnemonic: bool,
    use_private_key: bool,
    chain: Option<&str>,
    index: u32,
) -> Result<(), CliError> {
    // Read curve-specific keys from environment variables (cleared immediately after reading)
    let secp256k1_key = ows_signer::process_hardening::clear_env_var("OWS_SECP256K1_KEY");
    let ed25519_key = ows_signer::process_hardening::clear_env_var("OWS_ED25519_KEY");
    let secp256k1_key = secp256k1_key.as_deref().filter(|s| !s.is_empty());
    let ed25519_key = ed25519_key.as_deref().filter(|s| !s.is_empty());

    let has_curve_keys = secp256k1_key.is_some() || ed25519_key.is_some();
    let both_curve_keys = secp256k1_key.is_some() && ed25519_key.is_some();

    // Must specify exactly one import mode: --mnemonic, --private-key, or both curve keys (via env)
    if use_mnemonic && (use_private_key || has_curve_keys) {
        return Err(CliError::InvalidArgs(
            "cannot combine --mnemonic with --private-key or curve-specific keys".into(),
        ));
    }
    if !use_mnemonic && !use_private_key && !both_curve_keys {
        return Err(CliError::InvalidArgs(
            "specify --mnemonic, --private-key, or set OWS_SECP256K1_KEY and OWS_ED25519_KEY"
                .into(),
        ));
    }

    let info = if use_mnemonic {
        let phrase = super::read_mnemonic()?;
        ows_lib::import_wallet_mnemonic(name, &phrase, None, Some(index), None)?
    } else {
        // Read from env/stdin only when both curve keys are not already provided
        let private_key_hex = if both_curve_keys {
            zeroize::Zeroizing::new(String::new())
        } else {
            super::read_private_key()?
        };
        ows_lib::import_wallet_private_key(
            name,
            &private_key_hex,
            chain,
            None,
            None,
            secp256k1_key,
            ed25519_key,
        )?
    };

    audit::log_wallet_imported(&info);

    println!("Wallet imported: {}", info.id);
    println!("Name:            {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    Ok(())
}

pub fn export(wallet_name: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet export requires an interactive terminal (do not pipe stdin)".into(),
        ));
    }

    // Try empty passphrase first, then prompt if it fails
    let mut exported = match ows_lib::export_wallet(wallet_name, None, None) {
        Ok(s) => s,
        Err(_) => {
            let passphrase = super::read_passphrase();
            ows_lib::export_wallet(wallet_name, Some(&passphrase), None)?
        }
    };

    let is_key_pair = exported.starts_with('{');
    eprintln!();
    if is_key_pair {
        eprintln!("WARNING: The private key below provides FULL ACCESS to this wallet.");
    } else {
        eprintln!("WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
    }
    eprintln!("Do not share it. Store it securely offline.");
    eprintln!();
    println!("{exported}");
    exported.zeroize();

    let info = ows_lib::get_wallet(wallet_name, None)?;
    audit::log_wallet_exported(&info.id);
    Ok(())
}

pub fn delete(wallet_name: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To delete a wallet, pass --confirm.");
        eprintln!("Consider exporting it first: ows wallet export --wallet {wallet_name}");
        return Err(CliError::InvalidArgs(
            "--confirm is required to delete a wallet".into(),
        ));
    }

    let info = ows_lib::get_wallet(wallet_name, None)?;
    ows_lib::delete_wallet(wallet_name, None)?;
    audit::log_wallet_deleted(&info.id, &info.name);

    println!("Wallet deleted: {} ({})", info.id, info.name);
    Ok(())
}

pub fn rename(wallet_name: &str, new_name: &str) -> Result<(), CliError> {
    let info = ows_lib::get_wallet(wallet_name, None)?;
    ows_lib::rename_wallet(wallet_name, new_name, None)?;
    audit::log_wallet_renamed(&info.id, &info.name, new_name);

    println!("Wallet renamed: '{}' -> '{}'", info.name, new_name);
    Ok(())
}

pub fn list() -> Result<(), CliError> {
    let wallets = ows_lib::list_wallets(None)?;

    if wallets.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    for w in &wallets {
        println!("ID:      {}", w.id);
        println!("Name:    {}", w.name);
        println!("Secured: ✓ (encrypted)");
        for acct in &w.accounts {
            let label = ows_core::parse_chain(&acct.chain_id)
                .map(|c| format!(" ({})", c.name))
                .unwrap_or_default();
            println!("  {}{} → {}", acct.chain_id, label, acct.address);
        }
        println!("Created: {}", w.created_at);
        println!();
    }

    Ok(())
}

pub fn public_key(wallet_name: &str, chain: &str, index: u32, json_output: bool) -> Result<(), CliError> {
    let pubkey = ows_lib::get_public_key(wallet_name, chain, Some(index), None)?;
    if json_output {
        let obj = serde_json::json!({
            "wallet": wallet_name,
            "chain": chain,
            "index": index,
            "public_key": pubkey,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{pubkey}");
    }
    Ok(())
}
