use ows_signer::signer_for_chain;

use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        let result = ows_lib::sign_transaction(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            None,
        )?;
        return print_result(&result.signature, result.recovery_id, json_output);
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex transaction: {e}")))?;

    let signer = signer_for_chain(&chain);
    let signable = signer.extract_signable_bytes(&tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    print_result(
        &hex::encode(&output.signature),
        output.recovery_id,
        json_output,
    )
}

fn print_result(
    signature: &str,
    recovery_id: Option<u8>,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": signature,
            "recovery_id": recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{signature}");
    }
    Ok(())
}
