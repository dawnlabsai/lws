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
        return print_result(
            &result.signature,
            result.recovery_id,
            result.transaction,
            json_output,
        );
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_bytes = ows_lib::decode_tx_input(&chain, tx_hex)?;
    let signable_tx = ows_lib::prepare_signable_tx(&chain, tx_bytes, &key)?;

    let signer = signer_for_chain(&chain);
    let signable = signer.extract_signable_bytes(&signable_tx)?;
    let output = signer.sign_transaction(key.expose(), signable)?;
    let transaction =
        ows_lib::signed_transaction_hex(&chain, signer.as_ref(), &signable_tx, &output)?;

    print_result(
        &hex::encode(&output.signature),
        output.recovery_id,
        transaction,
        json_output,
    )
}

fn print_result(
    signature: &str,
    recovery_id: Option<u8>,
    transaction: Option<String>,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let mut obj = serde_json::json!({
            "signature": signature,
            "recovery_id": recovery_id,
        });
        // Only chains that seal a complete transaction at sign time (Midnight) carry this.
        if let Some(transaction) = transaction {
            obj["transaction"] = serde_json::Value::String(transaction);
        }
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{signature}");
    }
    Ok(())
}
