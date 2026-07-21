use ows_signer::chains::EvmSigner;
use ows_signer::signer_for_chain;

use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    message: &str,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        if let Some(td_json) = typed_data {
            let result = ows_lib::sign_typed_data(
                wallet_name,
                chain_str,
                td_json,
                passphrase.as_deref(),
                Some(index),
                None,
            )?;
            return print_result(&result, json_output);
        }
        let result = ows_lib::sign_message(
            wallet_name,
            chain_str,
            message,
            passphrase.as_deref(),
            Some(encoding),
            Some(index),
            None,
        )?;
        return print_result(&result, json_output);
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let signer = signer_for_chain(&chain);

    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != ows_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        EvmSigner.sign_typed_data(key.expose(), td_json)?
    } else {
        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(message)
                .map_err(|e| CliError::InvalidArgs(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )))
            }
        };
        signer.sign_message(key.expose(), &msg_bytes)?
    };

    // Encode per chain — Midnight prefixes the x-only pubkey to the BIP-340 signature; every other
    // chain returns the hex signature as-is.
    let result = ows_lib::sign_result_from_message_output(chain.chain_type, &output)?;
    print_result(&result, json_output)
}

fn print_result(result: &ows_lib::SignResult, json_output: bool) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": result.signature,
            "recovery_id": result.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.signature);
    }
    Ok(())
}
