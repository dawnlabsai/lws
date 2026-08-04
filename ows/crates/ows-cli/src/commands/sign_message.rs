use ows_signer::chains::EvmSigner;
use ows_signer::signer_for_chain;
use ows_signer::ChainSigner;

use crate::{parse_chain, CliError};

#[allow(clippy::too_many_arguments)]
pub fn run(
    chain_str: &str,
    wallet_name: &str,
    message: &str,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
    address: Option<&str>,
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
                address,
                None,
            )?;
            return print_result(&result.signature, result.recovery_id, json_output);
        }
        let result = ows_lib::sign_message(
            wallet_name,
            chain_str,
            message,
            passphrase.as_deref(),
            Some(encoding),
            Some(index),
            address,
            None,
        )?;
        return print_result(&result.signature, result.recovery_id, json_output);
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
        ChainSigner::verify_sign_message_address(&*signer, key.expose(), address)?;
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
        signer.sign_message(key.expose(), &msg_bytes, address)?
    };

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
