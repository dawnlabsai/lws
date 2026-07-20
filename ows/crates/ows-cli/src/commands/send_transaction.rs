use crate::{audit, parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
    rpc_url_override: Option<&str>,
) -> Result<(), CliError> {
    // Check for API token — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        let result = ows_lib::sign_and_send(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            rpc_url_override,
            None,
        )?;

        if json_output {
            let obj = serde_json::json!({
                "tx_hash": result.tx_hash,
                "chain": chain_str,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!("{}", result.tx_hash);
        }

        audit::log_broadcast(wallet_name, chain_str, &result.tx_hash);
        return Ok(());
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_bytes = ows_lib::decode_tx_input(&chain, tx_hex)?;

    let result =
        ows_lib::sign_encode_and_broadcast(key.expose(), chain_str, &tx_bytes, rpc_url_override)?;

    if json_output {
        let obj = serde_json::json!({
            "tx_hash": result.tx_hash,
            "chain": chain_str,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.tx_hash);
    }

    audit::log_broadcast(wallet_name, chain_str, &result.tx_hash);

    Ok(())
}
