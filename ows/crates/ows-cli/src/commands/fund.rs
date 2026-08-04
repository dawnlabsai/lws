use crate::CliError;
use ows_core::parse_chain;
use ows_lib::ops::resolve_rpc_url;
use ows_lib::types::AccountInfo;

/// Returns the wallet account matching the target funding chain.
fn find_account_for_chain<'a>(
    accounts: &'a [AccountInfo],
    chain: &str,
) -> Result<&'a AccountInfo, CliError> {
    let parsed_chain =
        parse_chain(chain).map_err(|e| CliError::InvalidArgs(format!("unknown chain: {e}")))?;

    accounts
        .iter()
        .find(|a| a.chain_id == parsed_chain.chain_id)
        .ok_or_else(|| {
            CliError::InvalidArgs(format!("wallet has no account for chain \"{chain}\""))
        })
}

/// `ows fund buy --wallet <name> [--chain base] [--token USDC]`
///
/// Creates a MoonPay deposit that generates multi-chain deposit addresses.
/// Anyone can send crypto from any chain — it auto-converts to the target token.
pub fn run(wallet_name: &str, chain: Option<&str>, token: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");

    let account = find_account_for_chain(&wallet.accounts, chain_name)?;
    let address = &account.address;
    let token_name = token.unwrap_or("USDC");

    eprintln!("Creating deposit for wallet \"{wallet_name}\" ({address})");
    eprintln!("Target: {token_name} on {chain_name}");

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::fund::fund(
        address,
        Some(chain_name),
        Some(token_name),
    ))?;

    eprintln!();
    eprintln!("Deposit created (ID: {})", result.deposit_id);
    eprintln!();

    // Show deposit addresses.
    if !result.wallets.is_empty() {
        eprintln!("Send crypto to any of these addresses:");
        for (chain, addr) in &result.wallets {
            eprintln!("  {chain:>10}  {addr}");
        }
        eprintln!();
    }

    eprintln!("{}", result.instructions);
    eprintln!();

    // Print the deposit URL (opens in browser for a web flow).
    println!("{}", result.deposit_url);

    // Try to open in browser.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&result.deposit_url)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&result.deposit_url)
            .spawn();
    }

    Ok(())
}

/// `ows fund balance --wallet <name> [--chain base]`
///
/// Check token balances via MoonPay.
pub fn balance(wallet_name: &str, chain: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");

    let account = find_account_for_chain(&wallet.accounts, chain_name)?;
    let address = &account.address;

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let chain = parse_chain(chain_name)
        .map_err(|e| CliError::InvalidArgs(format!("unknown chain: {e}")))?;

    let rpc_url = resolve_rpc_url(chain.chain_id, chain.chain_type, None).ok();
    let balances = rt.block_on(ows_pay::fund::get_balances(
        address,
        Some(chain_name),
        rpc_url.as_deref(),
    ))?;

    if balances.is_empty() {
        eprintln!("No tokens found for {address} on {chain_name}");
        return Ok(());
    }

    for token in &balances {
        let amount = token.balance.amount;
        match token.balance.value {
            Some(value) => println!(
                "{:>12.6} {:6} ${:<10.2}  {}",
                amount, token.symbol, value, token.name
            ),
            None => println!("{:>12} {:<10} {}", amount, token.symbol, token.name),
        }
    }

    Ok(())
}
