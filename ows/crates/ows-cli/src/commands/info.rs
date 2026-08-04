use ows_core::Config;

use crate::CliError;

pub fn run() -> Result<(), CliError> {
    let config = Config::default();

    println!("Vault path: {}", config.vault_path.display());
    println!();
    println!("Supported chains:");
    println!(
        "{:<22} {:<12} {:<10}",
        "Chain name", "Namespace", "Coin Type"
    );
    println!(
        "{:<22} {:<12} {:<10}",
        "----------", "---------", "---------"
    );

    for chain in ows_core::universal_wallet_chains() {
        println!(
            "{:<22} {:<12} {:<10}",
            chain.name,
            chain.chain_type.namespace(),
            chain.chain_type.default_coin_type()
        );
    }

    Ok(())
}
