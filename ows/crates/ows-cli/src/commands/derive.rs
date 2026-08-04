use ows_core::universal_wallet_chains;
use ows_signer::{signer_for_chain, HdDeriver, Mnemonic};
use zeroize::Zeroize;

use crate::{parse_chain, CliError};

pub fn run(chain_str: Option<&str>, index: u32) -> Result<(), CliError> {
    let mut mnemonic_str = super::read_mnemonic()?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    if let Some(cs) = chain_str {
        // Derive for a single chain
        let chain = parse_chain(cs)?;
        let signer = signer_for_chain(&chain);
        let paths = signer.default_derivation_paths(index);
        let curve = signer.curve();

        let keys = HdDeriver::derive_keys_from_mnemonic_cached(&mnemonic, "", paths, curve)?;
        let signing_key = signer.encode_keys(&keys)?;
        let address = signer.derive_address(signing_key.expose())?;

        println!("{address}");
    } else {
        // Derive for all universal-wallet networks (see `ows_core::universal_wallet_chains`)
        for chain in universal_wallet_chains() {
            let signer = signer_for_chain(&chain);
            let paths = signer.default_derivation_paths(index);
            let curve = signer.curve();

            let keys = HdDeriver::derive_keys_from_mnemonic_cached(&mnemonic, "", paths, curve)?;
            let signing_key = signer.encode_keys(&keys)?;
            let address = signer.derive_address(signing_key.expose())?;

            println!("{} → {}", chain.chain_id, address);
        }
    }

    Ok(())
}
