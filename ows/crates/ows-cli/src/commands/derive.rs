use ows_core::{default_chain_for_type, ALL_CHAIN_TYPES};
use ows_signer::{signer_for_chain, signer_for_chain_type, HdDeriver, Mnemonic};
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
        // Derive for all chains
        for ct in &ALL_CHAIN_TYPES {
            let chain = default_chain_for_type(*ct);
            let signer = signer_for_chain_type(*ct);
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
