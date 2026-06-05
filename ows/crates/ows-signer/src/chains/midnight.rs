use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;

/// Midnight signer scaffold.
///
/// Address derivation and signing land in following commits. For now every
/// operation reports "not implemented yet" so the registry is total without
/// pulling in any chain-specific dependencies.
pub struct MidnightSigner;

impl MidnightSigner {
    /// SLIP-44 coin type for Midnight.
    const COIN_TYPE: u32 = 2400;
    /// BIP-44 hardened account. OWS uses one account per wallet (single-address
    /// model), so this is fixed; per-address selection is the address index.
    const DEFAULT_ACCOUNT: u32 = 0;
}

impl ChainSigner for MidnightSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Midnight
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        Self::COIN_TYPE
    }

    fn derive_address(&self, _private_key: &[u8]) -> Result<String, SignerError> {
        Err(SignerError::AddressDerivationFailed(
            "Midnight address derivation is not implemented yet".into(),
        ))
    }

    fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight signing is not implemented yet".into(),
        ))
    }

    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight message signing is not implemented yet".into(),
        ))
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Midnight transaction signing is not implemented yet".into(),
        ))
    }

    fn default_derivation_path(&self, index: u32) -> String {
        let (coin, account) = (Self::COIN_TYPE, Self::DEFAULT_ACCOUNT);
        format!("m/44'/{coin}'/{account}'/0/{index}")
    }
}
