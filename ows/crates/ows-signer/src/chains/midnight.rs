use bech32::{Bech32m, Hrp};
use k256::schnorr::SigningKey;
use sha2::Digest;

use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;

/// Midnight signing support.
///
/// Implements the unshielded (Night) address as specified in the Midnight
/// WalletEngine specification. Signing and the shielded / dust roles land in
/// following commits.
pub struct MidnightSigner;

impl MidnightSigner {
    /// SLIP-44 coin type for Midnight.
    const COIN_TYPE: u32 = 2400;
    /// BIP-44 hardened account. OWS uses one account per wallet (single-address
    /// model), so this is fixed; per-address selection is the address index.
    const DEFAULT_ACCOUNT: u32 = 0;
    /// WalletEngine role for the unshielded (Night) key.
    const ROLE_UNSHIELDED: u32 = 0;

    /// Build a Wallet SDK derivation path for a `role` and address `index`.
    /// The coin type and hardened account live here as the single source of truth.
    fn derivation_path(role: u32, index: u32) -> String {
        let (coin, account) = (Self::COIN_TYPE, Self::DEFAULT_ACCOUNT);
        format!("m/44'/{coin}'/{account}'/{role}/{index}")
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32-byte secp256k1 key, got {} bytes",
                private_key.len()
            )));
        }
        SigningKey::from_bytes(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid secp256k1 key: {e}")))
    }

    fn bech32m_encode(hrp: &str, payload: &[u8]) -> Result<String, SignerError> {
        let hrp = Hrp::parse(hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("invalid hrp: {e}")))?;
        bech32::encode::<Bech32m>(hrp, payload)
            .map_err(|e| SignerError::AddressDerivationFailed(format!("bech32m encode: {e}")))
    }

    fn derive_unshielded_address_with_hrp(
        &self,
        private_key: &[u8],
        hrp: &str,
    ) -> Result<String, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let pk_xonly = sk.verifying_key().to_bytes(); // 32-byte BIP-340 x-only schnorr pubkey
        let hash = sha2::Sha256::digest(pk_xonly);
        Self::bech32m_encode(hrp, &hash)
    }
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

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        self.derive_unshielded_address_with_hrp(private_key, "mn_addr")
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
        Self::derivation_path(Self::ROLE_UNSHIELDED, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unshielded role 0 seed for the abandon-phrase wallet at index 0
    // (path m/44'/2400'/0'/0/0). Hardcoded so tests don't depend on
    // HdDeriver / Mnemonic — matches the EVM / Bitcoin / etc. signer
    // test pattern.
    const UNSHIELDED_KEY_HEX: &str =
        "822fa63c57f6317cd51d12d80f0e64c2bc2164088dec1c71ca34a87a890190aa";

    fn unshielded_key() -> Vec<u8> {
        hex::decode(UNSHIELDED_KEY_HEX).unwrap()
    }

    #[test]
    fn midnight_unshielded_mainnet_address_vector() {
        let signer = MidnightSigner;
        let key = unshielded_key();
        assert_eq!(
            signer.derive_address(&key).unwrap(),
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );
    }
}
