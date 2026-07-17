use bech32::{Bech32m, Hrp};
use k256::schnorr::SigningKey;
use sha2::Digest;

use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;

/// Midnight network selection. Each network uses the same keys but
/// network-specific Bech32m HRPs for unshielded and shielded addresses
/// (the dust HRP is network-agnostic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightNetwork {
    Mainnet,
    Preview,
    Preprod,
}

impl MidnightNetwork {
    fn unshielded_hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "mn_addr",
            Self::Preview => "mn_addr_preview",
            Self::Preprod => "mn_addr_preprod",
        }
    }

}

/// Midnight signing support.
///
/// Implements the unshielded (Night) address as specified in the Midnight
/// WalletEngine specification, plus the multi-role bundle plumbing
/// (`default_derivation_paths`, `encode_keys`, `decode_keys`) that lets the
/// shielded (Zswap) and dust roles ride the single-key signing channel.
pub struct MidnightSigner {
    network: MidnightNetwork,
}

impl MidnightSigner {
    /// SLIP-44 coin type for Midnight.
    const COIN_TYPE: u32 = 2400;
    /// BIP-44 hardened account. OWS uses one account per wallet (single-address
    /// model), so this is fixed; per-address selection is the address index.
    const DEFAULT_ACCOUNT: u32 = 0;
    /// WalletEngine roles under `m/44'/COIN_TYPE'/DEFAULT_ACCOUNT'/role/index`.
    const ROLE_UNSHIELDED: u32 = 0;
    pub fn mainnet() -> Self {
        Self {
            network: MidnightNetwork::Mainnet,
        }
    }

    pub fn preview() -> Self {
        Self {
            network: MidnightNetwork::Preview,
        }
    }

    pub fn preprod() -> Self {
        Self {
            network: MidnightNetwork::Preprod,
        }
    }

    /// Resolve a network from a CAIP-2 chain id. Panics on an unrecognized id:
    /// `signer_for_chain` only builds this from a registered Midnight `Chain`, so
    /// an unknown id here is a registry/programming error, never user input — and
    /// silently defaulting to mainnet would mint wrong-but-valid-looking addresses.
    pub fn from_chain_id(chain_id: &str) -> Self {
        if chain_id.eq_ignore_ascii_case("midnight:mainnet") {
            Self::mainnet()
        } else if chain_id.eq_ignore_ascii_case("midnight:preview") {
            Self::preview()
        } else if chain_id.eq_ignore_ascii_case("midnight:preprod") {
            Self::preprod()
        } else {
            panic!("unsupported Midnight chain id: {chain_id}")
        }
    }

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
        self.derive_unshielded_address_with_hrp(private_key, self.network.unshielded_hrp())
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
        let signer = MidnightSigner::mainnet();
        let key = unshielded_key();
        assert_eq!(
            signer.derive_address(&key).unwrap(),
            "mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"
        );
    }

    #[test]
    fn midnight_preview_unshielded_address_uses_preview_hrp() {
        let addr = MidnightSigner::preview()
            .derive_address(&unshielded_key())
            .unwrap();
        assert!(addr.starts_with("mn_addr_preview1"));
    }

    #[test]
    fn midnight_from_chain_id_maps_networks() {
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:mainnet").network,
            MidnightNetwork::Mainnet
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preview").network,
            MidnightNetwork::Preview
        );
        assert_eq!(
            MidnightSigner::from_chain_id("midnight:preprod").network,
            MidnightNetwork::Preprod
        );
    }

    #[test]
    #[should_panic(expected = "unsupported Midnight chain id")]
    fn midnight_from_chain_id_panics_on_unknown() {
        // No silent mainnet fallback: an unregistered id is a programming error.
        let _ = MidnightSigner::from_chain_id("midnight:bogus");
    }

}
