use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use cardano_serialization_lib::NetworkInfo;
use ows_core::ChainType;

pub struct CardanoSigner {
    network_id: u8,
}

impl CardanoSigner {
    pub fn mainnet() -> Self {
        Self {
            network_id: NetworkInfo::mainnet().network_id(),
        }
    }

    pub fn preprod() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preprod().network_id(),
        }
    }

    pub fn preview() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preview().network_id(),
        }
    }

    pub fn from_chain_id(chain_id: &str) -> Self {
        match chain_id {
            "cip34:0-1" => Self::preprod(),
            "cip34:0-2" => Self::preview(),
            _ => Self::mainnet(),
        }
    }

    /// CIP-1852 payment key path where index is the account index: `m/1852'/1815'/{index}'/0/0`.
    pub fn payment_derivation_path(index: u32) -> String {
        format!("m/1852'/1815'/{index}'/0/0")
    }

    /// CIP-1852 stake key path where index is the account index: `m/1852'/1815'/{index}'/2/0`.
    pub fn stake_derivation_path(index: u32) -> String {
        format!("m/1852'/1815'/{index}'/2/0")
    }
}

impl ChainSigner for CardanoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Cardano
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519Bip32
    }

    fn coin_type(&self) -> u32 {
        1815
    }

    /// Planned: Shelley **base** address from `payment_xprv || stake_xprv` (see module docs).
    fn derive_address(&self, _private_key: &[u8]) -> Result<String, SignerError> {
        Err(SignerError::AddressDerivationFailed(
            "Cardano Shelley base address encoding not implemented yet; planned `private_key` layout \
             is 192 bytes: payment XPrv (96) || stake XPrv (96) at matching CIP-1852 indices"
                .into(),
        ))
    }

    fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed("not implemented".into()))
    }

    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
        _address: Option<&str>,
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed("not implemented".into()))
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed("not implemented".into()))
    }

    /// Payment leaf (account 0) for generic single-path key resolution (`decrypt_signing_key`, etc.).
    fn default_derivation_path(&self, index: u32) -> String {
        Self::payment_derivation_path(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cip1852_paths() {
        assert_eq!(
            CardanoSigner::payment_derivation_path(0),
            "m/1852'/1815'/0'/0/0"
        );
        assert_eq!(
            CardanoSigner::stake_derivation_path(0),
            "m/1852'/1815'/0'/2/0"
        );
        assert_eq!(
            CardanoSigner::payment_derivation_path(3),
            "m/1852'/1815'/3'/0/0"
        );
    }

    #[test]
    fn test_chain_type_and_curve() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.chain_type(), ChainType::Cardano);
        assert_eq!(s.curve(), Curve::Ed25519Bip32);
        assert_eq!(s.coin_type(), 1815);
    }

    #[test]
    fn test_default_derivation_path_is_payment() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.default_derivation_path(0), "m/1852'/1815'/0'/0/0");
        assert_eq!(s.default_derivation_path(5), "m/1852'/1815'/5'/0/0");
    }
}
