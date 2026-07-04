use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
/// Cosmos chain signer (secp256k1, bech32 addresses).
pub struct CosmosSigner {
    /// Human-readable part for bech32 encoding ("cosmos", "osmo", etc.).
    hrp: String,
}

impl CosmosSigner {
    pub fn new(hrp: &str) -> Self {
        CosmosSigner {
            hrp: hrp.to_string(),
        }
    }

    pub fn cosmos_hub() -> Self {
        Self::new("cosmos")
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("key parsing failed".into()))
    }

    /// Hash160: SHA256 then RIPEMD160.
    fn hash160(data: &[u8]) -> Vec<u8> {
        let sha256 = Sha256::digest(data);
        let ripemd = Ripemd160::digest(sha256);
        ripemd.to_vec()
    }
}

impl ChainSigner for CosmosSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Cosmos
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        118
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Compressed public key
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        // Hash160 (same as Bitcoin)
        let hash = Self::hash160(pubkey_bytes);

        // Standard bech32 encoding (no witness version, unlike Bitcoin segwit)
        let hrp = bech32::Hrp::parse(&self.hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
        let address = bech32::encode::<bech32::Bech32>(hrp, &hash)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;

        Ok(address)
    }
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        Ok(compressed.as_bytes().to_vec())
    }


    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Cosmos transaction signing: SHA256 of the serialized SignDoc
        let hash = Sha256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Cosmos typically signs the SHA256 hash of the message
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/118'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        // Use generator point G (private key = 1)
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_known_address() {
        let privkey = test_privkey();
        let signer = CosmosSigner::cosmos_hub();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn test_different_hrps() {
        let privkey = test_privkey();
        let cosmos_signer = CosmosSigner::cosmos_hub();
        let osmo_signer = CosmosSigner::new("osmo");

        let cosmos_addr = cosmos_signer.derive_address(&privkey).unwrap();
        let osmo_addr = osmo_signer.derive_address(&privkey).unwrap();

        assert!(cosmos_addr.starts_with("cosmos1"));
        assert!(osmo_addr.starts_with("osmo1"));

        // Same key, different prefix but same hash
        let (_, cosmos_bytes) = bech32::decode(&cosmos_addr).unwrap();
        let (_, osmo_bytes) = bech32::decode(&osmo_addr).unwrap();
        assert_eq!(cosmos_bytes, osmo_bytes);
    }

    #[test]
    fn test_same_hash_as_bitcoin() {
        // Same private key should produce the same Hash160 on both Bitcoin and Cosmos
        let privkey = test_privkey();

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();
        let hash = CosmosSigner::hash160(pubkey_bytes);

        // Bitcoin uses the same hash160
        let btc_hash = {
            let sha256 = sha2::Sha256::digest(pubkey_bytes);
            let ripemd = ripemd::Ripemd160::digest(sha256);
            ripemd.to_vec()
        };

        assert_eq!(hash, btc_hash);
    }

    #[test]
    fn test_derivation_path() {
        let signer = CosmosSigner::cosmos_hub();
        assert_eq!(signer.default_derivation_path(0), "m/44'/118'/0'/0/0");
        assert_eq!(signer.default_derivation_path(2), "m/44'/118'/0'/0/2");
    }

    #[test]
    fn test_chain_properties() {
        let signer = CosmosSigner::cosmos_hub();
        assert_eq!(signer.chain_type(), ChainType::Cosmos);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 118);
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let signer = CosmosSigner::cosmos_hub();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }
}
