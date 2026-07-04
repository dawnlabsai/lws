use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

/// Tron chain signer (secp256k1, base58check addresses with 0x41 prefix).
pub struct TronSigner;

impl TronSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("key parsing failed".into()))
    }

    /// Derive the 20-byte address hash (same as EVM: keccak256 of uncompressed pubkey, last 20 bytes).
    fn address_bytes(private_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();

        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);
        Ok(hash[12..].to_vec())
    }
}

impl ChainSigner for TronSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Tron
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        195
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let addr_bytes = Self::address_bytes(private_key)?;

        // Prepend 0x41 (Tron mainnet prefix)
        let mut prefixed = vec![0x41u8];
        prefixed.extend_from_slice(&addr_bytes);

        // Base58Check encode
        let address = bs58::encode(&prefixed).with_check().into_string();

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

        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
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
        // Tron transaction signing: SHA256 of the raw_data bytes
        let hash = Sha256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Tron uses the same prefix as Ethereum for personal messages
        let prefix = format!("\x19TRON Signed Message:\n{}", message.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(message);

        let hash = Keccak256::digest(&prefixed);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/195'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap()
    }

    #[test]
    fn test_starts_with_t() {
        let signer = TronSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            address.starts_with('T'),
            "Tron address should start with T, got: {}",
            address
        );
    }

    #[test]
    fn test_address_length() {
        let signer = TronSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(
            address.len(),
            34,
            "Tron address should be 34 chars, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_same_20_byte_hash_as_evm() {
        let privkey = test_privkey();

        // Get Tron's 20-byte hash
        let tron_hash = TronSigner::address_bytes(&privkey).unwrap();

        // Get EVM's 20-byte hash (same algorithm)
        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);
        let evm_hash = &hash[12..];

        assert_eq!(tron_hash, evm_hash);
    }

    #[test]
    fn test_base58check_roundtrip() {
        let signer = TronSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();

        // Decode and verify the base58check
        let decoded = bs58::decode(&address)
            .with_check(None)
            .into_vec()
            .expect("should be valid base58check");

        assert_eq!(decoded[0], 0x41, "first byte should be 0x41");
        assert_eq!(
            decoded.len(),
            21,
            "decoded should be 21 bytes (1 prefix + 20 hash)"
        );
    }

    #[test]
    fn test_derivation_path() {
        let signer = TronSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/195'/0'/0/0");
        assert_eq!(signer.default_derivation_path(1), "m/44'/195'/0'/0/1");
    }

    #[test]
    fn test_chain_properties() {
        let signer = TronSigner;
        assert_eq!(signer.chain_type(), ChainType::Tron);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 195);
    }
}
