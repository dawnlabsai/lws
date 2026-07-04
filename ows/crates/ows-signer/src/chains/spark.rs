use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha2::{Digest, Sha256};

/// Spark chain signer (Bitcoin L2, secp256k1).
///
/// Reuses the Bitcoin BIP-84 derivation path — Spark operates on the same
/// key as Bitcoin since it's a Bitcoin L2 protocol.
pub struct SparkSigner;

impl SparkSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("key parsing failed".into()))
    }
}

impl ChainSigner for SparkSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Spark
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        0 // same as Bitcoin
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        Ok(format!(
            "spark:{}",
            hex::encode(pubkey_compressed.as_bytes())
        ))
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
        let hash = Sha256::digest(Sha256::digest(tx_bytes));
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    /// Uses the same BIP-84 derivation path as Bitcoin.
    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/84'/0'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_derivation_path_matches_bitcoin() {
        let signer = SparkSigner;
        assert_eq!(signer.default_derivation_path(0), "m/84'/0'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/84'/0'/0'/0/3");
    }

    #[test]
    fn test_address_derivation() {
        let privkey = test_privkey();
        let address = SparkSigner.derive_address(&privkey).unwrap();
        assert!(address.starts_with("spark:"));
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let addr1 = SparkSigner.derive_address(&privkey).unwrap();
        let addr2 = SparkSigner.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_chain_properties() {
        assert_eq!(SparkSigner.chain_type(), ChainType::Spark);
        assert_eq!(SparkSigner.curve(), Curve::Secp256k1);
        assert_eq!(SparkSigner.coin_type(), 0);
    }

    #[test]
    fn test_sign_message() {
        let privkey = test_privkey();
        let result = SparkSigner.sign_message(&privkey, b"hello spark").unwrap();
        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_sign_transaction() {
        let privkey = test_privkey();
        let result = SparkSigner
            .sign_transaction(&privkey, b"fake tx data")
            .unwrap();
        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }
}
