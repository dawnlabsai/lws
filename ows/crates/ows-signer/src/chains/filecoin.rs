use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use k256::ecdsa::SigningKey;
use ows_core::ChainType;

/// Filecoin chain signer (f1 secp256k1 addresses).
pub struct FilecoinSigner;

/// Filecoin uses lowercase base32 (RFC 4648) without padding.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

impl FilecoinSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("key parsing failed".into()))
    }

    /// Encode bytes using Filecoin's lowercase base32 (no padding).
    fn base32_encode(data: &[u8]) -> String {
        let mut result = String::new();
        let mut buffer: u64 = 0;
        let mut bits_in_buffer = 0;

        for &byte in data {
            buffer = (buffer << 8) | byte as u64;
            bits_in_buffer += 8;

            while bits_in_buffer >= 5 {
                bits_in_buffer -= 5;
                let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
                result.push(BASE32_ALPHABET[index] as char);
            }
        }

        if bits_in_buffer > 0 {
            let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }

        result
    }

    /// Compute a Blake2b hash with a variable output length.
    fn blake2b(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Blake2bVar::new(output_len).expect("valid output length");
        hasher.update(data);
        let mut buf = vec![0u8; output_len];
        hasher
            .finalize_variable(&mut buf)
            .expect("valid output length");
        buf
    }

    /// Compute the Filecoin address checksum: blake2b-4(protocol || payload).
    fn checksum(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + payload.len());
        data.push(protocol);
        data.extend_from_slice(payload);
        Self::blake2b(&data, 4)
    }
}

impl ChainSigner for FilecoinSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Filecoin
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        461
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key (65 bytes: 0x04 || x || y)
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();

        // Blake2b-160 hash of the full uncompressed pubkey (65 bytes)
        let payload = Self::blake2b(pubkey_uncompressed, 20);

        // Checksum: blake2b-4(protocol_byte || payload)
        let protocol: u8 = 1; // secp256k1
        let checksum = Self::checksum(protocol, &payload);

        // Address: "f1" + base32(payload + checksum)
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);

        Ok(format!("f1{}", Self::base32_encode(&addr_bytes)))
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
                "expected 32-byte prehash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        // Filecoin signature format: r (32) || s (32) || v (1)
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
        // Filecoin transaction signing: Blake2b-256 hash of CBOR-encoded message
        let hash = Self::blake2b(tx_bytes, 32);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Hash with Blake2b-256 and sign
        let hash = Self::blake2b(message, 32);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/461'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_properties() {
        let signer = FilecoinSigner;
        assert_eq!(signer.chain_type(), ChainType::Filecoin);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 461);
    }

    #[test]
    fn test_derivation_path() {
        let signer = FilecoinSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/461'/0'/0/0");
        assert_eq!(signer.default_derivation_path(5), "m/44'/461'/0'/0/5");
    }

    #[test]
    fn test_address_format() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = FilecoinSigner;
        let address = signer.derive_address(&privkey).unwrap();
        assert!(
            address.starts_with("f1"),
            "Filecoin f1 address should start with f1, got: {address}"
        );
    }

    #[test]
    fn test_deterministic_address() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = FilecoinSigner;
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_and_verify() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = FilecoinSigner;

        let hash = FilecoinSigner::blake2b(b"test message", 32);
        let result = signer.sign(&privkey, &hash).unwrap();

        assert_eq!(result.signature.len(), 65);
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_sign_rejects_non_32_byte_hash() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = FilecoinSigner;
        let result = signer.sign(&privkey, b"too short");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_rejection() {
        let signer = FilecoinSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_base32_encode() {
        // Test basic encoding
        assert_eq!(FilecoinSigner::base32_encode(b""), "");
        assert_eq!(FilecoinSigner::base32_encode(b"f"), "my");
        assert_eq!(FilecoinSigner::base32_encode(b"fo"), "mzxq");
        assert_eq!(FilecoinSigner::base32_encode(b"foo"), "mzxw6");
        assert_eq!(FilecoinSigner::base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(FilecoinSigner::base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(FilecoinSigner::base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_sign_message() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = FilecoinSigner;
        let result = signer.sign_message(&privkey, b"Hello Filecoin").unwrap();
        assert_eq!(result.signature.len(), 65);
    }
}
