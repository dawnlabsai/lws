use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;

/// Sui chain signer (Ed25519).
///
/// Sui uses BLAKE2b-256 for address derivation and intent-based transaction
/// signing. The signature wire format is `flag(0x00) || sig(64) || pubkey(32)`.
pub struct SuiSigner;

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui transaction intent prefix: [scope=0, version=0, app_id=0].
const TX_INTENT_PREFIX: [u8; 3] = [0x00, 0x00, 0x00];

/// Sui personal message intent prefix: [scope=3, version=0, app_id=0].
const PERSONAL_MSG_INTENT_PREFIX: [u8; 3] = [0x03, 0x00, 0x00];

/// Size of the Sui wire signature: flag(1) + sig(64) + pubkey(32).
pub const WIRE_SIG_LEN: usize = 1 + 64 + 32; // 97

impl SuiSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    fn blake2b_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("valid output size");
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("correct length");
        out
    }

    /// Build the intent message: prepend intent prefix, then BLAKE2b-256 hash.
    fn intent_hash(intent_prefix: &[u8; 3], data: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(3 + data.len());
        buf.extend_from_slice(intent_prefix);
        buf.extend_from_slice(data);
        Self::blake2b_256(&buf)
    }
}

impl ChainSigner for SuiSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Sui
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        784
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // Address = BLAKE2b-256(flag || pubkey)
        let mut buf = Vec::with_capacity(1 + 32);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(verifying_key.as_bytes());
        let hash = Self::blake2b_256(&buf);

        Ok(format!("0x{}", hex::encode(hash)))
    }
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.as_bytes().to_vec())
    }


    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;

        // Personal message signing: intent scope = 3
        // BCS-serialize the message length as a ULEB128 prefix, then the message bytes
        let bcs_msg = bcs_serialize_bytes(message);
        let digest = Self::intent_hash(&PERSONAL_MSG_INTENT_PREFIX, &bcs_msg);

        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.as_bytes().to_vec()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;

        // Transaction signing: intent prefix [0,0,0] + BCS tx → BLAKE2b-256 → Ed25519 sign
        let digest = Self::intent_hash(&TX_INTENT_PREFIX, tx_bytes);
        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.as_bytes().to_vec()),
        })
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        let pubkey = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction(
                "Sui encode_signed_transaction requires public_key in SignOutput".into(),
            )
        })?;
        if pubkey.len() != 32 {
            return Err(SignerError::InvalidTransaction(
                "expected 32-byte public key".into(),
            ));
        }

        // Wire signature: flag(0x00) || sig(64) || pubkey(32) = 97 bytes
        let mut wire_sig = Vec::with_capacity(WIRE_SIG_LEN);
        wire_sig.push(ED25519_FLAG);
        wire_sig.extend_from_slice(&signature.signature);
        wire_sig.extend_from_slice(pubkey);

        // Concatenate: tx_bytes || wire_sig
        // The broadcast function splits at len - 97 to recover both parts.
        let mut result = Vec::with_capacity(tx_bytes.len() + WIRE_SIG_LEN);
        result.extend_from_slice(tx_bytes);
        result.extend_from_slice(&wire_sig);
        Ok(result)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/784'/{}'/0'/0'", index)
    }
}

/// Minimal BCS serialization of a byte vector: ULEB128 length prefix + raw bytes.
fn bcs_serialize_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + data.len());
    let mut len = data.len();
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        if len == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
    buf.extend_from_slice(data);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const TEST_KEY: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn test_privkey() -> Vec<u8> {
        hex::decode(TEST_KEY).unwrap()
    }

    #[test]
    fn test_chain_properties() {
        let signer = SuiSigner;
        assert_eq!(signer.chain_type(), ChainType::Sui);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 784);
    }

    #[test]
    fn test_derivation_path() {
        let signer = SuiSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/784'/0'/0'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/784'/1'/0'/0'");
        assert_eq!(signer.default_derivation_path(5), "m/44'/784'/5'/0'/0'");
    }

    #[test]
    fn test_address_derivation_format() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let address = signer.derive_address(&privkey).unwrap();

        // Sui address: 0x + 64 hex chars (32 bytes)
        assert!(address.starts_with("0x"), "should start with 0x");
        assert_eq!(address.len(), 66, "0x + 64 hex chars = 66");

        // Verify the address is deterministic
        let address2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(address, address2);
    }

    #[test]
    fn test_address_derivation_correctness() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let address = signer.derive_address(&privkey).unwrap();

        // Manually compute: BLAKE2b-256(0x00 || pubkey)
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let pubkey = signing_key.verifying_key();
        let mut buf = vec![0x00u8];
        buf.extend_from_slice(pubkey.as_bytes());
        let expected_hash = SuiSigner::blake2b_256(&buf);
        let expected_addr = format!("0x{}", hex::encode(expected_hash));

        assert_eq!(address, expected_addr);
    }

    #[test]
    fn test_sign_raw_ed25519() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let message = b"test message for sui";

        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_none());

        // Verify the signature
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_sign_transaction_intent_digest() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let bcs_tx = b"fake_bcs_transaction_data";

        let result = signer.sign_transaction(&privkey, bcs_tx).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);

        // The signature should be over BLAKE2b-256([0,0,0] || bcs_tx)
        let digest = SuiSigner::intent_hash(&TX_INTENT_PREFIX, bcs_tx);
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("signature should verify against intent digest");
    }

    #[test]
    fn test_sign_message_personal() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let message = b"hello sui";

        let result = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());

        // Verify: digest = BLAKE2b-256([3,0,0] || bcs_serialize(message))
        let bcs_msg = bcs_serialize_bytes(message);
        let digest = SuiSigner::intent_hash(&PERSONAL_MSG_INTENT_PREFIX, &bcs_msg);
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("personal message signature should verify");
    }

    #[test]
    fn test_wire_signature_format() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let bcs_tx = b"test_tx";

        let output = signer.sign_transaction(&privkey, bcs_tx).unwrap();
        let encoded = signer.encode_signed_transaction(bcs_tx, &output).unwrap();

        // encoded = tx_bytes || wire_sig(97)
        assert_eq!(encoded.len(), bcs_tx.len() + WIRE_SIG_LEN);

        // Split and verify
        let (tx_part, sig_part) = encoded.split_at(encoded.len() - WIRE_SIG_LEN);
        assert_eq!(tx_part, bcs_tx);
        assert_eq!(sig_part.len(), WIRE_SIG_LEN);
        assert_eq!(sig_part[0], ED25519_FLAG);
        assert_eq!(&sig_part[1..65], &output.signature[..]);
        assert_eq!(
            &sig_part[65..],
            output.public_key.as_ref().unwrap().as_slice()
        );
    }

    #[test]
    fn test_encode_roundtrip_split() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let bcs_tx = b"some_bcs_transaction_bytes_here";

        let output = signer.sign_transaction(&privkey, bcs_tx).unwrap();
        let encoded = signer.encode_signed_transaction(bcs_tx, &output).unwrap();

        // Broadcast would split at len - 97
        let split_point = encoded.len() - WIRE_SIG_LEN;
        let recovered_tx = &encoded[..split_point];
        let recovered_sig = &encoded[split_point..];

        assert_eq!(recovered_tx, bcs_tx);
        assert_eq!(recovered_sig.len(), WIRE_SIG_LEN);
        assert_eq!(recovered_sig[0], ED25519_FLAG);
    }

    #[test]
    fn test_full_pipeline() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let bcs_tx = b"full_pipeline_bcs_tx";

        // 1. extract_signable_bytes (default: identity)
        let signable = signer.extract_signable_bytes(bcs_tx).unwrap();
        assert_eq!(signable, bcs_tx);

        // 2. sign_transaction
        let output = signer.sign_transaction(&privkey, signable).unwrap();

        // 3. encode_signed_transaction
        let signed = signer.encode_signed_transaction(bcs_tx, &output).unwrap();

        // 4. Split for broadcast
        let (tx_part, sig_part) = signed.split_at(signed.len() - WIRE_SIG_LEN);

        // Verify tx_part matches original
        assert_eq!(tx_part, bcs_tx);

        // Verify signature is valid over the intent digest
        let digest = SuiSigner::intent_hash(&TX_INTENT_PREFIX, bcs_tx);
        let pubkey_bytes: [u8; 32] = sig_part[65..97].try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig_bytes: [u8; 64] = sig_part[1..65].try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&digest, &sig)
            .expect("full pipeline signature should verify");
    }

    #[test]
    fn test_deterministic_signing() {
        let signer = SuiSigner;
        let privkey = test_privkey();
        let msg = b"deterministic test";

        let s1 = signer.sign_transaction(&privkey, msg).unwrap();
        let s2 = signer.sign_transaction(&privkey, msg).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_invalid_key() {
        let signer = SuiSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
    }

    #[test]
    fn test_bcs_serialize_bytes() {
        // Small message: length fits in one byte
        let data = b"hello";
        let bcs = bcs_serialize_bytes(data);
        assert_eq!(bcs[0], 5); // length
        assert_eq!(&bcs[1..], b"hello");

        // 128-byte message: length requires two bytes (ULEB128)
        let data = vec![0xAA; 128];
        let bcs = bcs_serialize_bytes(&data);
        assert_eq!(bcs[0], 0x80); // 128 & 0x7F = 0, with continuation bit
        assert_eq!(bcs[1], 0x01); // 128 >> 7 = 1
        assert_eq!(&bcs[2..], data.as_slice());

        // Empty message
        let bcs = bcs_serialize_bytes(b"");
        assert_eq!(bcs, vec![0]);
    }
}
