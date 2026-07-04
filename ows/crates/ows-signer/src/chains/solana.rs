use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;

/// Decode a Solana compact-u16 (short_vec length prefix).
/// Returns `(value, bytes_consumed)`.
fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), SignerError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 3 {
            return Err(SignerError::InvalidTransaction(
                "compact-u16 encoding exceeds 3 bytes".into(),
            ));
        }
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(SignerError::InvalidTransaction(
        "truncated compact-u16".into(),
    ))
}

/// Solana chain signer (Ed25519).
pub struct SolanaSigner;

impl SolanaSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for SolanaSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Solana
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        501
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(bs58::encode(verifying_key.as_bytes()).into_string())
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

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Ed25519 signs raw message bytes directly (no prehashing).
        // Callers passing a full serialized Solana transaction (with signature
        // slots) must call extract_signable_bytes() first.
        self.sign(private_key, tx_bytes)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        // Solana serialized transaction format (envelope):
        // [compact-u16: num_signatures] [64-byte signatures...] [message...]
        // Return only the message portion.
        //
        // Input MUST be a full transaction envelope. Raw message bytes
        // are not accepted — callers should always provide the serialized
        // transaction as produced by Solana SDKs.
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        let message_start = header_len + num_sigs * 64;
        if tx_bytes.len() <= message_start {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }
        Ok(&tx_bytes[message_start..])
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Solana serialized transaction format:
        // [compact-u16: num_signatures] [64-byte signatures...] [message...]
        // Replace the first 64-byte zero-signature with the real signature.
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }

        let (num_sigs, header_len) = decode_compact_u16(tx_bytes)?;
        if num_sigs == 0 {
            return Err(SignerError::InvalidTransaction(
                "transaction has no signature slots".into(),
            ));
        }
        let sigs_end = header_len + num_sigs * 64;
        if tx_bytes.len() < sigs_end {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }

        let mut signed = tx_bytes.to_vec();
        // Replace first signature slot (starts right after the compact-u16 header)
        let first_sig_start = header_len;
        let first_sig_end = first_sig_start + 64;
        signed[first_sig_start..first_sig_end].copy_from_slice(&signature.signature);
        Ok(signed)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Solana doesn't use a special prefix for message signing
        self.sign(private_key, message)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/501'/{}'/0'", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// Encode a u16 as Solana compact-u16 (short_vec).
    fn encode_compact_u16(mut value: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value > 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    /// Build a synthetic Solana serialized transaction with the given number
    /// of signature slots and a structurally valid message containing the
    /// given payload as instruction data.
    fn build_tx(num_sigs: u16, payload: &[u8]) -> Vec<u8> {
        let mut tx = encode_compact_u16(num_sigs);
        // Fill signature slots with zeros (placeholders)
        tx.extend(std::iter::repeat_n(0u8, num_sigs as usize * 64));
        // Structurally valid Solana message header
        let ns = if num_sigs == 0 { 1 } else { num_sigs as u8 };
        tx.extend_from_slice(&[ns, 0x00, 0x01]); // required_sigs, ro_signed, ro_unsigned
        tx.push(0x02); // num_account_keys (compact-u16 = 2)
        tx.extend_from_slice(&[0xAA; 32]); // account key 1
        tx.extend_from_slice(&[0x00; 32]); // account key 2 (system program)
        tx.extend_from_slice(&[0xCC; 32]); // recent blockhash
                                           // Instruction referencing the payload
        tx.push(0x01); // num_instructions
        tx.push(0x01); // program_id_index
        tx.push(0x01); // num_accounts
        tx.push(0x00); // account index 0
        tx.push(payload.len() as u8); // data_length
        tx.extend_from_slice(payload);
        tx
    }

    /// Return the expected message bytes for a build_tx output.
    fn expected_msg(num_sigs: u16, payload: &[u8]) -> Vec<u8> {
        let ns = if num_sigs == 0 { 1 } else { num_sigs as u8 };
        let mut msg = vec![ns, 0x00, 0x01, 0x02];
        msg.extend_from_slice(&[0xAA; 32]);
        msg.extend_from_slice(&[0x00; 32]);
        msg.extend_from_slice(&[0xCC; 32]);
        msg.push(0x01);
        msg.push(0x01);
        msg.push(0x01);
        msg.push(0x00);
        msg.push(payload.len() as u8);
        msg.extend_from_slice(payload);
        msg
    }

    #[test]
    fn test_ed25519_rfc8032_vector1() {
        // RFC 8032 Test Vector 1
        let secret =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let expected_pubkey =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();

        let signing_key = SigningKey::from_bytes(&secret.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        assert_eq!(verifying_key.as_bytes(), expected_pubkey.as_slice());
    }

    #[test]
    fn test_base58_address() {
        let signer = SolanaSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let address = signer.derive_address(&privkey).unwrap();
        // Base58 encoded ed25519 public key
        assert!(!address.is_empty());
        // Verify it decodes back to 32 bytes
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;

        let message = b"test message for solana";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Verify
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"hello";

        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_no_recovery_id() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let result = signer.sign(&privkey, b"msg").unwrap();
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn test_derivation_path() {
        let signer = SolanaSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/501'/0'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/501'/1'/0'");
    }

    #[test]
    fn test_chain_properties() {
        let signer = SolanaSigner;
        assert_eq!(signer.chain_type(), ChainType::Solana);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 501);
    }

    #[test]
    fn test_invalid_key() {
        let signer = SolanaSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_extract_signable_bytes() {
        let signer = SolanaSigner;
        let tx = build_tx(1, b"payload");
        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected_msg(1, b"payload").as_slice());
    }

    #[test]
    fn test_extract_signable_bytes_errors() {
        let signer = SolanaSigner;

        // Empty input
        assert!(signer.extract_signable_bytes(&[]).is_err());
    }

    #[test]
    fn test_extract_signable_bytes_too_short_errors() {
        let signer = SolanaSigner;

        // Claims 1 sig slot but too short
        let short = vec![0x01, 0x00];
        assert!(signer.extract_signable_bytes(&short).is_err());
    }

    #[test]
    fn test_sign_transaction_is_passthrough() {
        // sign_transaction signs whatever bytes it receives (caller strips headers)
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"fake_message_payload";

        let via_sign = signer.sign(&privkey, message).unwrap();
        let via_sign_tx = signer.sign_transaction(&privkey, message).unwrap();
        assert_eq!(via_sign.signature, via_sign_tx.signature);
    }

    #[test]
    fn test_full_sign_and_encode_pipeline() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let tx_bytes = build_tx(1, b"pipeline");
        let expected = expected_msg(1, b"pipeline");

        // Pipeline: extract → sign → encode (mirrors sign_and_send in ops.rs)
        let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
        assert_eq!(signable, expected.as_slice());

        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let signed = signer
            .encode_signed_transaction(&tx_bytes, &output)
            .unwrap();

        // The signature should be spliced in at bytes 1..65
        assert_eq!(&signed[1..65], &output.signature[..]);
        // The rest of the tx should be unchanged
        assert_eq!(&signed[65..], &tx_bytes[65..]);
        assert_eq!(signed.len(), tx_bytes.len());

        // Verify the signature is over the message portion
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(&expected, &sig)
            .expect("signature should verify against the message portion only");
    }

    #[test]
    fn test_sign_message_same_as_sign() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"hello solana";
        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    // ================================================================
    // Issue 2 regression tests: signing full tx vs message-only
    // ================================================================

    #[test]
    fn test_signing_full_tx_without_extraction_produces_wrong_signature() {
        // Demonstrates the footgun: if you sign the full serialized tx
        // (including sig-slot header) the signature won't verify against
        // just the message portion.
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;

        let message = b"fake_message_payload";
        let mut full_tx = vec![0x01]; // 1 sig slot
        full_tx.extend_from_slice(&[0u8; 64]); // placeholder
        full_tx.extend_from_slice(message);

        // Sign the FULL tx bytes (wrong — includes header + sig slot)
        let output = signer.sign_transaction(&privkey, &full_tx).unwrap();

        // The signature should NOT verify against just the message portion
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        assert!(
            verifying_key.verify(message, &sig).is_err(),
            "signing full tx bytes should produce a signature that does NOT \
             verify against the message portion alone"
        );
    }

    #[test]
    fn test_extract_then_sign_produces_valid_signature() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let full_tx = build_tx(1, b"correct pipeline");
        let expected = expected_msg(1, b"correct pipeline");

        let signable = signer.extract_signable_bytes(&full_tx).unwrap();
        let output = signer.sign_transaction(&privkey, signable).unwrap();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(&expected, &sig)
            .expect("extract → sign should produce a valid signature over the message");
    }

    #[test]
    fn test_extract_signable_bytes_with_multiple_sig_slots() {
        let signer = SolanaSigner;
        let tx = build_tx(2, b"multi");
        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected_msg(2, b"multi").as_slice());
    }

    #[test]
    fn test_extract_signable_bytes_with_three_sig_slots() {
        let signer = SolanaSigner;
        let tx = build_tx(3, b"three");
        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected_msg(3, b"three").as_slice());
    }

    #[test]
    fn test_encode_signed_transaction_preserves_other_sig_slots() {
        let signer = SolanaSigner;

        // 2 signature slots — second one has data (e.g. from another signer)
        let mut tx = vec![0x02]; // 2 sig slots
        tx.extend_from_slice(&[0u8; 64]); // first sig slot (empty)
        tx.extend_from_slice(&[0xAA; 64]); // second sig slot (pre-filled)
        tx.extend_from_slice(b"multi_sig_message");

        let fake_sig = SignOutput {
            signature: vec![0xBB; 64],
            recovery_id: None,
            public_key: None,
        };

        let signed = signer.encode_signed_transaction(&tx, &fake_sig).unwrap();

        // First sig slot should be replaced
        assert_eq!(&signed[1..65], &[0xBB; 64]);
        // Second sig slot should be preserved
        assert_eq!(&signed[65..129], &[0xAA; 64]);
        // Message should be preserved
        assert_eq!(&signed[129..], b"multi_sig_message");
    }

    #[test]
    fn test_full_pipeline_with_multiple_sig_slots() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let tx = build_tx(2, b"multi_slot");
        let expected = expected_msg(2, b"multi_slot");

        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected.as_slice());

        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let signed = signer.encode_signed_transaction(&tx, &output).unwrap();

        // Verify structure
        assert_eq!(signed[0], 0x02); // num_sigs preserved
        assert_eq!(&signed[1..65], &output.signature[..]); // our sig

        // Verify signature correctness
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(&expected, &sig)
            .expect("signature should verify against the message portion");
    }

    // ================================================================
    // compact-u16 decoder unit tests
    // ================================================================

    #[test]
    fn test_compact_u16_encode_decode_roundtrip() {
        let test_values: &[u16] = &[0, 1, 2, 3, 127, 128, 129, 255, 256, 16383, 16384, 65535];
        for &val in test_values {
            let encoded = encode_compact_u16(val);
            let (decoded, len) = decode_compact_u16(&encoded).unwrap();
            assert_eq!(decoded, val as usize, "roundtrip failed for {val}");
            assert_eq!(len, encoded.len(), "length mismatch for {val}");
        }
    }

    #[test]
    fn test_compact_u16_encoding_lengths() {
        // 0-127 → 1 byte
        assert_eq!(encode_compact_u16(0).len(), 1);
        assert_eq!(encode_compact_u16(1).len(), 1);
        assert_eq!(encode_compact_u16(127).len(), 1);

        // 128-16383 → 2 bytes
        assert_eq!(encode_compact_u16(128).len(), 2);
        assert_eq!(encode_compact_u16(255).len(), 2);
        assert_eq!(encode_compact_u16(16383).len(), 2);

        // 16384-65535 → 3 bytes
        assert_eq!(encode_compact_u16(16384).len(), 3);
        assert_eq!(encode_compact_u16(65535).len(), 3);
    }

    #[test]
    fn test_compact_u16_known_encodings() {
        // Value 1: single byte 0x01
        assert_eq!(encode_compact_u16(1), vec![0x01]);
        // Value 127: single byte 0x7F
        assert_eq!(encode_compact_u16(127), vec![0x7F]);
        // Value 128: [0x80, 0x01] (continuation bit set on first byte)
        assert_eq!(encode_compact_u16(128), vec![0x80, 0x01]);
        // Value 255: [0xFF, 0x01]
        assert_eq!(encode_compact_u16(255), vec![0xFF, 0x01]);
        // Value 256: [0x80, 0x02]
        assert_eq!(encode_compact_u16(256), vec![0x80, 0x02]);
    }

    #[test]
    fn test_compact_u16_decode_empty_input() {
        assert!(decode_compact_u16(&[]).is_err());
    }

    #[test]
    fn test_compact_u16_decode_truncated() {
        // First byte has continuation bit set but no second byte
        assert!(decode_compact_u16(&[0x80]).is_err());
        // Two bytes, both with continuation bits, but no third byte
        assert!(decode_compact_u16(&[0x80, 0x80]).is_err());
    }

    // ================================================================
    // compact-u16 multi-byte signature count: extraction edge cases
    // ================================================================

    #[test]
    fn test_extract_signable_128_sig_slots() {
        // 128 sigs → compact-u16 is [0x80, 0x01] (2-byte header)
        let signer = SolanaSigner;
        let message = b"MSG";
        let tx = build_tx(128, message);

        let header_len = encode_compact_u16(128).len(); // 2
        assert_eq!(header_len, 2);

        let signable = signer.extract_signable_bytes(&tx).unwrap();
        let expected = expected_msg(128, b"MSG");
        assert_eq!(
            signable,
            expected.as_slice(),
            "with 128 sig slots (2-byte compact-u16), message extraction must \
             account for the extra header byte"
        );
    }

    #[test]
    fn test_extract_signable_127_vs_128_boundary() {
        let signer = SolanaSigner;

        let tx_127 = build_tx(127, b"BND");
        assert_eq!(
            signer.extract_signable_bytes(&tx_127).unwrap(),
            expected_msg(127, b"BND").as_slice(),
            "127 sigs (1-byte header) should extract correctly"
        );

        let tx_128 = build_tx(128, b"BND");
        assert_eq!(
            signer.extract_signable_bytes(&tx_128).unwrap(),
            expected_msg(128, b"BND").as_slice(),
            "128 sigs (2-byte header) should extract correctly"
        );
    }

    #[test]
    fn test_extract_signable_255_sig_slots() {
        let signer = SolanaSigner;
        let tx = build_tx(255, b"255");
        assert_eq!(
            signer.extract_signable_bytes(&tx).unwrap(),
            expected_msg(255, b"255").as_slice()
        );
    }

    #[test]
    fn test_extract_signable_256_sig_slots() {
        let signer = SolanaSigner;
        let tx = build_tx(256, b"256");
        assert_eq!(
            signer.extract_signable_bytes(&tx).unwrap(),
            expected_msg(256, b"256").as_slice()
        );
    }

    #[test]
    fn test_encode_signed_tx_128_sig_slots() {
        let signer = SolanaSigner;
        let tx = build_tx(128, b"ENC");

        let fake_sig = SignOutput {
            signature: vec![0xAA; 64],
            recovery_id: None,
            public_key: None,
        };

        let signed = signer.encode_signed_transaction(&tx, &fake_sig).unwrap();
        let header_len = encode_compact_u16(128).len(); // 2

        assert_eq!(
            &signed[header_len..header_len + 64],
            &[0xAA; 64],
            "first sig slot must start after the 2-byte compact-u16 header"
        );
        assert_eq!(signed.len(), tx.len());
    }

    #[test]
    fn test_full_pipeline_128_sig_slots() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let tx = build_tx(128, b"p128");
        let expected = expected_msg(128, b"p128");

        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected.as_slice());

        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let _signed = signer.encode_signed_transaction(&tx, &output).unwrap();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(&expected, &sig)
            .expect("signature should verify against the message portion");
    }

    #[test]
    fn test_encode_signed_tx_0_sig_slots_errors() {
        let signer = SolanaSigner;
        let tx = build_tx(0, b"NOSIGS");
        let fake_sig = SignOutput {
            signature: vec![0xAA; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(&tx, &fake_sig).is_err());
    }

    #[test]
    fn test_extract_signable_0_sig_slots() {
        // 0 sigs → message_start = header_len (just the compact-u16 byte)
        let signer = SolanaSigner;
        let tx = build_tx(0, b"ZEROSIGS");
        let signable = signer.extract_signable_bytes(&tx).unwrap();
        assert_eq!(signable, expected_msg(0, b"ZEROSIGS").as_slice());
    }

    #[test]
    fn test_extract_signable_truncated_tx_errors() {
        let signer = SolanaSigner;
        // 128 sigs claimed but only a few bytes of data
        let mut tx = encode_compact_u16(128);
        tx.extend_from_slice(&[0u8; 10]);
        assert!(signer.extract_signable_bytes(&tx).is_err());
    }

    #[test]
    fn test_extract_presigned_envelope() {
        // A pre-signed envelope (first sig slot non-zero) should still
        // extract correctly — only the compact-u16 header matters.
        let signer = SolanaSigner;
        let msg = expected_msg(1, b"presigned");
        let mut envelope = vec![0x01]; // 1 sig slot
        envelope.extend_from_slice(&[0xDD; 64]); // non-zero sig
        envelope.extend_from_slice(&msg);

        let signable = signer.extract_signable_bytes(&envelope).unwrap();
        assert_eq!(signable, msg.as_slice());
    }

    #[test]
    fn test_build_tx_helper_produces_correct_layout() {
        // Sanity-check the test helper itself
        for num_sigs in [1u16, 2, 127, 128, 255, 256] {
            let payload = b"VFY";
            let tx = build_tx(num_sigs, payload);
            let header = encode_compact_u16(num_sigs);
            let msg = expected_msg(num_sigs, payload);
            let expected_len = header.len() + num_sigs as usize * 64 + msg.len();
            assert_eq!(
                tx.len(),
                expected_len,
                "build_tx({num_sigs}) should produce correct total length"
            );
            // Header bytes should match
            assert_eq!(&tx[..header.len()], &header[..]);
            // Message at the end should match expected_msg
            assert_eq!(&tx[tx.len() - msg.len()..], msg.as_slice());
        }
    }
}
