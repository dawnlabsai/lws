//! Nano (XNO) chain signer (Ed25519 with blake2b-512).
//!
//! Nano uses Ed25519 but replaces SHA-512 with blake2b-512 for key expansion
//! and signing. This requires the `hazmat` API from `ed25519-dalek`.
//!
//! Address format: `nano_` + 52 base32 chars (pubkey) + 8 base32 chars (checksum).
//! State block hash: blake2b-256 over 176-byte canonical block representation.

use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use blake2::digest::{consts::U32, consts::U5, Digest};
use blake2::{Blake2b, Blake2b512};
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::VerifyingKey;
use ows_core::ChainType;

// ─────────────────────────────────────────────────────────────────────────────
// Nano base32 address encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Nano's custom base32 alphabet (32 chars, no 0, 2, l, v).
const NANO_ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

/// Reverse lookup table: ASCII byte -> base32 value (255 = invalid).
const DECODE_TABLE: [u8; 128] = {
    let mut table = [255u8; 128];
    let mut i = 0u8;
    while i < 32 {
        table[NANO_ALPHABET[i as usize] as usize] = i;
        i += 1;
    }
    table
};

/// Encode a 32-byte public key as a Nano address (`nano_...`).
///
/// Format: `nano_` + 52 base32 chars (260-bit padded pubkey) + 8 base32 chars (checksum).
pub fn nano_address(pubkey: &[u8; 32]) -> String {
    // Base32 encodes 5 bits per char. 52 chars x 5 = 260 bits.
    // We pad the 256-bit pubkey with 4 leading zero bits (260 - 256 = 4).
    let encoded_key = encode_nano_base32(pubkey, 52);

    // Checksum: blake2b-40 (5-byte digest) of the public key, bytes reversed.
    let checksum = nano_checksum(pubkey);
    let encoded_checksum = encode_nano_base32(&checksum, 8);

    format!("nano_{}{}", encoded_key, encoded_checksum)
}

/// Decode a Nano address back to a 32-byte public key.
///
/// Returns `None` if the address is malformed or the checksum doesn't match.
pub fn nano_pubkey_from_address(address: &str) -> Option<[u8; 32]> {
    let body = address.strip_prefix("nano_")?;
    if body.len() != 60 {
        return None;
    }

    let key_part = &body[..52];
    let checksum_part = &body[52..];

    // Decode key (52 base32 chars -> 260 bits -> 32 bytes with 4-bit padding)
    let pubkey = decode_nano_base32(key_part, 32)?;

    // Verify checksum
    let expected_checksum = nano_checksum(&pubkey);
    let expected_encoded = encode_nano_base32(&expected_checksum, 8);
    if checksum_part != expected_encoded {
        return None;
    }

    Some(pubkey)
}

/// Compute the Nano checksum: blake2b-40 of pubkey, bytes reversed.
fn nano_checksum(pubkey: &[u8; 32]) -> [u8; 5] {
    let mut hasher = Blake2b::<U5>::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut checksum = [0u8; 5];
    checksum.copy_from_slice(&hash);
    checksum.reverse();
    checksum
}

/// Encode arbitrary bytes as Nano base32 with exactly `char_count` output chars.
///
/// Bits are taken MSB-first, padded with leading zeros on the left to fill
/// `char_count * 5` bits.
fn encode_nano_base32(data: &[u8], char_count: usize) -> String {
    let total_bits = char_count * 5;
    let data_bits = data.len() * 8;
    let padding_bits = total_bits - data_bits;

    let mut result = String::with_capacity(char_count);

    for i in 0..char_count {
        let bit_offset = i * 5;
        let mut value = 0u8;

        for b in 0..5 {
            let global_bit = bit_offset + b;
            if global_bit < padding_bits {
                // Zero padding bit
                continue;
            }
            let data_bit = global_bit - padding_bits;
            let byte_idx = data_bit / 8;
            let bit_idx = 7 - (data_bit % 8);
            if (data[byte_idx] >> bit_idx) & 1 == 1 {
                value |= 1 << (4 - b);
            }
        }

        result.push(NANO_ALPHABET[value as usize] as char);
    }

    result
}

/// Decode Nano base32 string to bytes. Returns `None` on invalid characters.
///
/// Reverses the encoding: `char_count * 5` bits -> `byte_count` bytes,
/// stripping leading padding bits.
fn decode_nano_base32(s: &str, byte_count: usize) -> Option<[u8; 32]> {
    if byte_count != 32 {
        return None; // only support 32-byte decode for now
    }

    let char_count = s.len();
    let total_bits = char_count * 5;
    let data_bits = byte_count * 8;
    let padding_bits = total_bits - data_bits;

    let mut output = [0u8; 32];

    for (i, ch) in s.bytes().enumerate() {
        if ch >= 128 {
            return None;
        }
        let value = DECODE_TABLE[ch as usize];
        if value == 255 {
            return None;
        }

        for b in 0..5 {
            let global_bit = i * 5 + b;
            if global_bit < padding_bits {
                continue;
            }
            let data_bit = global_bit - padding_bits;
            let byte_idx = data_bit / 8;
            let bit_idx = 7 - (data_bit % 8);
            if (value >> (4 - b)) & 1 == 1 {
                output[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    Some(output)
}

// ─────────────────────────────────────────────────────────────────────────────
// Nano state block hashing
// ─────────────────────────────────────────────────────────────────────────────

/// The state block preamble: 31 zero bytes followed by 0x06.
const STATE_BLOCK_PREAMBLE: [u8; 32] = {
    let mut p = [0u8; 32];
    p[31] = 0x06;
    p
};

/// Hash a Nano state block, returning the 32-byte blake2b-256 digest.
///
/// `tx_bytes` must be exactly 176 bytes:
///   preamble (32) + account (32) + previous (32) + representative (32)
///   + balance (16, big-endian u128) + link (32)
pub fn hash_state_block(tx_bytes: &[u8]) -> Result<[u8; 32], SignerError> {
    if tx_bytes.len() != 176 {
        return Err(SignerError::InvalidTransaction(format!(
            "state block must be 176 bytes, got {}",
            tx_bytes.len()
        )));
    }

    // Verify preamble
    if tx_bytes[..32] != STATE_BLOCK_PREAMBLE {
        return Err(SignerError::InvalidTransaction(
            "invalid state block preamble (first 32 bytes must be 0x00...06)".into(),
        ));
    }

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(tx_bytes);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

/// Build the 176-byte state block payload from individual fields.
pub fn build_state_block(
    account: &[u8; 32],
    previous: &[u8; 32],
    representative: &[u8; 32],
    balance: u128,
    link: &[u8; 32],
) -> [u8; 176] {
    let mut block = [0u8; 176];
    block[..32].copy_from_slice(&STATE_BLOCK_PREAMBLE);
    block[32..64].copy_from_slice(account);
    block[64..96].copy_from_slice(previous);
    block[96..128].copy_from_slice(representative);
    block[128..144].copy_from_slice(&balance.to_be_bytes());
    block[144..176].copy_from_slice(link);
    block
}

// ─────────────────────────────────────────────────────────────────────────────
// NanoSigner
// ─────────────────────────────────────────────────────────────────────────────

/// Nano chain signer (Ed25519 with blake2b-512).
pub struct NanoSigner;

impl NanoSigner {
    /// Expand a 32-byte seed into an [`ExpandedSecretKey`] using blake2b-512.
    ///
    /// Standard Ed25519 uses SHA-512 here; Nano uses blake2b-512.
    fn expand_secret_key(private_key: &[u8]) -> Result<ExpandedSecretKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;

        let mut hasher = Blake2b512::new();
        hasher.update(key_bytes);
        let hash: [u8; 64] = hasher.finalize().into();

        Ok(ExpandedSecretKey::from_bytes(&hash))
    }

    /// Derive the [`VerifyingKey`] (public key) from a private key via blake2b-512 expansion.
    fn verifying_key(private_key: &[u8]) -> Result<VerifyingKey, SignerError> {
        let esk = Self::expand_secret_key(private_key)?;
        Ok(VerifyingKey::from(&esk))
    }
}

impl ChainSigner for NanoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Nano
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        165
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let vk = Self::verifying_key(private_key)?;
        let pubkey_bytes: [u8; 32] = vk.to_bytes();
        Ok(nano_address(&pubkey_bytes))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let esk = Self::expand_secret_key(private_key)?;
        let vk = VerifyingKey::from(&esk);
        let signature = raw_sign::<Blake2b512>(&esk, message, &vk);

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(vk.to_bytes().to_vec()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Nano state blocks: blake2b-256 hash the 176-byte block, then sign the hash.
        let block_hash = hash_state_block(tx_bytes)?;
        self.sign(private_key, &block_hash)
    }

    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
        _address: Option<&str>,
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "Nano off-chain message signing is not supported: no canonical standard exists. \
             Define an ecosystem convention before enabling this."
                .into(),
        ))
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Nano wire format: 176-byte state block + 64-byte signature = 240 bytes.
        // Work bytes (8 bytes) are added separately by the RPC/broadcast layer.
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.len() != 176 {
            return Err(SignerError::InvalidTransaction(format!(
                "expected 176-byte state block, got {}",
                tx_bytes.len()
            )));
        }

        let mut signed = Vec::with_capacity(176 + 64);
        signed.extend_from_slice(tx_bytes);
        signed.extend_from_slice(&signature.signature);
        Ok(signed)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/165'/{}'", index)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Curve;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::hazmat::raw_verify;

    // 24-word test vector
    const MNEMONIC_24: &str = "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur";
    const PASSPHRASE_24: &str = "some password";

    // 12-word test vector
    const MNEMONIC_12: &str =
        "company public remove bread fashion tortoise ahead shrimp onion prefer waste blade";

    /// Helper: derive a Nano private key from a mnemonic phrase and path.
    fn derive_key(phrase: &str, passphrase: &str, path: &str) -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(phrase).expect("valid mnemonic");
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, passphrase, path, Curve::Ed25519)
            .expect("derivation succeeded");
        key.expose().to_vec()
    }

    // ─── chain properties ────────────────────────────────────────────────────

    #[test]
    fn test_chain_properties() {
        let signer = NanoSigner;
        assert_eq!(signer.chain_type(), ChainType::Nano);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 165);
    }

    #[test]
    fn test_derivation_path() {
        let signer = NanoSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/165'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/165'/1'");
        assert_eq!(signer.default_derivation_path(99), "m/44'/165'/99'");
    }

    // ─── known address vectors ────────────────────────────────────────────────

    #[test]
    fn test_derive_address_24word_index_0() {
        let key = derive_key(MNEMONIC_24, PASSPHRASE_24, "m/44'/165'/0'");
        let signer = NanoSigner;
        let address = signer.derive_address(&key).unwrap();
        assert_eq!(
            address,
            "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d"
        );
    }

    #[test]
    fn test_pubkey_hex_24word_index_0() {
        let key = derive_key(MNEMONIC_24, PASSPHRASE_24, "m/44'/165'/0'");
        let vk = NanoSigner::verifying_key(&key).unwrap();
        let pubkey_hex = hex::encode(vk.to_bytes());
        assert_eq!(
            pubkey_hex,
            "5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4"
        );
    }

    #[test]
    fn test_derive_address_12word_index_0() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;
        let address = signer.derive_address(&key).unwrap();
        assert_eq!(
            address,
            "nano_16tfkg33dxndscjt3sdnzqjkdz4d5cxfmhbxf87zxycp8gtnzytqmcosi3zr"
        );
    }

    // ─── address encode/decode roundtrip ─────────────────────────────────────

    #[test]
    fn test_address_encode_decode_roundtrip() {
        let pubkey_hex = "5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4";
        let pubkey: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();

        let address = nano_address(&pubkey);
        assert_eq!(
            address,
            "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d"
        );

        let decoded = nano_pubkey_from_address(&address).expect("should decode");
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn test_address_invalid_checksum() {
        // Valid address with last char flipped
        let bad = "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1e";
        assert!(nano_pubkey_from_address(bad).is_none());
    }

    #[test]
    fn test_address_wrong_prefix() {
        let bad = "nanox_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d";
        assert!(nano_pubkey_from_address(bad).is_none());
    }

    #[test]
    fn test_address_wrong_length() {
        assert!(nano_pubkey_from_address("nano_abc").is_none());
    }

    #[test]
    fn test_address_invalid_chars() {
        // 'l' and 'v' are not in the Nano alphabet
        let bad = "nano_llllllllllllllllllllllllllllllllllllllllllllllllllllllllllll";
        assert!(nano_pubkey_from_address(bad).is_none());
    }

    // ─── sign / verify roundtrip ──────────────────────────────────────────────

    #[test]
    fn test_sign_verify_roundtrip() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;

        let message = b"test message for nano";
        let result = signer.sign(&key, message).unwrap();

        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());

        // Verify using blake2b-512 (Nano's Ed25519 variant)
        let vk = NanoSigner::verifying_key(&key).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        raw_verify::<Blake2b512>(&vk, message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;
        let message = b"hello nano";

        let sig1 = signer.sign(&key, message).unwrap();
        let sig2 = signer.sign(&key, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_message_unsupported() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;
        let message = b"hello nano";
        let result = signer.sign_message(&key, message, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Nano off-chain message signing is not supported"));
    }

    #[test]
    fn test_public_key_in_sign_output() {
        let key = derive_key(MNEMONIC_24, PASSPHRASE_24, "m/44'/165'/0'");
        let signer = NanoSigner;

        let result = signer.sign(&key, b"msg").unwrap();
        let expected_pubkey =
            hex::decode("5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4")
                .unwrap();
        assert_eq!(result.public_key.unwrap(), expected_pubkey);
    }

    #[test]
    fn test_invalid_key() {
        let signer = NanoSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
    }

    // ─── state block / transaction signing ───────────────────────────────────

    #[test]
    fn test_sign_transaction_state_block() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;

        let vk = NanoSigner::verifying_key(&key).unwrap();
        let account = vk.to_bytes();

        let block = build_state_block(
            &account,
            &[0u8; 32],                                    // open block (no previous)
            &[2u8; 32],                                    // representative
            1_000_000_000_000_000_000_000_000_000_000u128, // 1 XNO in raw
            &[3u8; 32],                                    // link
        );

        let result = signer.sign_transaction(&key, &block).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Verify: signature must be over the block hash, not raw block bytes
        let block_hash = hash_state_block(&block).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        raw_verify::<Blake2b512>(&vk, &block_hash, &sig).expect("should verify against block hash");
    }

    #[test]
    fn test_sign_transaction_wrong_length() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;
        // Not 176 bytes
        assert!(signer.sign_transaction(&key, &[0u8; 100]).is_err());
        assert!(signer.sign_transaction(&key, &[0u8; 177]).is_err());
    }

    #[test]
    fn test_sign_transaction_wrong_preamble() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;
        let mut block = [0u8; 176];
        block[31] = 0x05; // wrong preamble byte
        assert!(signer.sign_transaction(&key, &block).is_err());
    }

    // ─── encode_signed_transaction ────────────────────────────────────────────

    #[test]
    fn test_encode_signed_transaction() {
        let key = derive_key(MNEMONIC_12, "", "m/44'/165'/0'");
        let signer = NanoSigner;

        let vk = NanoSigner::verifying_key(&key).unwrap();
        let account = vk.to_bytes();

        let block = build_state_block(
            &account,
            &[0u8; 32],
            &[2u8; 32],
            1_000_000_000_000_000_000_000_000_000_000u128,
            &[3u8; 32],
        );

        let result = signer.sign_transaction(&key, &block).unwrap();
        let signed = signer.encode_signed_transaction(&block, &result).unwrap();

        // 176-byte block + 64-byte signature = 240 bytes
        assert_eq!(signed.len(), 240);
        assert_eq!(&signed[..176], &block[..]);
        assert_eq!(&signed[176..], &result.signature[..]);
    }

    #[test]
    fn test_encode_signed_transaction_wrong_sig_len() {
        let signer = NanoSigner;
        let block = {
            let mut b = [0u8; 176];
            b[31] = 0x06;
            b
        };
        let bad_sig = SignOutput {
            signature: vec![0u8; 32], // wrong: should be 64
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(&block, &bad_sig).is_err());
    }

    #[test]
    fn test_encode_signed_transaction_wrong_block_len() {
        let signer = NanoSigner;
        let bad_block = vec![0u8; 100]; // wrong length
        let sig = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(&bad_block, &sig).is_err());
    }

    // ─── full end-to-end pipeline ─────────────────────────────────────────────

    #[test]
    fn test_full_pipeline_mnemonic_to_sign_to_verify() {
        // Mnemonic -> derive key -> derive address -> build block -> sign -> encode -> verify
        let key = derive_key(MNEMONIC_24, PASSPHRASE_24, "m/44'/165'/0'");
        let signer = NanoSigner;

        // Verify known address
        let address = signer.derive_address(&key).unwrap();
        assert_eq!(
            address,
            "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d"
        );

        let vk = NanoSigner::verifying_key(&key).unwrap();
        let account = vk.to_bytes();

        // Build a send block
        let block = build_state_block(
            &account,
            &[0xABu8; 32],                               // previous
            &account,                                    // self as representative
            500_000_000_000_000_000_000_000_000_000u128, // 0.5 XNO remaining
            &[0xCDu8; 32],                               // destination link
        );

        // sign_transaction hashes first, then signs
        let result = signer.sign_transaction(&key, &block).unwrap();
        let signed = signer.encode_signed_transaction(&block, &result).unwrap();
        assert_eq!(signed.len(), 240);

        // Verify signature over the block hash
        let block_hash = hash_state_block(&block).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        raw_verify::<Blake2b512>(&vk, &block_hash, &sig)
            .expect("end-to-end signature should verify");
    }
}
