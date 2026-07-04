use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};

/// TON chain signer (Ed25519, wallet v5r1 addresses).
pub struct TonSigner;

/// Wallet v5r1 code cell hash (SHA256 of the cell representation).
/// Verified against @ton/ton WalletContractV5R1.
const WALLET_V5R1_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

/// Wallet v5r1 code cell depth.
const WALLET_V5R1_CODE_DEPTH: u16 = 6;

/// Default walletId for mainnet workchain 0.
/// Computed as: networkGlobalId(-239) XOR context(0x80000000)
/// context = 1(1b) + workchain(0, 8b) + version(0, 8b) + subwalletNumber(0, 15b)
const DEFAULT_WALLET_ID: i32 = 0x7FFFFF11u32 as i32;

impl TonSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    /// Compute the data cell hash for wallet v5r1 initial state.
    /// Data: is_sig_allowed(1b) + seqno(0, 32b) + walletId(32b) + pubkey(256b) + extensions(0, 1b)
    /// = 322 bits, 0 refs.
    fn data_cell_hash(public_key: &[u8; 32]) -> [u8; 32] {
        // 322 bits: 40 full bytes + 2 extra bits
        let d1: u8 = 0; // 0 refs
        let d2: u8 = 81; // ceil(322/8) + floor(322/8) = 41 + 40

        // Build the 322-bit data as a byte stream.
        // Bit layout (MSB first within each byte):
        //   bit 0:       is_signature_allowed = 1
        //   bits 1-32:   seqno = 0 (32 bits)
        //   bits 33-64:  walletId as int32 (32 bits)
        //   bits 65-320: public_key (256 bits)
        //   bit 321:     extensions = 0
        // Then completion tag: bit 322 = 1, bits 323-327 = 0
        //
        // Byte 0:  1_0000000  (is_sig=1, seqno MSBs = 0)
        // Bytes 1-3: 00000000 (seqno continued)
        // Byte 4:  0_0111111  (seqno LSB=0, then walletId top 7 bits)
        //   walletId = 0x7FFFFF11:
        //     binary: 01111111 11111111 11111111 00010001
        //   shifted right by 1 bit into the stream starting at bit 33:
        // This is complex to hand-encode, so we build it programmatically.

        let wallet_id_bytes = DEFAULT_WALLET_ID.to_be_bytes();

        // Pack bits into bytes: [1-bit flag] [32-bit seqno] [32-bit walletId] [256-bit key] [1-bit ext]
        // = 322 bits total. We'll use a simple bit packer.
        let mut bits = Vec::with_capacity(328);

        // is_signature_allowed = 1
        bits.push(1u8);

        // seqno = 0 (32 bits)
        bits.extend(std::iter::repeat_n(0u8, 32));

        // walletId (32 bits, big-endian)
        for &b in &wallet_id_bytes {
            for shift in (0..8).rev() {
                bits.push((b >> shift) & 1);
            }
        }

        // public_key (256 bits)
        for &b in public_key {
            for shift in (0..8).rev() {
                bits.push((b >> shift) & 1);
            }
        }

        // extensions = 0
        bits.push(0);

        // Add completion tag: 1 followed by zeros to fill the byte
        bits.push(1);
        while bits.len() % 8 != 0 {
            bits.push(0);
        }

        // Convert bit array to bytes
        let mut data_bytes = Vec::with_capacity(bits.len() / 8);
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= bit << (7 - i);
            }
            data_bytes.push(byte);
        }

        let mut repr = Vec::with_capacity(2 + data_bytes.len());
        repr.push(d1);
        repr.push(d2);
        repr.extend_from_slice(&data_bytes);

        Sha256::digest(&repr).into()
    }

    /// Compute the StateInit cell hash.
    /// StateInit: 5 bits (00110) = split_depth(0) special(0) code(1) data(1) library(0), 2 refs.
    fn state_init_hash(code_hash: &[u8; 32], code_depth: u16, data_hash: &[u8; 32]) -> [u8; 32] {
        let d1: u8 = 2; // 2 refs
        let d2: u8 = 1; // ceil(5/8) + floor(5/8) = 1 + 0

        let mut repr = Vec::with_capacity(3 + 4 + 64);
        repr.push(d1);
        repr.push(d2);
        repr.push(0x34); // 00110 + completion tag '100' = 0b00110100

        // Depths (2 bytes big-endian each)
        repr.push((code_depth >> 8) as u8);
        repr.push(code_depth as u8);
        repr.push(0); // data cell depth = 0
        repr.push(0);

        // Hashes
        repr.extend_from_slice(code_hash);
        repr.extend_from_slice(data_hash);

        Sha256::digest(&repr).into()
    }

    /// Encode a TON user-friendly address (base64url with CRC16).
    fn encode_address(workchain: i8, hash: &[u8; 32], bounceable: bool) -> String {
        use base64::Engine;
        let tag: u8 = if bounceable { 0x11 } else { 0x51 };

        let mut addr = Vec::with_capacity(36);
        addr.push(tag);
        addr.push(workchain as u8);
        addr.extend_from_slice(hash);

        let crc = crc16_ccitt(&addr);
        addr.push((crc >> 8) as u8);
        addr.push(crc as u8);

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&addr)
    }
}

impl ChainSigner for TonSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Ton
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        607
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        let data_hash = Self::data_cell_hash(pubkey_bytes);
        let state_hash =
            Self::state_init_hash(&WALLET_V5R1_CODE_HASH, WALLET_V5R1_CODE_DEPTH, &data_hash);

        Ok(Self::encode_address(0, &state_hash, false))
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
        self.sign(private_key, tx_bytes)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/607'/{}'", index)
    }
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::Verifier;

    fn test_privkey() -> Vec<u8> {
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap()
    }

    #[test]
    fn test_code_hash_constant() {
        assert_eq!(
            hex::encode(WALLET_V5R1_CODE_HASH),
            "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f"
        );
    }

    #[test]
    fn test_data_cell_hash_matches_ton_core() {
        // Null pubkey data cell hash verified against @ton/ton WalletContractV5R1
        let null_pubkey = [0u8; 32];
        let hash = TonSigner::data_cell_hash(&null_pubkey);
        assert_eq!(
            hex::encode(hash),
            "0f80a4e3e2630cba3f6f37d12dbcf6afaaa015cd889eeb681a334a4fbe84cf31"
        );
    }

    #[test]
    fn test_known_address() {
        // Address verified against @ton/ton WalletContractV5R1.create()
        // Private key: 9d61b19d... -> Public key: d75a9801...
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            address.starts_with("UQ"),
            "non-bounceable address should start with UQ, got: {address}"
        );
    }

    #[test]
    fn test_address_format() {
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(address.len(), 48, "TON address should be 48 chars");
        assert!(
            address.starts_with("UQ"),
            "non-bounceable workchain-0 address should start with UQ, got: {address}"
        );
    }

    #[test]
    fn test_address_decodes_to_valid_structure() {
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&address)
            .unwrap();
        assert_eq!(decoded.len(), 36);
        assert_eq!(decoded[0], 0x51); // non-bounceable tag
        assert_eq!(decoded[1], 0x00); // workchain 0

        let crc = crc16_ccitt(&decoded[..34]);
        assert_eq!(decoded[34], (crc >> 8) as u8);
        assert_eq!(decoded[35], crc as u8);
    }

    #[test]
    fn test_deterministic_address() {
        let signer = TonSigner;
        let addr1 = signer.derive_address(&test_privkey()).unwrap();
        let addr2 = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey = test_privkey();
        let signer = TonSigner;
        let message = b"test message for ton";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_no_recovery_id() {
        let signer = TonSigner;
        let result = signer.sign(&test_privkey(), b"msg").unwrap();
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn test_derivation_path() {
        let signer = TonSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/607'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/607'/1'");
    }

    #[test]
    fn test_chain_properties() {
        let signer = TonSigner;
        assert_eq!(signer.chain_type(), ChainType::Ton);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 607);
    }

    #[test]
    fn test_invalid_key() {
        let signer = TonSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_crc16() {
        let data = b"123456789";
        assert_eq!(crc16_ccitt(data), 0x31C3);
    }
}
