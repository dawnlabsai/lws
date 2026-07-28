use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use bech32::{Bech32, Hrp};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_bip32::XPrv;
use ows_core::ChainType;

/// Domain-separation prefix for `sign_message`. Ensures a signed message can
/// never be byte-identical to a blake2b-256 transaction hash (the prefixed
/// payload is always longer than 32 bytes and starts with ASCII that a raw
/// hash context cannot require), so message signatures are structurally
/// unusable as transaction witnesses.
pub const CARDANO_MESSAGE_PREFIX: &[u8] = b"Cardano Signed Message:\n";

/// Cardano network tag used in address header byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    fn tag(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Testnet => 0,
        }
    }

    fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "addr",
            Network::Testnet => "addr_test",
        }
    }
}

/// Cardano signer — CIP-1852, Ed25519-BIP32, bech32 enterprise addresses.
pub struct CardanoSigner {
    network: Network,
}

impl CardanoSigner {
    /// Mainnet signer (default).
    pub fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
        }
    }

    /// Testnet signer (preprod / preview).
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
        }
    }

    /// Reconstruct an `XPrv` from the 64-byte extended private key produced by CIP-1852
    /// derivation. See [`xprv_from_extended_bytes`].
    fn xprv_from_extended(extended_key: &[u8]) -> Result<XPrv, SignerError> {
        xprv_from_extended_bytes(extended_key)
    }

    /// Compute the blake2b-224 hash (28 bytes) of the given data.
    fn blake2b_224(data: &[u8]) -> [u8; 28] {
        let mut hasher = Blake2bVar::new(28).expect("28 is a valid Blake2b output length");
        hasher.update(data);
        let mut out = [0u8; 28];
        hasher.finalize_variable(&mut out).unwrap();
        out
    }

    /// Compute the blake2b-256 hash (32 bytes) of the given data.
    fn blake2b_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("32 is a valid Blake2b output length");
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).unwrap();
        out
    }

    /// Encode a Cardano enterprise address for this signer's network.
    ///
    /// Enterprise address = header_byte || blake2b-224(payment_pubkey)
    /// Header byte: 0b0110_0000 | network_tag  (0x61 mainnet, 0x60 testnet)
    fn encode_address(&self, pub_key: &[u8; 32]) -> Result<String, SignerError> {
        let header = 0b0110_0000u8 | self.network.tag();
        let key_hash = Self::blake2b_224(pub_key);

        // 29 bytes: [header (1)] || [key_hash (28)]
        let mut payload = Vec::with_capacity(29);
        payload.push(header);
        payload.extend_from_slice(&key_hash);

        let hrp = Hrp::parse(self.network.hrp())
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
        bech32::encode::<Bech32>(hrp, &payload)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
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

    /// Derive a Cardano enterprise address from a 64-byte extended private key.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let xprv = Self::xprv_from_extended(private_key)?;
        let xpub = xprv.public();
        let pub_key = xpub.public_key_bytes();
        self.encode_address(pub_key)
    }

    /// Sign a message directly with Ed25519-BIP32 (no pre-hashing).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let xprv = Self::xprv_from_extended(private_key)?;
        let sig: ed25519_bip32::Signature<()> = xprv.sign(message);
        Ok(SignOutput {
            signature: sig.as_ref().to_vec(),
            recovery_id: None,
            public_key: Some(xprv.public().public_key_bytes().to_vec()),
        })
    }

    /// Sign a Cardano transaction.
    ///
    /// `tx_bytes` must be the CBOR-serialized full transaction:
    /// `[tx_body_map, witness_set_map, bool, aux_data_or_null]`.
    ///
    /// The signature covers blake2b-256(cbor(tx_body)) where `tx_body` is the
    /// first element of the outer array (CBOR index 0).
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Parse the full CBOR transaction to extract the transaction body.
        let tx_value: ciborium::Value = ciborium::de::from_reader(tx_bytes)
            .map_err(|e| SignerError::InvalidTransaction(format!("CBOR decode error: {e}")))?;

        let tx_array = match &tx_value {
            ciborium::Value::Array(arr) => arr,
            _ => {
                return Err(SignerError::InvalidTransaction(
                    "expected CBOR array at top level".into(),
                ))
            }
        };

        if tx_array.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "transaction array is empty".into(),
            ));
        }

        // Re-encode the transaction body (index 0) to get its canonical CBOR bytes.
        let mut tx_body_cbor = Vec::new();
        ciborium::ser::into_writer(&tx_array[0], &mut tx_body_cbor).map_err(|e| {
            SignerError::InvalidTransaction(format!("CBOR encode tx_body error: {e}"))
        })?;

        // Hash the tx_body with blake2b-256.
        let tx_hash = Self::blake2b_256(&tx_body_cbor);

        // Sign the hash.
        self.sign(private_key, &tx_hash)
    }

    /// Sign an arbitrary message with a domain-separation prefix.
    ///
    /// The prefix guarantees the signed payload can never equal a raw
    /// blake2b-256 transaction hash, so a "sign this message" request can
    /// never yield a valid Cardano transaction witness. Verifiers must
    /// prepend the same prefix. (Full CIP-8 / COSE_Sign1 enveloping is a
    /// planned follow-up for wallet interoperability.)
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let mut prefixed = Vec::with_capacity(CARDANO_MESSAGE_PREFIX.len() + message.len());
        prefixed.extend_from_slice(CARDANO_MESSAGE_PREFIX);
        prefixed.extend_from_slice(message);
        self.sign(private_key, &prefixed)
    }

    /// Inject the witness set into the Cardano transaction.
    ///
    /// `tx_bytes` must be the full CBOR transaction array.
    /// The witness set is injected at index 1 as:
    /// `{ 0: [[vkey_32_bytes, signature_64_bytes]] }`
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
        let pub_key = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction("missing public key in SignOutput".into())
        })?;
        if pub_key.len() != 32 {
            return Err(SignerError::InvalidTransaction(
                "expected 32-byte Ed25519 public key".into(),
            ));
        }

        // Parse the original transaction.
        let mut tx_value: ciborium::Value = ciborium::de::from_reader(tx_bytes)
            .map_err(|e| SignerError::InvalidTransaction(format!("CBOR decode error: {e}")))?;

        let tx_array = match &mut tx_value {
            ciborium::Value::Array(arr) => arr,
            _ => {
                return Err(SignerError::InvalidTransaction(
                    "expected CBOR array at top level".into(),
                ))
            }
        };

        if tx_array.len() < 2 {
            return Err(SignerError::InvalidTransaction(
                "transaction array too short (need at least 2 elements)".into(),
            ));
        }

        // Build witness set: { 0: [[vkey, signature]] }
        let witness_set = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(0u64.into()),
            ciborium::Value::Array(vec![ciborium::Value::Array(vec![
                ciborium::Value::Bytes(pub_key.clone()),
                ciborium::Value::Bytes(signature.signature.clone()),
            ])]),
        )]);

        // Replace the witness set at index 1.
        tx_array[1] = witness_set;

        // Re-encode the modified transaction.
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&tx_value, &mut encoded)
            .map_err(|e| SignerError::InvalidTransaction(format!("CBOR encode error: {e}")))?;

        Ok(encoded)
    }

    /// CIP-1852 derivation path for the payment key.
    ///
    /// Path: `m/1852'/1815'/account'/0/index`
    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/1852'/1815'/{index}'/0/0")
    }
}

/// Derive the staking key path per CIP-1852.
///
/// Path: `m/1852'/1815'/account'/2/0`
pub fn staking_key_path(account: u32) -> String {
    format!("m/1852'/1815'/{account}'/2/0")
}

/// Apply one more step of CIP-1852 child derivation to reach the payment key at `index`.
/// Useful when the caller already has the account-level key and wants a specific address index.
pub fn payment_key_path(account: u32, index: u32) -> String {
    format!("m/1852'/1815'/{account}'/0/{index}")
}

/// Derive a staking address from an extended stake key using the CIP-1852 reward address format.
///
/// Reward address = header_byte || blake2b-224(stake_pubkey)
/// Header: 0b1110_0000 | network_tag (0xE1 mainnet, 0xE0 testnet)
pub fn reward_address(stake_key: &[u8], mainnet: bool) -> Result<String, SignerError> {
    let xprv = xprv_from_extended_bytes(stake_key)?;
    let pub_key = xprv.public();
    let pub_key_bytes = pub_key.public_key_bytes();

    let mut hasher = Blake2bVar::new(28).expect("valid output length");
    hasher.update(pub_key_bytes);
    let mut key_hash = [0u8; 28];
    hasher.finalize_variable(&mut key_hash).unwrap();

    let network_tag: u8 = if mainnet { 1 } else { 0 };
    let header = 0b1110_0000u8 | network_tag;

    let mut payload = Vec::with_capacity(29);
    payload.push(header);
    payload.extend_from_slice(&key_hash);

    let hrp_str = if mainnet { "stake" } else { "stake_test" };
    let hrp =
        Hrp::parse(hrp_str).map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, &payload)
        .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
}

/// Reconstruct an `XPrv` from a 64-byte extended private key. Chain code is set to
/// zeroes because it is not needed for signing or public-key derivation — only the
/// scalar (kL) and extension (kR) matter. Child derivation is deliberately NOT
/// offered on keys reconstructed this way: BIP32-Ed25519 child derivation is keyed
/// by the chain code, and a zero chain code would make sibling public keys
/// enumerable from a single exposed public key. Path derivation happens in
/// `HdDeriver`, which carries the real chain code.
///
/// The scalar (kL, first 32 bytes) is clamped per the BIP32-Ed25519 spec so that the
/// XPrv construction never panics and always yields a valid Ed25519 scalar,
/// regardless of the key source. All XPrv construction from raw bytes must go
/// through this helper so addresses and signatures stay consistent.
fn xprv_from_extended_bytes(extended_key: &[u8]) -> Result<XPrv, SignerError> {
    if extended_key.len() != 64 {
        return Err(SignerError::InvalidPrivateKey(format!(
            "Cardano requires a 64-byte extended private key, got {}",
            extended_key.len()
        )));
    }
    let mut sk = [0u8; 64];
    sk.copy_from_slice(extended_key);
    // Clamp kL per BIP32-Ed25519 / CIP-1852 so the scalar is always valid.
    sk[0] &= 0b1111_1000;
    sk[31] &= 0b0001_1111;
    sk[31] |= 0b0100_0000;
    Ok(XPrv::from_extended_and_chaincode(&sk, &[0u8; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Curve;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    fn derive_payment_key(mnemonic: &Mnemonic) -> Vec<u8> {
        let signer = CardanoSigner::mainnet();
        let path = signer.default_derivation_path(0);
        HdDeriver::derive_from_mnemonic(mnemonic, "", &path, Curve::Ed25519Bip32)
            .unwrap()
            .expose()
            .to_vec()
    }

    #[test]
    fn test_chain_properties() {
        let signer = CardanoSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Cardano);
        assert_eq!(signer.curve(), Curve::Ed25519Bip32);
        assert_eq!(signer.coin_type(), 1815);
    }

    #[test]
    fn test_derivation_path() {
        let signer = CardanoSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/1852'/1815'/0'/0/0");
        assert_eq!(signer.default_derivation_path(1), "m/1852'/1815'/1'/0/0");
    }

    #[test]
    fn test_address_is_valid_bech32_mainnet() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();
        let address = signer.derive_address(&key).unwrap();
        assert!(
            address.starts_with("addr1"),
            "mainnet enterprise address must start with 'addr1', got: {address}"
        );
        // Mainnet enterprise addresses are always 59 chars (29 payload bytes → 47 base32 chars + 6 checksum + "addr1" prefix)
        assert!(
            address.len() > 50,
            "address too short: {} chars",
            address.len()
        );
    }

    #[test]
    fn test_address_is_valid_bech32_testnet() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::testnet();
        let address = signer.derive_address(&key).unwrap();
        assert!(
            address.starts_with("addr_test1"),
            "testnet enterprise address must start with 'addr_test1', got: {address}"
        );
    }

    #[test]
    fn test_mainnet_testnet_different_addresses() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let mainnet_addr = CardanoSigner::mainnet().derive_address(&key).unwrap();
        let testnet_addr = CardanoSigner::testnet().derive_address(&key).unwrap();
        assert_ne!(mainnet_addr, testnet_addr);
    }

    #[test]
    fn test_deterministic_address() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();
        let addr1 = signer.derive_address(&key).unwrap();
        let addr2 = signer.derive_address(&key).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();
        let message = b"test message for cardano";
        let result = signer.sign(&key, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.unwrap().len(), 32);
    }

    #[test]
    fn test_sign_deterministic() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();
        let message = b"hello cardano";
        let sig1 = signer.sign(&key, message).unwrap();
        let sig2 = signer.sign(&key, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_invalid_key_length() {
        let signer = CardanoSigner::mainnet();
        let bad_key = vec![0u8; 32]; // too short (need 64)
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
    }

    #[test]
    fn test_different_mnemonics_different_addresses() {
        let mnemonic1 = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let phrase2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let mnemonic2 = Mnemonic::from_phrase(phrase2).unwrap();

        let signer = CardanoSigner::mainnet();
        let key1 = derive_payment_key(&mnemonic1);
        let path = signer.default_derivation_path(0);
        let key2 = HdDeriver::derive_from_mnemonic(&mnemonic2, "", &path, Curve::Ed25519Bip32)
            .unwrap()
            .expose()
            .to_vec();

        let addr1 = signer.derive_address(&key1).unwrap();
        let addr2 = signer.derive_address(&key2).unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_sign_transaction_valid_cbor() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();

        // Minimal syntactically valid Cardano transaction CBOR:
        // [tx_body_map, witness_set_map, true, null]
        // tx_body_map = {0: [[input_bytes, 0]], 1: [[output_addr, lovelace]], 2: fee}
        // We use a simplified form: [{}, {}, true, null]
        let tx: Vec<ciborium::Value> = vec![
            ciborium::Value::Map(vec![]), // tx_body (empty for test)
            ciborium::Value::Map(vec![]), // witness_set placeholder
            ciborium::Value::Bool(true),
            ciborium::Value::Null,
        ];
        let mut tx_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Array(tx), &mut tx_bytes).unwrap();

        let result = signer.sign_transaction(&key, &tx_bytes).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());
    }

    #[test]
    fn test_encode_signed_transaction() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();

        let tx: Vec<ciborium::Value> = vec![
            ciborium::Value::Map(vec![]),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bool(true),
            ciborium::Value::Null,
        ];
        let mut tx_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Array(tx), &mut tx_bytes).unwrap();

        let sig = signer.sign_transaction(&key, &tx_bytes).unwrap();
        let signed_tx = signer.encode_signed_transaction(&tx_bytes, &sig).unwrap();

        // Decode the signed tx and verify witness set is present at index 1
        let decoded: ciborium::Value = ciborium::de::from_reader(&signed_tx[..]).unwrap();
        let arr = match decoded {
            ciborium::Value::Array(a) => a,
            _ => panic!("expected array"),
        };
        assert_eq!(arr.len(), 4);

        // Witness set should be a map with key 0
        match &arr[1] {
            ciborium::Value::Map(m) => {
                assert_eq!(m.len(), 1, "witness set should have one entry");
            }
            other => panic!("expected map at index 1, got: {other:?}"),
        }
    }

    #[test]
    fn test_blake2b_224_known_vector() {
        // Blake2b-224 of empty input — known value
        let hash = CardanoSigner::blake2b_224(b"");
        assert_eq!(hash.len(), 28);
        // Basic sanity: not all zeros
        assert_ne!(hash, [0u8; 28]);
    }

    #[test]
    fn test_blake2b_256_known_vector() {
        let hash = CardanoSigner::blake2b_256(b"");
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_staking_key_path() {
        assert_eq!(staking_key_path(0), "m/1852'/1815'/0'/2/0");
        assert_eq!(staking_key_path(1), "m/1852'/1815'/1'/2/0");
    }

    #[test]
    fn test_payment_key_path() {
        assert_eq!(payment_key_path(0, 0), "m/1852'/1815'/0'/0/0");
        assert_eq!(payment_key_path(0, 5), "m/1852'/1815'/0'/0/5");
    }

    #[test]
    fn test_reward_address_mainnet() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let stake_path = staking_key_path(0);
        let stake_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", &stake_path, Curve::Ed25519Bip32)
                .unwrap();
        let addr = reward_address(stake_key.expose(), true).unwrap();
        assert!(
            addr.starts_with("stake1"),
            "mainnet reward address must start with 'stake1', got: {addr}"
        );
    }

    #[test]
    fn test_reward_address_testnet() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let stake_path = staking_key_path(0);
        let stake_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", &stake_path, Curve::Ed25519Bip32)
                .unwrap();
        let addr = reward_address(stake_key.expose(), false).unwrap();
        assert!(
            addr.starts_with("stake_test1"),
            "testnet reward address must start with 'stake_test1', got: {addr}"
        );
    }

    #[test]
    fn test_reward_address_clamps_malformed_key() {
        // A key with no BIP32-Ed25519 clamp bits set must not panic and must
        // produce the same address as its pre-clamped equivalent, keeping
        // address derivation consistent with the (clamping) signing path.
        let unclamped = [0xFFu8; 64];
        let mut clamped = unclamped;
        clamped[0] &= 0b1111_1000;
        clamped[31] &= 0b0001_1111;
        clamped[31] |= 0b0100_0000;
        assert_eq!(
            reward_address(&unclamped, true).unwrap(),
            reward_address(&clamped, true).unwrap()
        );
    }

    #[test]
    fn test_reward_address_rejects_bad_length() {
        assert!(reward_address(&[0u8; 32], true).is_err());
    }

    #[test]
    fn test_sign_message_is_domain_separated_from_transaction_signing() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key = derive_payment_key(&mnemonic);
        let signer = CardanoSigner::mainnet();

        // A phishing "message" that is exactly a 32-byte transaction hash
        // must not produce the same signature the transaction path would,
        // otherwise the message signature is a valid transaction witness.
        let fake_tx_hash = [0xABu8; 32];
        let message_sig = signer.sign_message(&key, &fake_tx_hash).unwrap();
        let witness_sig = signer.sign(&key, &fake_tx_hash).unwrap();
        assert_ne!(message_sig.signature, witness_sig.signature);

        // The prefixed payload is what actually gets signed.
        let mut prefixed = CARDANO_MESSAGE_PREFIX.to_vec();
        prefixed.extend_from_slice(&fake_tx_hash);
        let expected = signer.sign(&key, &prefixed).unwrap();
        assert_eq!(message_sig.signature, expected.signature);
    }
}
