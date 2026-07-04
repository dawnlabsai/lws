use crate::curve::Curve;
use ows_core::ChainType;

/// Output of a signing operation.
#[derive(Debug, Clone)]
pub struct SignOutput {
    /// The raw signature bytes.
    pub signature: Vec<u8>,
    /// Recovery ID (for secp256k1 signatures). None for Ed25519.
    pub recovery_id: Option<u8>,
    /// Public key bytes (needed by chains like Sui whose wire format includes the pubkey).
    pub public_key: Option<Vec<u8>>,
}

/// Trait for chain-specific signing operations.
///
/// All methods take raw `&[u8]` private keys — callers are responsible for
/// HD derivation and zeroization of key material.
pub trait ChainSigner: Send + Sync {
    /// The chain type this signer handles.
    fn chain_type(&self) -> ChainType;

    /// The elliptic curve used by this chain.
    fn curve(&self) -> Curve;

    /// The BIP-44 coin type for this chain.
    fn coin_type(&self) -> u32;

    /// Derive an on-chain address from a private key.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError>;

    /// Derive the raw public key bytes from a private key.
    ///
    /// Returns the canonical public key encoding for this chain's curve:
    /// - secp256k1 chains: 33-byte compressed public key (SEC1)
    /// - Ed25519 chains: 32-byte public key
    ///
    /// Public keys are not secret — exposing them does not weaken the security model.
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// Sign a pre-hashed message (32 bytes for secp256k1, raw message for ed25519).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an arbitrary message with chain-specific prefixing/hashing.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an unsigned transaction. Each chain hashes the raw transaction
    /// bytes according to its own rules before signing.
    ///
    /// `tx_bytes` should be the signable payload — i.e. the bytes that the
    /// chain's validators expect the signature to cover. For most chains this
    /// is the serialized transaction itself (which gets hashed internally).
    /// Callers that hold a *full* serialized container (e.g. Solana's
    /// `[sig-slots | message]`) should call [`extract_signable_bytes`] first.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError>;

    /// Extract the signable portion from a full serialized transaction.
    ///
    /// Some wire formats include non-signed metadata (e.g. Solana prepends
    /// signature-slot placeholders). This method strips that metadata and
    /// returns only the bytes that must be signed.
    ///
    /// The default implementation returns the input unchanged — most chains
    /// sign the full serialized blob (after internal hashing).
    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        Ok(tx_bytes)
    }

    /// Encode the full signed transaction from the unsigned transaction bytes
    /// and the signing output. Returns the bytes suitable for broadcasting.
    ///
    /// The default implementation returns an error — chains must opt in.
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        let _ = (tx_bytes, signature);
        Err(SignerError::InvalidTransaction(format!(
            "encode_signed_transaction not implemented for {}",
            self.chain_type()
        )))
    }

    /// Returns the default BIP-44 derivation path template for this chain.
    fn default_derivation_path(&self, index: u32) -> String;
}

/// Errors that can occur during signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("address derivation failed: {0}")]
    AddressDerivationFailed(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
}
