use crate::curve::Curve;
use crate::hd::DerivedKey;
use crate::zeroizing::SecretBytes;
use ows_core::policy::TransactionContext;
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

    /// Whether a wallet imported from a single raw private key derives an account
    /// for this chain. Defaults to `true`. Chains whose account only exists as a
    /// mnemonic-derived key bundle (Midnight packs three role seeds into one
    /// signing key) return `false`, so a bare imported key skips them rather than
    /// failing the whole import.
    fn supports_private_key_import(&self) -> bool {
        true
    }

    /// Derive an on-chain address from the key material produced by
    /// [`ChainSigner::encode_keys`] — the primary key for single-key chains, or
    /// the full encoded bundle for chains that bind several keys per account
    /// (e.g. Cardano's payment + staking), which decode it here.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError>;

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

    fn make_transaction_context(
        &self,
        tx_bytes: &[u8],
        _rpc_url: Option<&str>,
    ) -> Result<TransactionContext, SignerError> {
        Ok(TransactionContext {
            effects: vec![],
            raw_hex: hex::encode(tx_bytes),
            data: None,
            chain_extra: None,
        })
    }

    /// Returns the default BIP-44 derivation path template for this chain.
    fn default_derivation_path(&self, index: u32) -> String;

    /// All derivation paths this chain binds to one account at `index`.
    ///
    /// Defaults to the single [`ChainSigner::default_derivation_path`] on this
    /// chain's [`ChainSigner::curve`]. Chains that derive several keys per
    /// account (e.g. Midnight's unshielded / shielded / dust roles) override
    /// this; the first path is the primary (address / signing) key.
    fn default_derivation_paths(&self, index: u32) -> Vec<String> {
        vec![self.default_derivation_path(index)]
    }

    /// Collapse a resolved key bundle into the single key-material blob that the
    /// signing methods (`sign`, `sign_message`, `sign_transaction`) and
    /// `derive_address` consume.
    ///
    /// Most chains bind one key per account, so the default returns the primary
    /// (first) key unchanged — `default_derivation_paths[0]` is the contractual
    /// primary. Chains that bind several keys per account (e.g. Midnight,
    /// Cardano) override this to pack them into one blob; the matching decode
    /// lives in that chain's signer, which unpacks it inside its signing and
    /// address methods. The blob is opaque to the generic path — only the
    /// producing chain interprets it.
    fn encode_keys(&self, keys: &[DerivedKey]) -> Result<SecretBytes, SignerError> {
        keys.first()
            .map(|k| k.secret.clone())
            .ok_or_else(|| SignerError::InvalidPrivateKey("no derived keys to encode".into()))
    }
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
