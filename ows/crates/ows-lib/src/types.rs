use ows_core::ChainType;
use ows_signer::SignOutput;
use serde::{Deserialize, Serialize};

use crate::error::OwsLibError;

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Binding-friendly wallet information (no crypto envelope exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

/// Result from a signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u8>,
    /// The fully signed, sealed transaction (hex), when a chain assembles a complete broadcastable
    /// artifact at sign time. Only Midnight does: its proven intent is signed and then sealed
    /// (keyless), yielding a submit-ready transaction. `None` for every other chain, whose signing
    /// product is the bare `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
}

/// Byte length of a Midnight message signature's x-only BIP-340 public key prefix.
pub const MIDNIGHT_MESSAGE_PUBKEY_LEN: usize = 32;
/// Byte length of a Midnight message signature body (BIP-340 Schnorr).
pub const MIDNIGHT_MESSAGE_SIG_LEN: usize = 64;

/// Encode a Midnight message signature as hex of `pubkey (32) || signature (64)` — 96 bytes, 192
/// hex chars. The x-only public key is prefixed because BIP-340 signatures aren't
/// public-key-recoverable: the verifier needs the key, and it lets the caller derive the signer's
/// unshielded address.
pub fn encode_midnight_message_signature(pubkey: &[u8], sig: &[u8]) -> Result<String, OwsLibError> {
    if pubkey.len() != MIDNIGHT_MESSAGE_PUBKEY_LEN || sig.len() != MIDNIGHT_MESSAGE_SIG_LEN {
        return Err(OwsLibError::InvalidInput(format!(
            "midnight message signature needs a {MIDNIGHT_MESSAGE_PUBKEY_LEN}-byte pubkey and \
             {MIDNIGHT_MESSAGE_SIG_LEN}-byte signature, got {} and {}",
            pubkey.len(),
            sig.len()
        )));
    }
    let mut buf = Vec::with_capacity(MIDNIGHT_MESSAGE_PUBKEY_LEN + MIDNIGHT_MESSAGE_SIG_LEN);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(sig);
    Ok(hex::encode(buf))
}

/// Split a Midnight message signature hex back into `(pubkey, signature)`. Accepts an optional `0x`
/// prefix. The inverse of [`encode_midnight_message_signature`].
pub fn decode_midnight_message_signature(
    signature_hex: &str,
) -> Result<(Vec<u8>, Vec<u8>), OwsLibError> {
    let bytes = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(signature_hex))
        .map_err(|e| OwsLibError::InvalidInput(format!("invalid midnight signature hex: {e}")))?;
    let expected = MIDNIGHT_MESSAGE_PUBKEY_LEN + MIDNIGHT_MESSAGE_SIG_LEN;
    if bytes.len() != expected {
        return Err(OwsLibError::InvalidInput(format!(
            "midnight message signature must be {expected} bytes, got {}",
            bytes.len()
        )));
    }
    let (pubkey, sig) = bytes.split_at(MIDNIGHT_MESSAGE_PUBKEY_LEN);
    Ok((pubkey.to_vec(), sig.to_vec()))
}

impl SignResult {
    /// A plain detached signature — hex of the raw signature bytes, with an optional recovery id.
    /// The signing product for every chain whose signature is self-contained.
    pub fn detached_signature(signature: String, recovery_id: Option<u8>) -> Self {
        Self {
            signature,
            recovery_id,
            transaction: None,
        }
    }

    /// A Midnight message signature: the x-only public key prefixed to the BIP-340 signature.
    pub fn midnight_message(pubkey: &[u8], sig: &[u8]) -> Result<Self, OwsLibError> {
        Ok(Self {
            signature: encode_midnight_message_signature(pubkey, sig)?,
            recovery_id: None,
            transaction: None,
        })
    }
}

/// Build a [`SignResult`] from a signer's message-signing [`SignOutput`], applying each chain's
/// wire encoding. Midnight prefixes the x-only public key to the signature (see
/// [`encode_midnight_message_signature`]); every other chain returns the hex signature as-is.
pub fn sign_result_from_message_output(
    chain_type: ChainType,
    output: &SignOutput,
) -> Result<SignResult, OwsLibError> {
    match chain_type {
        ChainType::Midnight => {
            let pubkey = output.public_key.as_deref().ok_or_else(|| {
                OwsLibError::InvalidInput(
                    "midnight message signing returned no public key".to_string(),
                )
            })?;
            SignResult::midnight_message(pubkey, &output.signature)
        }
        _ => Ok(SignResult::detached_signature(
            hex::encode(&output.signature),
            output.recovery_id,
        )),
    }
}

/// Result from a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midnight_message_signature_roundtrips() {
        let pubkey = [7u8; MIDNIGHT_MESSAGE_PUBKEY_LEN];
        let sig = [9u8; MIDNIGHT_MESSAGE_SIG_LEN];

        let encoded = encode_midnight_message_signature(&pubkey, &sig).unwrap();
        assert_eq!(
            encoded.len(),
            2 * (MIDNIGHT_MESSAGE_PUBKEY_LEN + MIDNIGHT_MESSAGE_SIG_LEN)
        );

        let (dp, ds) = decode_midnight_message_signature(&encoded).unwrap();
        assert_eq!(dp, pubkey);
        assert_eq!(ds, sig);
        // A leading 0x is accepted.
        let (dp2, _) = decode_midnight_message_signature(&format!("0x{encoded}")).unwrap();
        assert_eq!(dp2, pubkey);

        // Wrong lengths are rejected on both sides.
        assert!(encode_midnight_message_signature(&[0u8; 31], &sig).is_err());
        assert!(decode_midnight_message_signature("00").is_err());
    }

    #[test]
    fn sign_result_encodes_midnight_message_with_pubkey_prefix() {
        let output = SignOutput {
            signature: vec![1u8; MIDNIGHT_MESSAGE_SIG_LEN],
            recovery_id: None,
            public_key: Some(vec![2u8; MIDNIGHT_MESSAGE_PUBKEY_LEN]),
        };
        let midnight = sign_result_from_message_output(ChainType::Midnight, &output).unwrap();
        // 96 bytes -> 192 hex chars, x-only pubkey first.
        assert_eq!(midnight.signature.len(), 192);
        assert!(midnight
            .signature
            .starts_with(&"02".repeat(MIDNIGHT_MESSAGE_PUBKEY_LEN)));
        assert_eq!(midnight.recovery_id, None);

        // Midnight message signing without a public key is an error (the verifier needs it).
        let no_pk = SignOutput {
            signature: vec![1u8; MIDNIGHT_MESSAGE_SIG_LEN],
            recovery_id: None,
            public_key: None,
        };
        assert!(sign_result_from_message_output(ChainType::Midnight, &no_pk).is_err());

        // A non-Midnight chain returns the bare hex signature plus its recovery id.
        let evm = SignOutput {
            signature: vec![0xab; 3],
            recovery_id: Some(1),
            public_key: None,
        };
        let r = sign_result_from_message_output(ChainType::Evm, &evm).unwrap();
        assert_eq!(r.signature, "ababab");
        assert_eq!(r.recovery_id, Some(1));
    }
}
