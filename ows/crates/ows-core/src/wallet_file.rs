use crate::chain::ChainType;
use serde::{Deserialize, Serialize};

/// The full on-disk wallet file format (extended Ethereum Keystore v3).
/// Written to `~/.ows/wallets/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    #[serde(alias = "lws_version")]
    pub ows_version: u32,
    pub id: String,
    pub name: String,
    pub created_at: String,
    /// Deprecated in v2. Kept for backward compat when deserializing v1 wallets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_type: Option<ChainType>,
    pub accounts: Vec<WalletAccount>,
    pub crypto: serde_json::Value,
    pub key_type: KeyType,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub account_id: String,
    pub address: String,
    pub chain_id: String,
    pub derivation_path: String,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Mnemonic,
    /// Multi-curve key pair: encrypted JSON `{"secp256k1":"hex","ed25519":"hex","ed25519_bip32":"hex"}`.
    /// Derives one account per [`crate::chain::universal_wallet_chains`] row from these keys.
    PrivateKey,
}

impl EncryptedWallet {
    pub fn new(
        id: String,
        name: String,
        accounts: Vec<WalletAccount>,
        crypto: serde_json::Value,
        key_type: KeyType,
    ) -> Self {
        EncryptedWallet {
            ows_version: 2,
            id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
            chain_type: None,
            accounts,
            crypto,
            key_type,
            metadata: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_wallet() -> EncryptedWallet {
        EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn test_serde_roundtrip() {
        let wallet = dummy_wallet();
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        let deserialized: EncryptedWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test-id");
        assert_eq!(deserialized.name, "test-wallet");
        assert_eq!(deserialized.ows_version, 2);
        assert!(deserialized.chain_type.is_none());
    }

    #[test]
    fn test_key_type_serde() {
        let json = serde_json::to_string(&KeyType::Mnemonic).unwrap();
        assert_eq!(json, "\"mnemonic\"");
        let json = serde_json::to_string(&KeyType::PrivateKey).unwrap();
        assert_eq!(json, "\"private_key\"");
    }

    #[test]
    fn test_v2_no_chain_type_field() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(
            json.get("chain_type").is_none(),
            "v2 wallets should not serialize chain_type"
        );
    }

    #[test]
    fn test_matches_spec_format() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        for key in [
            "ows_version",
            "id",
            "name",
            "created_at",
            "accounts",
            "crypto",
            "key_type",
        ] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
    }

    #[test]
    fn test_metadata_omitted_when_null() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn test_v1_backward_compat() {
        // Simulate a v1 wallet JSON with chain_type field
        let v1_json = serde_json::json!({
            "lws_version": 1,
            "id": "old-id",
            "name": "old-wallet",
            "created_at": "2024-01-01T00:00:00Z",
            "chain_type": "evm",
            "accounts": [{
                "account_id": "eip155:1:0xabc",
                "address": "0xabc",
                "chain_id": "eip155:1",
                "derivation_path": "m/44'/60'/0'/0/0"
            }],
            "crypto": {"cipher": "aes-256-gcm"},
            "key_type": "mnemonic"
        });
        let wallet: EncryptedWallet = serde_json::from_value(v1_json).unwrap();
        assert_eq!(wallet.ows_version, 1);
        assert_eq!(wallet.chain_type, Some(ChainType::Evm));
    }
}
