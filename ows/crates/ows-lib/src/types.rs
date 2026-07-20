use serde::{Deserialize, Serialize};

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

/// Result from a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}
