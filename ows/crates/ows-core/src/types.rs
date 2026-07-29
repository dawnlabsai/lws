use serde::{Deserialize, Serialize};

/// A token balance for a wallet address, normalized across chains and providers.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TokenBalance {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub chain: String,
    pub decimals: u32,
    pub balance: BalanceInfo,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BalanceInfo {
    pub amount: f64,
    /// Fiat value when known (e.g. MoonPay). Absent for chains without pricing (e.g. Cardano via Koios).
    #[serde(default)]
    pub value: Option<f64>,
    /// Spot price when known. Absent for chains without pricing.
    #[serde(default)]
    pub price: Option<f64>,
}

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

impl Default for WalletId {
    fn default() -> Self {
        WalletId(uuid::Uuid::new_v4().to_string())
    }
}

impl WalletId {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_generates_uuid() {
        let id = WalletId::new();
        assert!(!id.0.is_empty());
        assert!(uuid::Uuid::parse_str(&id.0).is_ok());
    }

    #[test]
    fn test_wallet_id_serde() {
        let id = WalletId("test-id".to_string());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
        let id2: WalletId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }
}
