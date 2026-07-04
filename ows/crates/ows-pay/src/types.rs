use serde::{Deserialize, Serialize};

// ===========================================================================
// Unified public types
// ===========================================================================

/// Which payment protocol was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    X402,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::X402 => write!(f, "x402"),
        }
    }
}

/// Details about a payment that was made.
#[derive(Debug, Clone)]
pub struct PaymentInfo {
    /// Human-readable amount (e.g. "$0.01").
    pub amount: String,
    /// Network/chain name (e.g. "Base", "Tempo").
    pub network: String,
    /// Token symbol (e.g. "USDC").
    pub token: String,
}

/// Result of a `pay()` call.
#[derive(Debug, Clone)]
pub struct PayResult {
    /// Which protocol handled the payment.
    pub protocol: Protocol,
    /// HTTP status of the final response.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// Payment details. `None` if no payment was required (non-402).
    pub payment: Option<PaymentInfo>,
}

/// A discovered payable service, normalized across protocols.
#[derive(Debug, Clone)]
pub struct Service {
    /// Protocol this service uses.
    pub protocol: Protocol,
    /// Human-readable name.
    pub name: String,
    /// Full endpoint URL.
    pub url: String,
    /// Short description.
    pub description: String,
    /// Cheapest price display (e.g. "$0.01", "free").
    pub price: String,
    /// Network or chain (e.g. "base", "Tempo").
    pub network: String,
    /// Categories / tags.
    pub tags: Vec<String>,
}

/// Result of a `discover()` call, including pagination info.
#[derive(Debug, Clone)]
pub struct DiscoverResult {
    /// Discovered services on this page.
    pub services: Vec<Service>,
    /// Total number of services in the directory.
    pub total: u64,
    /// Limit used for this page.
    pub limit: u64,
    /// Offset used for this page.
    pub offset: u64,
}

// ===========================================================================
// x402 wire types (internal, used by x402 module)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    #[serde(alias = "maxAmountRequired")]
    pub amount: String,
    pub asset: String,
    #[serde(alias = "payTo")]
    pub pay_to: String,
    #[serde(default = "default_timeout")]
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "is_json_null")]
    pub extra: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

fn is_json_null(value: &serde_json::Value) -> bool {
    value.is_null()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Response {
    #[serde(default)]
    pub x402_version: Option<u32>,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// The signed payment payload sent to the server in the payment header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentPayload {
    V1(PaymentPayloadV1),
    V2(PaymentPayloadV2),
}

/// x402 v1 payment payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayloadV1 {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: serde_json::Value,
}

/// x402 v2 payment payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayloadV2 {
    pub x402_version: u32,
    pub accepted: PaymentRequirements,
    pub resource: Option<serde_json::Value>,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3009Payload {
    pub signature: String,
    pub authorization: Eip3009Authorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip3009Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

// ===========================================================================
// x402 discovery wire types
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredService {
    pub resource: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub x402_version: Option<u32>,
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    pub metadata: Option<ServiceMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    pub description: Option<String>,
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub output: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub items: Vec<DiscoveredService>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: u64,
    pub offset: u64,
    pub total: u64,
}

// ===========================================================================
// MoonPay wire types
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct MoonPayDepositRequest {
    pub name: String,
    pub wallet: String,
    pub chain: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoonPayDepositResponse {
    pub id: String,
    pub destination_wallet: String,
    pub destination_chain: String,
    pub customer_token: String,
    pub deposit_url: String,
    pub wallets: Vec<DepositWallet>,
    pub instructions: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositWallet {
    pub address: String,
    pub chain: String,
    pub qr_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoonPayBalanceRequest {
    pub wallet: String,
    pub chain: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MoonPayBalanceResponse {
    pub items: Vec<TokenBalance>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenBalance {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub chain: String,
    pub decimals: u32,
    pub balance: BalanceInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceInfo {
    pub amount: f64,
    pub value: f64,
    pub price: f64,
}

/// Result of `ows fund`.
#[derive(Debug, Clone)]
pub struct FundResult {
    pub deposit_id: String,
    pub deposit_url: String,
    pub wallets: Vec<(String, String)>,
    pub instructions: String,
}
