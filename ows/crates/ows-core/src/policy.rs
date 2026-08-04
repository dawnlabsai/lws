use serde::{Deserialize, Serialize};

/// Action taken when a policy rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Deny,
}

/// A declarative policy rule evaluated in-process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Deny if `chain_id` is not in the allowlist.
    AllowedChains { chain_ids: Vec<String> },

    /// Deny if current time is past the timestamp.
    ExpiresAt { timestamp: String },

    /// Deny typed data signing if `domain.verifyingContract` is not in the allowlist.
    /// Passes through for non-typed-data signing operations.
    AllowedTypedDataContracts { contracts: Vec<String> },
}

/// A stored policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub created_at: String,
    pub rules: Vec<PolicyRule>,
    /// Path to a custom executable policy program (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Opaque configuration passed to the executable (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    pub action: PolicyAction,
}

/// Context passed to policy evaluation (and to executable policies via stdin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub chain_id: String,
    pub wallet_id: String,
    pub api_key_id: String,
    /// Transaction-shaped context for the signing request. Present for
    /// `sign_transaction`, `sign_message`, and `sign_hash` (the latter two
    /// surface their payload through `raw_hex`). Omitted for `sign_typed_data`,
    /// which exposes its payload via [`TypedDataContext::raw_json`] instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionContext>,
    pub spending: SpendingContext,
    pub timestamp: String,
    /// EIP-712 typed data context (only present for `sign_typed_data` calls).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typed_data: Option<TypedDataContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionEffect {
    pub address: String,
    pub diff: Vec<(String, i64)>, // (asset, diff)
}

/// Signing-request fields available for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    pub effects: Vec<TransactionEffect>,
    /// Raw transaction hex.
    pub raw_hex: String,
    /// Calldata / input data (EVM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Carried in [`PolicyContext`] for executable policies (opaque JSON). Not used by built-in rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingContext {
    /// Reserved for future use / custom tooling.
    pub daily_total: String,
    /// Date string (YYYY-MM-DD).
    pub date: String,
}

/// EIP-712 typed data context for policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataContext {
    /// The `domain.verifyingContract` address (if present in the EIP-712 domain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,
    /// The `domain.chainId` (if present in the EIP-712 domain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_chain_id: Option<u64>,
    /// The EIP-712 `primaryType` (e.g. "Permit", "Order").
    pub primary_type: String,
    /// The `domain.name` (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    /// The `domain.version` (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_version: Option<String>,
    /// The full typed data JSON for executable policies to inspect.
    pub raw_json: String,
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub allow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Which policy produced the denial (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

impl PolicyResult {
    pub fn allowed() -> Self {
        Self {
            allow: true,
            reason: None,
            policy_id: None,
        }
    }

    pub fn denied(policy_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: Some(reason.into()),
            policy_id: Some(policy_id.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_rule_serde_allowed_chains() {
        let rule = PolicyRule::AllowedChains {
            chain_ids: vec!["eip155:8453".into(), "eip155:84532".into()],
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["type"], "allowed_chains");
        assert_eq!(json["chain_ids"][0], "eip155:8453");

        let deserialized: PolicyRule = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, rule);
    }

    #[test]
    fn test_policy_rule_serde_expires_at() {
        let rule = PolicyRule::ExpiresAt {
            timestamp: "2026-04-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["type"], "expires_at");
        assert_eq!(json["timestamp"], "2026-04-01T00:00:00Z");

        let deserialized: PolicyRule = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, rule);
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = Policy {
            id: "base-agent-limits".into(),
            name: "Base Agent Safety Limits".into(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".into(),
            rules: vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".into()],
                },
                PolicyRule::ExpiresAt {
                    timestamp: "2026-12-31T23:59:59Z".into(),
                },
            ],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "base-agent-limits");
        assert_eq!(deserialized.rules.len(), 2);
        assert!(deserialized.executable.is_none());
    }

    #[test]
    fn test_policy_with_executable() {
        let json = r#"{
            "id": "sim-policy",
            "name": "Simulation Policy",
            "version": 1,
            "created_at": "2026-03-22T10:00:00Z",
            "rules": [],
            "executable": "/usr/local/bin/simulate-tx",
            "config": {"rpc": "https://mainnet.base.org"},
            "action": "deny"
        }"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.executable.unwrap(), "/usr/local/bin/simulate-tx");
        assert!(policy.config.is_some());
    }

    #[test]
    fn test_policy_context_serde() {
        let ctx = PolicyContext {
            chain_id: "eip155:8453".into(),
            wallet_id: "3198bc9c-6672-5ab3-d995-4942343ae5b6".into(),
            api_key_id: "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c".into(),
            transaction: Some(TransactionContext {
                effects: vec![TransactionEffect {
                    address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".into(),
                    diff: vec![("ETH".into(), 100000000000000000)],
                }],
                raw_hex: "0x02f8...".into(),
                data: None,
            }),
            spending: SpendingContext {
                daily_total: "50000000000000000".into(),
                date: "2026-03-22".into(),
            },
            timestamp: "2026-03-22T10:35:22Z".into(),
            typed_data: None,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: PolicyContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.chain_id, "eip155:8453");
        assert_eq!(
            deserialized.transaction.unwrap().effects.first().unwrap(),
            &TransactionEffect {
                address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".into(),
                diff: vec![("ETH".into(), 100000000000000000)],
            }
        );
        // data was None, should be absent from serialized form
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_policy_result_allowed() {
        let result = PolicyResult::allowed();
        assert!(result.allow);
        assert!(result.reason.is_none());
        assert!(result.policy_id.is_none());

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["allow"], true);
        assert!(!json.as_object().unwrap().contains_key("reason"));
    }

    #[test]
    fn test_policy_result_denied() {
        let result = PolicyResult::denied(
            "spending-limit",
            "Daily spending limit exceeded: 0.95 / 1.0 ETH",
        );
        assert!(!result.allow);
        assert_eq!(
            result.reason.as_deref(),
            Some("Daily spending limit exceeded: 0.95 / 1.0 ETH")
        );
        assert_eq!(result.policy_id.as_deref(), Some("spending-limit"));
    }

    #[test]
    fn test_policy_action_serde() {
        let action = PolicyAction::Deny;
        let json = serde_json::to_value(&action).unwrap();
        assert_eq!(json, "deny");

        let deserialized: PolicyAction = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, PolicyAction::Deny);
    }

    #[test]
    fn test_typed_data_context_serde() {
        let ctx = TypedDataContext {
            verifying_contract: Some("0x000000000022D473030F116dDEE9F6B43aC78BA3".into()),
            domain_chain_id: Some(8453),
            primary_type: "PermitSingle".into(),
            domain_name: Some("Permit2".into()),
            domain_version: Some("1".into()),
            raw_json: r#"{"types":{},"primaryType":"PermitSingle","domain":{},"message":{}}"#
                .into(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: TypedDataContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.primary_type, "PermitSingle");
        assert_eq!(
            deserialized.verifying_contract.as_deref(),
            Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")
        );
        assert_eq!(deserialized.domain_chain_id, Some(8453));
    }

    #[test]
    fn test_typed_data_context_optional_fields_omitted() {
        let ctx = TypedDataContext {
            verifying_contract: None,
            domain_chain_id: None,
            primary_type: "Mail".into(),
            domain_name: None,
            domain_version: None,
            raw_json: "{}".into(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("verifying_contract"));
        assert!(!json.contains("domain_chain_id"));
        assert!(!json.contains("domain_name"));
        assert!(!json.contains("domain_version"));
    }

    #[test]
    fn test_policy_rule_serde_allowed_typed_data_contracts() {
        let rule = PolicyRule::AllowedTypedDataContracts {
            contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["type"], "allowed_typed_data_contracts");
        assert_eq!(
            json["contracts"][0],
            "0x000000000022D473030F116dDEE9F6B43aC78BA3"
        );

        let deserialized: PolicyRule = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, rule);
    }

    #[test]
    fn test_policy_context_typed_data_none_omitted() {
        let ctx = PolicyContext {
            chain_id: "eip155:8453".into(),
            wallet_id: "w".into(),
            api_key_id: "k".into(),
            transaction: Some(TransactionContext {
                effects: vec![],
                raw_hex: "0x00".into(),
                data: None,
            }),
            spending: SpendingContext {
                daily_total: "0".into(),
                date: "2026-03-30".into(),
            },
            timestamp: "2026-03-30T12:00:00Z".into(),
            typed_data: None,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("typed_data"));
    }

    #[test]
    fn test_policy_context_transaction_none_omitted() {
        let ctx = PolicyContext {
            chain_id: "eip155:8453".into(),
            wallet_id: "w".into(),
            api_key_id: "k".into(),
            transaction: None,
            spending: SpendingContext {
                daily_total: "0".into(),
                date: "2026-03-30".into(),
            },
            timestamp: "2026-03-30T12:00:00Z".into(),
            typed_data: None,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("transaction"));
    }
}
