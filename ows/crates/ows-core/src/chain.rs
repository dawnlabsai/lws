use crate::caip::ChainId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Tron,
    Ton,
    Spark,
    Filecoin,
    Sui,
    Xrpl,
    Nano,
    Near,
}

/// All supported chain families, used for universal wallet derivation.
pub const ALL_CHAIN_TYPES: [ChainType; 12] = [
    ChainType::Evm,
    ChainType::Solana,
    ChainType::Bitcoin,
    ChainType::Cosmos,
    ChainType::Tron,
    ChainType::Ton,
    ChainType::Spark,
    ChainType::Filecoin,
    ChainType::Sui,
    ChainType::Xrpl,
    ChainType::Nano,
    ChainType::Near,
];

/// A specific chain (e.g. "ethereum", "arbitrum") with its family type and CAIP-2 ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub name: &'static str,
    pub chain_type: ChainType,
    pub chain_id: &'static str,
}

impl Chain {
    /// Return the EIP-155 reference portion of this chain's CAIP-2 ID.
    pub fn evm_chain_reference(&self) -> Result<&str, String> {
        if self.chain_type != ChainType::Evm {
            return Err(format!("chain '{}' is not an EVM chain", self.chain_id));
        }

        let chain_id = self
            .chain_id
            .parse::<ChainId>()
            .map_err(|e| e.to_string())?;
        if chain_id.namespace != "eip155" {
            return Err(format!(
                "EVM chain '{}' is missing an eip155 reference",
                self.chain_id
            ));
        }

        self.chain_id
            .split_once(':')
            .map(|(_, reference)| reference)
            .ok_or_else(|| format!("invalid CAIP-2 chain ID: '{}'", self.chain_id))
    }

    /// Return the numeric EIP-155 chain ID for an EVM chain.
    pub fn evm_chain_id_u64(&self) -> Result<u64, String> {
        self.evm_chain_reference()?
            .parse()
            .map_err(|_| format!("cannot extract numeric chain ID from: {}", self.chain_id))
    }
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
    Chain {
        name: "ethereum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:1",
    },
    Chain {
        name: "polygon",
        chain_type: ChainType::Evm,
        chain_id: "eip155:137",
    },
    Chain {
        name: "arbitrum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:42161",
    },
    Chain {
        name: "optimism",
        chain_type: ChainType::Evm,
        chain_id: "eip155:10",
    },
    Chain {
        name: "base",
        chain_type: ChainType::Evm,
        chain_id: "eip155:8453",
    },
    Chain {
        name: "plasma",
        chain_type: ChainType::Evm,
        chain_id: "eip155:9745",
    },
    Chain {
        name: "bsc",
        chain_type: ChainType::Evm,
        chain_id: "eip155:56",
    },
    Chain {
        name: "avalanche",
        chain_type: ChainType::Evm,
        chain_id: "eip155:43114",
    },
    Chain {
        name: "etherlink",
        chain_type: ChainType::Evm,
        chain_id: "eip155:42793",
    },
    Chain {
        name: "solana",
        chain_type: ChainType::Solana,
        chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    },
    Chain {
        name: "bitcoin",
        chain_type: ChainType::Bitcoin,
        chain_id: "bip122:000000000019d6689c085ae165831e93",
    },
    Chain {
        name: "cosmos",
        chain_type: ChainType::Cosmos,
        chain_id: "cosmos:cosmoshub-4",
    },
    Chain {
        name: "tron",
        chain_type: ChainType::Tron,
        chain_id: "tron:mainnet",
    },
    Chain {
        name: "ton",
        chain_type: ChainType::Ton,
        chain_id: "ton:mainnet",
    },
    Chain {
        name: "spark",
        chain_type: ChainType::Spark,
        chain_id: "spark:mainnet",
    },
    Chain {
        name: "filecoin",
        chain_type: ChainType::Filecoin,
        chain_id: "fil:mainnet",
    },
    Chain {
        name: "sui",
        chain_type: ChainType::Sui,
        chain_id: "sui:mainnet",
    },
    Chain {
        name: "xrpl",
        chain_type: ChainType::Xrpl,
        chain_id: "xrpl:mainnet",
    },
    Chain {
        name: "xrpl-testnet",
        chain_type: ChainType::Xrpl,
        chain_id: "xrpl:testnet",
    },
    Chain {
        name: "xrpl-devnet",
        chain_type: ChainType::Xrpl,
        chain_id: "xrpl:devnet",
    },
    Chain {
        name: "nano",
        chain_type: ChainType::Nano,
        chain_id: "nano:mainnet",
    },
    Chain {
        name: "near",
        chain_type: ChainType::Near,
        chain_id: "near:mainnet",
    },
    Chain {
        name: "near-testnet",
        chain_type: ChainType::Near,
        chain_id: "near:testnet",
    },
    Chain {
        name: "tempo",
        chain_type: ChainType::Evm,
        chain_id: "eip155:4217",
    },
    Chain {
        name: "hyperliquid",
        chain_type: ChainType::Evm,
        chain_id: "eip155:999",
    },
    // EVM testnets
    Chain {
        name: "sepolia",
        chain_type: ChainType::Evm,
        chain_id: "eip155:11155111",
    },
    Chain {
        name: "base-sepolia",
        chain_type: ChainType::Evm,
        chain_id: "eip155:84532",
    },
    Chain {
        name: "arbitrum-sepolia",
        chain_type: ChainType::Evm,
        chain_id: "eip155:421614",
    },
    Chain {
        name: "optimism-sepolia",
        chain_type: ChainType::Evm,
        chain_id: "eip155:11155420",
    },
    Chain {
        name: "polygon-amoy",
        chain_type: ChainType::Evm,
        chain_id: "eip155:80002",
    },
];

/// Parse a chain string into a `Chain`. Accepts:
/// - Friendly names: "ethereum", "base", "arbitrum", "solana", etc.
/// - CAIP-2 chain IDs: "eip155:1", "eip155:8453", etc.
/// - Bare numeric EVM chain IDs: "8453" → eip155:8453
/// - Legacy "evm" (deprecated, warns on stderr, resolves to ethereum)
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_lowercase();

    // Legacy "evm" — deprecated, warn and resolve
    if lower == "evm" {
        eprintln!(
            "warning: '--chain evm' is deprecated; use '--chain ethereum' \
             or a specific chain name (base, arbitrum, polygon, ...)"
        );
        return Ok(*KNOWN_CHAINS.iter().find(|c| c.name == "ethereum").unwrap());
    }

    // Try friendly name match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lower) {
        return Ok(*chain);
    }

    // Try CAIP-2 chain ID match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(*chain);
    }

    // Bare numeric → treat as EVM chain ID (eip155:<n>)
    if !lower.is_empty() && lower.chars().all(|c| c.is_ascii_digit()) {
        let caip2 = format!("eip155:{}", lower);
        if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == caip2) {
            return Ok(*chain);
        }
        let leaked: &'static str = Box::leak(caip2.into_boxed_str());
        return Ok(Chain {
            name: leaked,
            chain_type: ChainType::Evm,
            chain_id: leaked,
        });
    }

    // Try namespace match for unknown CAIP-2 IDs (e.g. eip155:4217, eip155:84532).
    // Uses the same signer as the namespace's default chain. The chain_id string is
    // leaked to satisfy the 'static lifetime — acceptable since parse_chain is called
    // with a small, bounded set of user-supplied chain identifiers.
    if let Some((namespace, _reference)) = s.split_once(':') {
        if let Some(ct) = ChainType::from_namespace(namespace) {
            let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
            return Ok(Chain {
                name: leaked,
                chain_type: ct,
                chain_id: leaked,
            });
        }
    }

    Err(format!(
        "unknown chain: '{s}'\n\n\
         Supported chains:\n  \
           EVM:     ethereum, base, arbitrum, optimism, polygon, bsc, avalanche, plasma, etherlink\n  \
           Solana:  solana\n  \
           Bitcoin: bitcoin\n  \
           Other:   cosmos, tron, ton, sui, filecoin, spark, xrpl, nano, near\n\n\
         Or use a CAIP-2 ID (eip155:8453) or bare EVM chain ID (8453)"
    ))
}

/// Returns the default `Chain` for a given `ChainType` (first match in registry).
pub fn default_chain_for_type(ct: ChainType) -> Chain {
    *KNOWN_CHAINS.iter().find(|c| c.chain_type == ct).unwrap()
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    pub fn namespace(&self) -> &'static str {
        match self {
            ChainType::Evm => "eip155",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bip122",
            ChainType::Tron => "tron",
            ChainType::Ton => "ton",
            ChainType::Spark => "spark",
            ChainType::Filecoin => "fil",
            ChainType::Sui => "sui",
            ChainType::Xrpl => "xrpl",
            ChainType::Nano => "nano",
            ChainType::Near => "near",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    pub fn default_coin_type(&self) -> u32 {
        match self {
            ChainType::Evm => 60,
            ChainType::Solana => 501,
            ChainType::Cosmos => 118,
            ChainType::Bitcoin => 0,
            ChainType::Tron => 195,
            ChainType::Ton => 607,
            ChainType::Spark => 8797555,
            ChainType::Filecoin => 461,
            ChainType::Sui => 784,
            ChainType::Xrpl => 144,
            ChainType::Nano => 165,
            ChainType::Near => 397,
        }
    }

    /// Returns the ChainType for a given CAIP-2 namespace.
    pub fn from_namespace(ns: &str) -> Option<ChainType> {
        match ns {
            "eip155" => Some(ChainType::Evm),
            "solana" => Some(ChainType::Solana),
            "cosmos" => Some(ChainType::Cosmos),
            "bip122" => Some(ChainType::Bitcoin),
            "tron" => Some(ChainType::Tron),
            "ton" => Some(ChainType::Ton),
            "spark" => Some(ChainType::Spark),
            "fil" => Some(ChainType::Filecoin),
            "sui" => Some(ChainType::Sui),
            "xrpl" => Some(ChainType::Xrpl),
            "nano" => Some(ChainType::Nano),
            "near" => Some(ChainType::Near),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ChainType::Evm => "evm",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bitcoin",
            ChainType::Tron => "tron",
            ChainType::Ton => "ton",
            ChainType::Spark => "spark",
            ChainType::Filecoin => "filecoin",
            ChainType::Sui => "sui",
            ChainType::Xrpl => "xrpl",
            ChainType::Nano => "nano",
            ChainType::Near => "near",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(ChainType::Evm),
            "solana" => Ok(ChainType::Solana),
            "cosmos" => Ok(ChainType::Cosmos),
            "bitcoin" => Ok(ChainType::Bitcoin),
            "tron" => Ok(ChainType::Tron),
            "ton" => Ok(ChainType::Ton),
            "spark" => Ok(ChainType::Spark),
            "filecoin" => Ok(ChainType::Filecoin),
            "sui" => Ok(ChainType::Sui),
            "xrpl" => Ok(ChainType::Xrpl),
            "nano" => Ok(ChainType::Nano),
            "near" => Ok(ChainType::Near),
            _ => Err(format!("unknown chain type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip() {
        let chain = ChainType::Evm;
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, "\"evm\"");
        let chain2: ChainType = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_serde_all_variants() {
        for (chain, expected) in [
            (ChainType::Evm, "\"evm\""),
            (ChainType::Solana, "\"solana\""),
            (ChainType::Cosmos, "\"cosmos\""),
            (ChainType::Bitcoin, "\"bitcoin\""),
            (ChainType::Tron, "\"tron\""),
            (ChainType::Ton, "\"ton\""),
            (ChainType::Spark, "\"spark\""),
            (ChainType::Filecoin, "\"filecoin\""),
            (ChainType::Sui, "\"sui\""),
            (ChainType::Xrpl, "\"xrpl\""),
            (ChainType::Nano, "\"nano\""),
            (ChainType::Near, "\"near\""),
        ] {
            let json = serde_json::to_string(&chain).unwrap();
            assert_eq!(json, expected);
            let deserialized: ChainType = serde_json::from_str(&json).unwrap();
            assert_eq!(chain, deserialized);
        }
    }

    #[test]
    fn test_namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Cosmos.namespace(), "cosmos");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
        assert_eq!(ChainType::Tron.namespace(), "tron");
        assert_eq!(ChainType::Ton.namespace(), "ton");
        assert_eq!(ChainType::Spark.namespace(), "spark");
        assert_eq!(ChainType::Filecoin.namespace(), "fil");
        assert_eq!(ChainType::Sui.namespace(), "sui");
        assert_eq!(ChainType::Xrpl.namespace(), "xrpl");
        assert_eq!(ChainType::Nano.namespace(), "nano");
        assert_eq!(ChainType::Near.namespace(), "near");
    }

    #[test]
    fn test_coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Cosmos.default_coin_type(), 118);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
        assert_eq!(ChainType::Tron.default_coin_type(), 195);
        assert_eq!(ChainType::Ton.default_coin_type(), 607);
        assert_eq!(ChainType::Spark.default_coin_type(), 8797555);
        assert_eq!(ChainType::Filecoin.default_coin_type(), 461);
        assert_eq!(ChainType::Sui.default_coin_type(), 784);
        assert_eq!(ChainType::Xrpl.default_coin_type(), 144);
        assert_eq!(ChainType::Nano.default_coin_type(), 165);
        assert_eq!(ChainType::Near.default_coin_type(), 397);
    }

    #[test]
    fn test_from_namespace() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("cosmos"), Some(ChainType::Cosmos));
        assert_eq!(
            ChainType::from_namespace("bip122"),
            Some(ChainType::Bitcoin)
        );
        assert_eq!(ChainType::from_namespace("tron"), Some(ChainType::Tron));
        assert_eq!(ChainType::from_namespace("ton"), Some(ChainType::Ton));
        assert_eq!(ChainType::from_namespace("spark"), Some(ChainType::Spark));
        assert_eq!(ChainType::from_namespace("fil"), Some(ChainType::Filecoin));
        assert_eq!(ChainType::from_namespace("sui"), Some(ChainType::Sui));
        assert_eq!(ChainType::from_namespace("xrpl"), Some(ChainType::Xrpl));
        assert_eq!(ChainType::from_namespace("nano"), Some(ChainType::Nano));
        assert_eq!(ChainType::from_namespace("near"), Some(ChainType::Near));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn test_from_str() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
    }

    #[test]
    fn test_parse_chain_friendly_name() {
        let chain = parse_chain("ethereum").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:1");
    }

    #[test]
    fn test_parse_chain_plasma_alias() {
        let chain = parse_chain("plasma").unwrap();
        assert_eq!(chain.name, "plasma");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9745");
    }

    #[test]
    fn test_parse_chain_etherlink_alias() {
        let chain = parse_chain("etherlink").unwrap();
        assert_eq!(chain.name, "etherlink");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:42793");
    }

    #[test]
    fn test_parse_chain_caip2() {
        let chain = parse_chain("eip155:42161").unwrap();
        assert_eq!(chain.name, "arbitrum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_plasma_caip2() {
        let chain = parse_chain("eip155:9745").unwrap();
        assert_eq!(chain.name, "plasma");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9745");
    }

    #[test]
    fn test_parse_chain_unknown_evm_caip2() {
        let chain = parse_chain("eip155:9746").unwrap();
        assert_eq!(chain.name, "eip155:9746");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:9746");
    }

    #[test]
    fn test_evm_chain_reference_for_known_chain() {
        let chain = parse_chain("base").unwrap();
        assert_eq!(chain.evm_chain_reference().unwrap(), "8453");
        assert_eq!(chain.evm_chain_id_u64().unwrap(), 8453);
    }

    #[test]
    fn test_evm_chain_reference_for_unknown_caip2_chain() {
        let chain = parse_chain("eip155:999999").unwrap();
        assert_eq!(chain.evm_chain_reference().unwrap(), "999999");
        assert_eq!(chain.evm_chain_id_u64().unwrap(), 999999);
    }

    #[test]
    fn test_evm_chain_reference_rejects_non_evm_chain() {
        let chain = parse_chain("solana").unwrap();
        let err = chain.evm_chain_reference().unwrap_err();
        assert!(err.contains("not an EVM chain"));
    }

    #[test]
    fn test_parse_chain_legacy_evm() {
        let chain = parse_chain("evm").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_solana() {
        let chain = parse_chain("solana").unwrap();
        assert_eq!(chain.chain_type, ChainType::Solana);
    }

    #[test]
    fn test_parse_chain_xrpl() {
        let chain = parse_chain("xrpl").unwrap();
        assert_eq!(chain.chain_type, ChainType::Xrpl);
        assert_eq!(chain.chain_id, "xrpl:mainnet");

        let testnet = parse_chain("xrpl-testnet").unwrap();
        assert_eq!(testnet.chain_type, ChainType::Xrpl);
        assert_eq!(testnet.chain_id, "xrpl:testnet");

        let devnet = parse_chain("xrpl-devnet").unwrap();
        assert_eq!(devnet.chain_type, ChainType::Xrpl);
        assert_eq!(devnet.chain_id, "xrpl:devnet");

        // CAIP-2 IDs also accepted directly
        let via_caip2 = parse_chain("xrpl:testnet").unwrap();
        assert_eq!(via_caip2.chain_type, ChainType::Xrpl);
        assert_eq!(via_caip2.chain_id, "xrpl:testnet");
    }

    #[test]
    fn test_parse_chain_bare_numeric_known() {
        // "8453" → Base (eip155:8453)
        let chain = parse_chain("8453").unwrap();
        assert_eq!(chain.name, "base");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:8453");
    }

    #[test]
    fn test_parse_chain_bare_numeric_mainnet() {
        let chain = parse_chain("1").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_id, "eip155:1");
    }

    #[test]
    fn test_parse_chain_bare_numeric_unknown() {
        // Unknown EVM chain ID still resolves
        let chain = parse_chain("99999").unwrap();
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:99999");
    }

    #[test]
    fn test_parse_chain_unknown() {
        assert!(parse_chain("unknown_chain").is_err());
    }

    #[test]
    fn test_parse_chain_tempo_alias() {
        let chain = parse_chain("tempo").unwrap();
        assert_eq!(chain.name, "tempo");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:4217");
    }

    #[test]
    fn test_parse_chain_tempo_caip2() {
        let chain = parse_chain("eip155:4217").unwrap();
        assert_eq!(chain.name, "tempo");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:4217");
    }

    #[test]
    fn test_parse_chain_hyperliquid_alias() {
        let chain = parse_chain("hyperliquid").unwrap();
        assert_eq!(chain.name, "hyperliquid");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:999");
    }

    #[test]
    fn test_parse_chain_hyperliquid_caip2() {
        let chain = parse_chain("eip155:999").unwrap();
        assert_eq!(chain.name, "hyperliquid");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:999");
    }

    #[test]
    fn test_all_chain_types() {
        assert_eq!(ALL_CHAIN_TYPES.len(), 12);
    }

    #[test]
    fn test_parse_chain_near() {
        let chain = parse_chain("near").unwrap();
        assert_eq!(chain.name, "near");
        assert_eq!(chain.chain_type, ChainType::Near);
        assert_eq!(chain.chain_id, "near:mainnet");

        let testnet = parse_chain("near-testnet").unwrap();
        assert_eq!(testnet.chain_type, ChainType::Near);
        assert_eq!(testnet.chain_id, "near:testnet");

        // CAIP-2 IDs accepted directly
        let via_caip2 = parse_chain("near:testnet").unwrap();
        assert_eq!(via_caip2.chain_type, ChainType::Near);
        assert_eq!(via_caip2.chain_id, "near:testnet");
    }

    #[test]
    fn test_default_chain_for_type() {
        let chain = default_chain_for_type(ChainType::Evm);
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_id, "eip155:1");
    }
    #[test]
    fn parse_base_sepolia_by_name() {
        let chain = parse_chain("base-sepolia").unwrap();
        assert_eq!(chain.chain_id, "eip155:84532");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_sepolia_by_name() {
        let chain = parse_chain("sepolia").unwrap();
        assert_eq!(chain.chain_id, "eip155:11155111");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_arbitrum_sepolia_by_name() {
        let chain = parse_chain("arbitrum-sepolia").unwrap();
        assert_eq!(chain.chain_id, "eip155:421614");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_optimism_sepolia_by_name() {
        let chain = parse_chain("optimism-sepolia").unwrap();
        assert_eq!(chain.chain_id, "eip155:11155420");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_polygon_amoy_by_name() {
        let chain = parse_chain("polygon-amoy").unwrap();
        assert_eq!(chain.chain_id, "eip155:80002");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn parse_base_sepolia_by_caip2() {
        let chain = parse_chain("eip155:84532").unwrap();
        assert_eq!(chain.chain_id, "eip155:84532");
    }

    #[test]
    fn parse_base_sepolia_by_chain_id() {
        let chain = parse_chain("84532").unwrap();
        assert_eq!(chain.chain_id, "eip155:84532");
    }
}
