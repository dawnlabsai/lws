/// Thin helpers around `ows_core` for the payment layer.
///
/// All chain knowledge lives in `ows_core`. These are convenience
/// wrappers for the specific lookups the payment flow needs.
use ows_core::ChainType;

/// Resolve a network string to a `ChainType`.
///
/// Handles CAIP-2 IDs (`"eip155:8453"`), known names (`"base"`),
/// and unknown CAIP-2 IDs for known namespaces (`"eip155:999999"` → Evm).
pub fn resolve_chain_type(network: &str) -> Option<ChainType> {
    // Fast path: known chain name or CAIP-2 ID.
    if let Ok(chain) = ows_core::parse_chain(network) {
        return Some(chain.chain_type);
    }
    // Fallback: extract namespace from CAIP-2 for unregistered chains.
    let ns = network.split(':').next()?;
    ChainType::from_namespace(ns)
}

/// Human-readable name for a network. Falls back to the raw string.
pub fn display_name(network: &str) -> &str {
    if let Ok(chain) = ows_core::parse_chain(network) {
        return chain.name;
    }
    network
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_name() {
        assert_eq!(resolve_chain_type("base"), Some(ChainType::Evm));
        assert_eq!(resolve_chain_type("solana"), Some(ChainType::Solana));
        assert_eq!(resolve_chain_type("bitcoin"), Some(ChainType::Bitcoin));
    }

    #[test]
    fn resolve_known_caip2() {
        assert_eq!(resolve_chain_type("eip155:8453"), Some(ChainType::Evm));
        assert_eq!(
            resolve_chain_type("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            Some(ChainType::Solana)
        );
    }

    #[test]
    fn resolve_monad_name() {
        assert_eq!(resolve_chain_type("monad"), Some(ChainType::Evm));
    }

    #[test]
    fn resolve_monad_caip2() {
        assert_eq!(resolve_chain_type("eip155:143"), Some(ChainType::Evm));
    }

    #[test]
    fn display_monad() {
        assert_eq!(display_name("monad"), "monad");
        assert_eq!(display_name("eip155:143"), "monad");
    }

    #[test]
    fn resolve_unknown_caip2_known_namespace() {
        // Chain not in KNOWN_CHAINS but namespace is recognized.
        assert_eq!(resolve_chain_type("eip155:999999"), Some(ChainType::Evm));
    }

    #[test]
    fn resolve_unknown_namespace() {
        assert_eq!(resolve_chain_type("foochain:1"), None);
    }

    #[test]
    fn resolve_bare_unknown() {
        assert_eq!(resolve_chain_type("foochain"), None);
    }

    #[test]
    fn display_known() {
        assert_eq!(display_name("base"), "base");
        assert_eq!(display_name("eip155:8453"), "base");
    }

    #[test]
    fn display_unknown_passthrough() {
        assert_eq!(display_name("eip155:999999"), "eip155:999999");
    }
}
