use ows_core::{parse_chain, ChainType};

use crate::cardano::get_cardano_balances;
use crate::error::{PayError, PayErrorCode};
use crate::types::{
    FundResult, MoonPayBalanceRequest, MoonPayBalanceResponse, MoonPayDepositRequest,
    MoonPayDepositResponse, TokenBalance,
};

const MOONPAY_API: &str = "https://agents.moonpay.com";

/// MoonPay-specific chain mapping. This is separate from the protocol-level
/// CAIP-2 utilities because MoonPay has its own chain name scheme.
/// MoonPay expects the BNB Chain funding slug to be `bnb`, while OWS uses `bsc` as the canonical chain name.
#[derive(Debug)]
struct MoonPayChain {
    display_name: &'static str,
    moonpay_name: &'static str,
}

const MOONPAY_CHAINS: &[(&str, MoonPayChain)] = &[
    (
        "base",
        MoonPayChain {
            display_name: "Base",
            moonpay_name: "base",
        },
    ),
    (
        "ethereum",
        MoonPayChain {
            display_name: "Ethereum",
            moonpay_name: "ethereum",
        },
    ),
    (
        "polygon",
        MoonPayChain {
            display_name: "Polygon",
            moonpay_name: "polygon",
        },
    ),
    (
        "arbitrum",
        MoonPayChain {
            display_name: "Arbitrum",
            moonpay_name: "arbitrum",
        },
    ),
    (
        "optimism",
        MoonPayChain {
            display_name: "Optimism",
            moonpay_name: "optimism",
        },
    ),
    (
        "bsc",
        MoonPayChain {
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "bnb",
        MoonPayChain {
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "base-sepolia",
        MoonPayChain {
            display_name: "Base Sepolia",
            moonpay_name: "base-sepolia",
        },
    ),
    (
        "solana",
        MoonPayChain {
            display_name: "Solana",
            moonpay_name: "solana",
        },
    ),
];

const DEFAULT_MOONPAY_CHAIN: &MoonPayChain = &MoonPayChain {
    display_name: "Base",
    moonpay_name: "base",
};

fn resolve_moonpay_chain(chain: Option<&str>) -> Result<&'static MoonPayChain, PayError> {
    match chain {
        Some(name) => {
            let lower = name.to_lowercase();
            MOONPAY_CHAINS
                .iter()
                .find(|(k, _)| *k == lower)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    PayError::new(
                        PayErrorCode::UnsupportedChain,
                        format!("unknown chain for funding: {name}"),
                    )
                })
        }
        None => Ok(DEFAULT_MOONPAY_CHAIN),
    }
}

/// Create a MoonPay deposit that auto-converts incoming crypto to USDC.
pub async fn fund(
    wallet_address: &str,
    chain: Option<&str>,
    token: Option<&str>,
) -> Result<FundResult, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;
    let token = token.unwrap_or("USDC");

    let client = reqwest::Client::new();
    let req = MoonPayDepositRequest {
        name: format!("OWS deposit ({token} on {})", mapping.display_name),
        wallet: wallet_address.to_string(),
        chain: mapping.moonpay_name.to_string(),
        token: token.to_string(),
    };

    let resp = client
        .post(format!("{MOONPAY_API}/api/tools/deposit_create"))
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay returned {status}: {body}"),
        ));
    }

    let deposit: MoonPayDepositResponse = resp.json().await?;

    Ok(FundResult {
        deposit_id: deposit.id,
        deposit_url: deposit.deposit_url,
        wallets: deposit
            .wallets
            .iter()
            .map(|w| (w.chain.clone(), w.address.clone()))
            .collect(),
        instructions: deposit.instructions,
    })
}

/// Check token balances for a wallet address via MoonPay.
/// If the chain is Cardano, rpc+url is required and it's used to fetch the token balances instead of MoonPay.
pub async fn get_balances(
    wallet_address: &str,
    chain: Option<&str>,
    rpc_url: Option<&str>,
) -> Result<Vec<TokenBalance>, PayError> {
    if let Some(c) = chain {
        let chain = parse_chain(c).map_err(|e| {
            PayError::new(
                PayErrorCode::UnsupportedChain,
                format!("unknown chain: {e}"),
            )
        })?;

        if chain.chain_type == ChainType::Cardano {
            let rpc_url = rpc_url.map_or_else(
                || {
                    Err(PayError::new(
                        PayErrorCode::InvalidInput,
                        "RPC URL is required for Cardano",
                    ))
                },
                Ok,
            )?;

            return get_cardano_balances(wallet_address, rpc_url).await;
        }
    }

    let mapping = resolve_moonpay_chain(chain)?;
    let client = reqwest::Client::new();

    let req = MoonPayBalanceRequest {
        wallet: wallet_address.to_string(),
        chain: mapping.moonpay_name.to_string(),
    };

    let resp = client
        .post(format!("{MOONPAY_API}/api/tools/token_balance_list"))
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay balance returned {status}: {body}"),
        ));
    }

    let balance_resp: MoonPayBalanceResponse = resp.json().await?;
    Ok(balance_resp.items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_bsc_to_bnb() {
        let chain = resolve_moonpay_chain(Some("bsc")).unwrap();
        assert_eq!(chain.display_name, "BNB Chain");
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_bnb_alias() {
        let chain = resolve_moonpay_chain(Some("bnb")).unwrap();
        assert_eq!(chain.display_name, "BNB Chain");
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_chain_is_case_insensitive() {
        let chain = resolve_moonpay_chain(Some("BnB")).unwrap();
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_unknown_chain_errors() {
        let err = resolve_moonpay_chain(Some("unknown")).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn resolve_defaults_to_base() {
        let chain = resolve_moonpay_chain(None).unwrap();
        assert_eq!(chain.display_name, "Base");
        assert_eq!(chain.moonpay_name, "base");
    }
}
