//! Midnight integration — unshielded + shielded + dust indexer sync + `ows fund balance`.

/// Shielded balances keyed by the hex-encoded `ShieldedTokenType`.
pub type ShieldedBalances = std::collections::BTreeMap<String, u128>;

mod async_runtime;
mod balance_tx;
mod cache_io;
mod dapp_connector;
mod fund_balance;
mod indexer_ws;
mod ledger_params;
mod midnight_env;
mod prover;
mod submit;
mod tip_verify;
mod urls;
mod wallet;
mod wallet_sync;

pub use async_runtime::block_on;
pub use balance_tx::balance_unsealed_proven_tx;
pub use dapp_connector::{
    classify_unsealed_payload, parse_balance_unsealed_json, BalanceUnsealedRequest, UnsealedKind,
};
pub use fund_balance::print_fund_balance;
pub use ledger_params::fetch_indexer_ledger_parameters;
pub use prover::Prover;
pub use submit::broadcast_sealed;
pub use wallet_sync::dust::{format_dust_specks, get_dust_balance_for_display};
pub use wallet_sync::shielded::get_shielded_balances_for_display;
pub use wallet_sync::unshielded::{get_unshielded_utxos_for_display, UnshieldedUtxo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Native,
    Custom([u8; 32]),
}

impl TokenType {
    pub fn to_wire_token_type(&self) -> String {
        match self {
            TokenType::Native => hex::encode([0u8; 32]),
            TokenType::Custom(b) => hex::encode(b),
        }
    }
}

pub fn parse_token_type(token: Option<&str>) -> Result<TokenType, std::io::Error> {
    let t = token.map(str::trim).unwrap_or("");
    if t.is_empty() || t.eq_ignore_ascii_case("native") || t.eq_ignore_ascii_case("night") {
        return Ok(TokenType::Native);
    }
    let hex_s = t.strip_prefix("0x").unwrap_or(t);
    let bytes =
        hex::decode(hex_s).map_err(|e| std::io::Error::other(format!("invalid token hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(std::io::Error::other(format!(
            "token id must be 32 bytes, got {} bytes",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    if arr == [0u8; 32] {
        Ok(TokenType::Native)
    } else {
        Ok(TokenType::Custom(arr))
    }
}
