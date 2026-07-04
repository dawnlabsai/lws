use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::path::PathBuf;

fn vault_path(p: Option<String>) -> Option<PathBuf> {
    p.map(PathBuf::from)
}

fn map_err(e: ows_lib::OwsLibError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// A single account within a wallet (one per chain family).
#[napi(object)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Wallet information returned by create/import/list/get operations.
#[napi(object)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

impl From<ows_lib::WalletInfo> for WalletInfo {
    fn from(w: ows_lib::WalletInfo) -> Self {
        WalletInfo {
            id: w.id,
            name: w.name,
            accounts: w
                .accounts
                .into_iter()
                .map(|a| AccountInfo {
                    chain_id: a.chain_id,
                    address: a.address,
                    derivation_path: a.derivation_path,
                })
                .collect(),
            created_at: w.created_at,
        }
    }
}

/// Result from a signing operation.
#[napi(object)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u32>,
}

/// Result from a sign-and-send operation.
#[napi(object)]
pub struct SendResult {
    pub tx_hash: String,
}

/// Generate a new BIP-39 mnemonic phrase.
#[napi]
pub fn generate_mnemonic(words: Option<u32>) -> Result<String> {
    ows_lib::generate_mnemonic(words.unwrap_or(12)).map_err(map_err)
}

/// Derive an address from a mnemonic for the given chain.
#[napi]
pub fn derive_address(mnemonic: String, chain: String, index: Option<u32>) -> Result<String> {
    ows_lib::derive_address(&mnemonic, &chain, index).map_err(map_err)
}

/// Create a new universal wallet (derives addresses for all chains).
#[napi]
pub fn create_wallet(
    name: String,
    passphrase: Option<String>,
    words: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::create_wallet(
        &name,
        words,
        passphrase.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// Import a wallet from a mnemonic phrase (derives addresses for all chains).
#[napi]
pub fn import_wallet_mnemonic(
    name: String,
    mnemonic: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_mnemonic(
        &name,
        &mnemonic,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// Import a wallet from a hex-encoded private key.
/// All 6 chains are supported: the provided key is used for its curve's chains,
/// and a random key is generated for the other curve.
/// The optional `chain` parameter specifies the key's source chain (e.g. "evm", "solana")
/// to determine which curve it uses. Defaults to "evm" (secp256k1).
///
/// Alternatively, provide explicit keys for each curve via `secp256k1Key` and `ed25519Key`.
/// When both are given, `privateKeyHex` and `chain` are ignored.
#[napi]
pub fn import_wallet_private_key(
    name: String,
    private_key_hex: String,
    passphrase: Option<String>,
    vault_path_opt: Option<String>,
    chain: Option<String>,
    secp256k1_key: Option<String>,
    ed25519_key: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_private_key(
        &name,
        &private_key_hex,
        chain.as_deref(),
        passphrase.as_deref(),
        vault_path(vault_path_opt).as_deref(),
        secp256k1_key.as_deref(),
        ed25519_key.as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// List all wallets in the vault.
#[napi]
pub fn list_wallets(vault_path_opt: Option<String>) -> Result<Vec<WalletInfo>> {
    ows_lib::list_wallets(vault_path(vault_path_opt).as_deref())
        .map(|ws| ws.into_iter().map(WalletInfo::from).collect())
        .map_err(map_err)
}

/// Get a single wallet by name or ID.
#[napi]
pub fn get_wallet(name_or_id: String, vault_path_opt: Option<String>) -> Result<WalletInfo> {
    ows_lib::get_wallet(&name_or_id, vault_path(vault_path_opt).as_deref())
        .map(WalletInfo::from)
        .map_err(map_err)
}

/// Delete a wallet from the vault.
#[napi]
pub fn delete_wallet(name_or_id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::delete_wallet(&name_or_id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

/// Export a wallet's secret (mnemonic or private key).
#[napi]
pub fn export_wallet(
    name_or_id: String,
    passphrase: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<String> {
    ows_lib::export_wallet(
        &name_or_id,
        passphrase.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}

/// Rename a wallet.
#[napi]
pub fn rename_wallet(
    name_or_id: String,
    new_name: String,
    vault_path_opt: Option<String>,
) -> Result<()> {
    ows_lib::rename_wallet(
        &name_or_id,
        &new_name,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}

/// Sign a transaction. Returns hex-encoded signature.
#[napi]
pub fn sign_transaction(
    wallet: String,
    chain: String,
    tx_hex: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_transaction(
        &wallet,
        &chain,
        &tx_hex,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign a message. Returns hex-encoded signature.
#[napi]
pub fn sign_message(
    wallet: String,
    chain: String,
    message: String,
    passphrase: Option<String>,
    encoding: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_message(
        &wallet,
        &chain,
        &message,
        passphrase.as_deref(),
        encoding.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign EIP-712 typed structured data (EVM only). Returns hex-encoded signature.
#[napi]
pub fn sign_typed_data(
    wallet: String,
    chain: String,
    typed_data_json: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_typed_data(
        &wallet,
        &chain,
        &typed_data_json,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign a raw 32-byte hash on a secp256k1-backed chain. Returns hex-encoded signature.
#[napi]
pub fn sign_hash(
    wallet: String,
    chain: String,
    hash_hex: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_hash(
        &wallet,
        &chain,
        &hash_hex,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign an EIP-7702 authorization tuple. Returns hex-encoded signature.
#[napi]
pub fn sign_authorization(
    wallet: String,
    chain: String,
    address: String,
    nonce: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_authorization(
        &wallet,
        &chain,
        &address,
        &nonce,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

/// Register a policy from a JSON string.
#[napi]
pub fn create_policy(policy_json: String, vault_path_opt: Option<String>) -> Result<()> {
    let policy: ows_core::Policy =
        serde_json::from_str(&policy_json).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ows_lib::policy_store::save_policy(&policy, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

/// List all registered policies.
#[napi]
pub fn list_policies(vault_path_opt: Option<String>) -> Result<Vec<serde_json::Value>> {
    let policies = ows_lib::policy_store::list_policies(vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    policies
        .iter()
        .map(|p| serde_json::to_value(p).map_err(|e| napi::Error::from_reason(e.to_string())))
        .collect()
}

/// Get a single policy by ID.
#[napi]
pub fn get_policy(id: String, vault_path_opt: Option<String>) -> Result<serde_json::Value> {
    let policy = ows_lib::policy_store::load_policy(&id, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    serde_json::to_value(&policy).map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Delete a policy by ID.
#[napi]
pub fn delete_policy(id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::policy_store::delete_policy(&id, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

// ---------------------------------------------------------------------------
// API key management
// ---------------------------------------------------------------------------

/// API key creation result.
#[napi(object)]
pub struct ApiKeyResult {
    /// The raw token (shown once — caller must save it).
    pub token: String,
    /// The key file ID.
    pub id: String,
    pub name: String,
}

/// Create an API key for agent access to wallets.
/// Returns the raw token (shown once) and key metadata.
#[napi]
pub fn create_api_key(
    name: String,
    wallet_ids: Vec<String>,
    policy_ids: Vec<String>,
    passphrase: String,
    expires_at: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<ApiKeyResult> {
    let (token, key_file) = ows_lib::key_ops::create_api_key(
        &name,
        &wallet_ids,
        &policy_ids,
        &passphrase,
        expires_at.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Ok(ApiKeyResult {
        token,
        id: key_file.id,
        name: key_file.name,
    })
}

/// List all API keys (tokens are never returned).
#[napi]
pub fn list_api_keys(vault_path_opt: Option<String>) -> Result<Vec<serde_json::Value>> {
    let keys = ows_lib::key_store::list_api_keys(vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    keys.iter()
        .map(|k| {
            // Strip wallet_secrets from the output — never expose encrypted material
            let mut v =
                serde_json::to_value(k).map_err(|e| napi::Error::from_reason(e.to_string()))?;
            v.as_object_mut().map(|m| m.remove("wallet_secrets"));
            Ok(v)
        })
        .collect()
}

/// Revoke (delete) an API key by ID.
#[napi]
pub fn revoke_api_key(id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::key_store::delete_api_key(&id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

/// Sign and broadcast a transaction. Returns the transaction hash.
#[napi]
pub fn sign_and_send(
    wallet: String,
    chain: String,
    tx_hex: String,
    passphrase: Option<String>,
    index: Option<u32>,
    rpc_url: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<SendResult> {
    ows_lib::sign_and_send(
        &wallet,
        &chain,
        &tx_hex,
        passphrase.as_deref(),
        index,
        rpc_url.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SendResult { tx_hash: r.tx_hash })
    .map_err(map_err)
}

#[napi]
pub fn get_public_key(
    wallet: String,
    chain: String,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<String> {
    ows_lib::get_public_key(
        &wallet,
        &chain,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}
