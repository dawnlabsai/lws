use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;

fn vault_path(p: Option<String>) -> Option<PathBuf> {
    p.map(PathBuf::from)
}

fn map_err(e: ows_lib::OwsLibError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Generate a new BIP-39 mnemonic phrase.
#[pyfunction]
#[pyo3(signature = (words=12))]
fn generate_mnemonic(words: u32) -> PyResult<String> {
    ows_lib::generate_mnemonic(words).map_err(map_err)
}

/// Derive an address from a mnemonic for the given chain.
#[pyfunction]
#[pyo3(signature = (mnemonic, chain, index=None))]
fn derive_address(mnemonic: &str, chain: &str, index: Option<u32>) -> PyResult<String> {
    ows_lib::derive_address(mnemonic, chain, index).map_err(map_err)
}

/// Create a new universal wallet (derives addresses for all chains).
#[pyfunction]
#[pyo3(signature = (name, passphrase=None, words=None, vault_path_opt=None))]
fn create_wallet(
    name: &str,
    passphrase: Option<&str>,
    words: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let info = ows_lib::create_wallet(
        name,
        words,
        passphrase,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;
    Python::with_gil(|py| wallet_info_to_dict(py, &info))
}

/// Import a wallet from a mnemonic phrase (derives addresses for all chains).
#[pyfunction]
#[pyo3(signature = (name, mnemonic, passphrase=None, index=None, vault_path_opt=None))]
fn import_wallet_mnemonic(
    name: &str,
    mnemonic: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let info = ows_lib::import_wallet_mnemonic(
        name,
        mnemonic,
        passphrase,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;
    Python::with_gil(|py| wallet_info_to_dict(py, &info))
}

/// Import a wallet from a hex-encoded private key (derives addresses for all chains).
/// Optionally specify explicit keys per curve via `secp256k1_key` and `ed25519_key`.
#[pyfunction]
#[pyo3(signature = (name, private_key_hex, chain=None, passphrase=None, vault_path_opt=None, secp256k1_key=None, ed25519_key=None))]
fn import_wallet_private_key(
    name: &str,
    private_key_hex: &str,
    chain: Option<&str>,
    passphrase: Option<&str>,
    vault_path_opt: Option<String>,
    secp256k1_key: Option<&str>,
    ed25519_key: Option<&str>,
) -> PyResult<PyObject> {
    let info = ows_lib::import_wallet_private_key(
        name,
        private_key_hex,
        chain,
        passphrase,
        vault_path(vault_path_opt).as_deref(),
        secp256k1_key,
        ed25519_key,
    )
    .map_err(map_err)?;
    Python::with_gil(|py| wallet_info_to_dict(py, &info))
}

/// List all wallets in the vault.
#[pyfunction]
#[pyo3(signature = (vault_path_opt=None))]
fn list_wallets(vault_path_opt: Option<String>) -> PyResult<PyObject> {
    let wallets = ows_lib::list_wallets(vault_path(vault_path_opt).as_deref()).map_err(map_err)?;
    Python::with_gil(|py| {
        let list = pyo3::types::PyList::empty(py);
        for w in &wallets {
            let dict = wallet_info_to_dict_inner(py, w)?;
            list.append(dict)?;
        }
        Ok(list.unbind().into())
    })
}

/// Get a single wallet by name or ID.
#[pyfunction]
#[pyo3(signature = (name_or_id, vault_path_opt=None))]
fn get_wallet(name_or_id: &str, vault_path_opt: Option<String>) -> PyResult<PyObject> {
    let info =
        ows_lib::get_wallet(name_or_id, vault_path(vault_path_opt).as_deref()).map_err(map_err)?;
    Python::with_gil(|py| wallet_info_to_dict(py, &info))
}

/// Delete a wallet from the vault.
#[pyfunction]
#[pyo3(signature = (name_or_id, vault_path_opt=None))]
fn delete_wallet(name_or_id: &str, vault_path_opt: Option<String>) -> PyResult<()> {
    ows_lib::delete_wallet(name_or_id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

/// Export a wallet's secret (mnemonic or private key).
#[pyfunction]
#[pyo3(signature = (name_or_id, passphrase=None, vault_path_opt=None))]
fn export_wallet(
    name_or_id: &str,
    passphrase: Option<&str>,
    vault_path_opt: Option<String>,
) -> PyResult<String> {
    ows_lib::export_wallet(
        name_or_id,
        passphrase,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}

/// Rename a wallet.
#[pyfunction]
#[pyo3(signature = (name_or_id, new_name, vault_path_opt=None))]
fn rename_wallet(name_or_id: &str, new_name: &str, vault_path_opt: Option<String>) -> PyResult<()> {
    ows_lib::rename_wallet(name_or_id, new_name, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

/// Sign a transaction.
#[pyfunction]
#[pyo3(signature = (wallet, chain, tx_hex, passphrase=None, index=None, vault_path_opt=None))]
fn sign_transaction(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_transaction(
        wallet,
        chain,
        tx_hex,
        passphrase,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("signature", &result.signature)?;
        dict.set_item("recovery_id", result.recovery_id)?;
        Ok(dict.unbind().into())
    })
}

/// Sign a message.
#[pyfunction]
#[pyo3(signature = (wallet, chain, message, passphrase=None, encoding=None, index=None, vault_path_opt=None))]
fn sign_message(
    wallet: &str,
    chain: &str,
    message: &str,
    passphrase: Option<&str>,
    encoding: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_message(
        wallet,
        chain,
        message,
        passphrase,
        encoding,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("signature", &result.signature)?;
        dict.set_item("recovery_id", result.recovery_id)?;
        Ok(dict.unbind().into())
    })
}

/// Sign EIP-712 typed structured data (EVM only).
#[pyfunction]
#[pyo3(signature = (wallet, chain, typed_data_json, passphrase=None, index=None, vault_path_opt=None))]
fn sign_typed_data(
    wallet: &str,
    chain: &str,
    typed_data_json: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_typed_data(
        wallet,
        chain,
        typed_data_json,
        passphrase,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("signature", &result.signature)?;
        dict.set_item("recovery_id", result.recovery_id)?;
        Ok(dict.unbind().into())
    })
}

/// Sign a raw 32-byte hash on a secp256k1-backed chain.
#[pyfunction]
#[pyo3(signature = (wallet, chain, hash_hex, passphrase=None, index=None, vault_path_opt=None))]
fn sign_hash(
    wallet: &str,
    chain: &str,
    hash_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_hash(
        wallet,
        chain,
        hash_hex,
        passphrase,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("signature", &result.signature)?;
        dict.set_item("recovery_id", result.recovery_id)?;
        Ok(dict.unbind().into())
    })
}

/// Sign an EIP-7702 authorization tuple.
#[pyfunction]
#[pyo3(signature = (wallet, chain, address, nonce, passphrase=None, index=None, vault_path_opt=None))]
fn sign_authorization(
    wallet: &str,
    chain: &str,
    address: &str,
    nonce: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_authorization(
        wallet,
        chain,
        address,
        nonce,
        passphrase,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("signature", &result.signature)?;
        dict.set_item("recovery_id", result.recovery_id)?;
        Ok(dict.unbind().into())
    })
}

/// Sign and broadcast a transaction.
#[pyfunction]
#[pyo3(signature = (wallet, chain, tx_hex, passphrase=None, index=None, rpc_url=None, vault_path_opt=None))]
fn sign_and_send(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    rpc_url: Option<&str>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let result = ows_lib::sign_and_send(
        wallet,
        chain,
        tx_hex,
        passphrase,
        index,
        rpc_url,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("tx_hash", &result.tx_hash)?;
        Ok(dict.unbind().into())
    })
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

/// Register a policy from a JSON string.
#[pyfunction]
#[pyo3(signature = (policy_json, vault_path_opt=None))]
fn create_policy(policy_json: &str, vault_path_opt: Option<String>) -> PyResult<()> {
    let policy: ows_core::Policy = serde_json::from_str(policy_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    ows_lib::policy_store::save_policy(&policy, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

/// List all registered policies.
#[pyfunction]
#[pyo3(signature = (vault_path_opt=None))]
fn list_policies(vault_path_opt: Option<String>) -> PyResult<PyObject> {
    let policies = ows_lib::policy_store::list_policies(vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    let json_str =
        serde_json::to_string(&policies).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Python::with_gil(|py| {
        let json_mod = py.import("json")?;
        json_mod
            .call_method1("loads", (json_str,))
            .map(|o| o.unbind())
    })
}

/// Get a single policy by ID.
#[pyfunction]
#[pyo3(signature = (id, vault_path_opt=None))]
fn get_policy(id: &str, vault_path_opt: Option<String>) -> PyResult<PyObject> {
    let policy = ows_lib::policy_store::load_policy(id, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    let json_str =
        serde_json::to_string(&policy).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Python::with_gil(|py| {
        let json_mod = py.import("json")?;
        json_mod
            .call_method1("loads", (json_str,))
            .map(|o| o.unbind())
    })
}

/// Delete a policy by ID.
#[pyfunction]
#[pyo3(signature = (id, vault_path_opt=None))]
fn delete_policy(id: &str, vault_path_opt: Option<String>) -> PyResult<()> {
    ows_lib::policy_store::delete_policy(id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

// ---------------------------------------------------------------------------
// API key management
// ---------------------------------------------------------------------------

/// Create an API key for agent access to wallets.
/// Returns a dict with `token` (shown once), `id`, and `name`.
#[pyfunction]
#[pyo3(signature = (name, wallet_ids, policy_ids, passphrase, expires_at=None, vault_path_opt=None))]
fn create_api_key(
    name: &str,
    wallet_ids: Vec<String>,
    policy_ids: Vec<String>,
    passphrase: &str,
    expires_at: Option<&str>,
    vault_path_opt: Option<String>,
) -> PyResult<PyObject> {
    let (token, key_file) = ows_lib::key_ops::create_api_key(
        name,
        &wallet_ids,
        &policy_ids,
        passphrase,
        expires_at,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("token", token)?;
        dict.set_item("id", &key_file.id)?;
        dict.set_item("name", &key_file.name)?;
        Ok(dict.unbind().into())
    })
}

/// List all API keys (tokens are never returned).
#[pyfunction]
#[pyo3(signature = (vault_path_opt=None))]
fn list_api_keys(vault_path_opt: Option<String>) -> PyResult<PyObject> {
    let keys = ows_lib::key_store::list_api_keys(vault_path(vault_path_opt).as_deref())
        .map_err(map_err)?;
    // Strip wallet_secrets from output
    let sanitized: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            let mut v = serde_json::to_value(k).unwrap_or_default();
            v.as_object_mut().map(|m| m.remove("wallet_secrets"));
            v
        })
        .collect();
    let json_str =
        serde_json::to_string(&sanitized).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Python::with_gil(|py| {
        let json_mod = py.import("json")?;
        json_mod
            .call_method1("loads", (json_str,))
            .map(|o| o.unbind())
    })
}

/// Revoke (delete) an API key by ID.
#[pyfunction]
#[pyo3(signature = (id, vault_path_opt=None))]
fn revoke_api_key(id: &str, vault_path_opt: Option<String>) -> PyResult<()> {
    ows_lib::key_store::delete_api_key(id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

fn wallet_info_to_dict(py: Python<'_>, info: &ows_lib::WalletInfo) -> PyResult<PyObject> {
    let dict = wallet_info_to_dict_inner(py, info)?;
    Ok(dict.unbind().into())
}

fn wallet_info_to_dict_inner<'py>(
    py: Python<'py>,
    info: &ows_lib::WalletInfo,
) -> PyResult<pyo3::Bound<'py, pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("id", &info.id)?;
    dict.set_item("name", &info.name)?;

    let accounts_list = pyo3::types::PyList::empty(py);
    for acct in &info.accounts {
        let acct_dict = pyo3::types::PyDict::new(py);
        acct_dict.set_item("chain_id", &acct.chain_id)?;
        acct_dict.set_item("address", &acct.address)?;
        acct_dict.set_item("derivation_path", &acct.derivation_path)?;
        accounts_list.append(acct_dict)?;
    }
    dict.set_item("accounts", accounts_list)?;

    dict.set_item("created_at", &info.created_at)?;
    Ok(dict)
}

/// Python module definition.
#[pyfunction]
fn get_public_key(
    wallet: &str,
    chain: &str,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> PyResult<String> {
    ows_lib::get_public_key(
        wallet,
        chain,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(derive_address, m)?)?;
    m.add_function(wrap_pyfunction!(create_wallet, m)?)?;
    m.add_function(wrap_pyfunction!(import_wallet_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(import_wallet_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(list_wallets, m)?)?;
    m.add_function(wrap_pyfunction!(get_wallet, m)?)?;
    m.add_function(wrap_pyfunction!(delete_wallet, m)?)?;
    m.add_function(wrap_pyfunction!(export_wallet, m)?)?;
    m.add_function(wrap_pyfunction!(rename_wallet, m)?)?;
    m.add_function(wrap_pyfunction!(sign_transaction, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(sign_typed_data, m)?)?;
    m.add_function(wrap_pyfunction!(sign_hash, m)?)?;
    m.add_function(wrap_pyfunction!(sign_authorization, m)?)?;
    m.add_function(wrap_pyfunction!(sign_and_send, m)?)?;
    m.add_function(wrap_pyfunction!(create_policy, m)?)?;
    m.add_function(wrap_pyfunction!(list_policies, m)?)?;
    m.add_function(wrap_pyfunction!(get_policy, m)?)?;
    m.add_function(wrap_pyfunction!(delete_policy, m)?)?;
    m.add_function(wrap_pyfunction!(create_api_key, m)?)?;
    m.add_function(wrap_pyfunction!(list_api_keys, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(revoke_api_key, m)?)?;
    Ok(())
}
