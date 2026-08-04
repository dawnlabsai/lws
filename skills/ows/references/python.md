# Python SDK — `open-wallet-standard`

```bash
pip install open-wallet-standard
```

Native PyO3 bindings — Rust core runs in-process, no subprocess or server. Prebuilt wheels for macOS and Linux, Python 3.9-3.13.

## Return Types

All functions return Python dicts:

```python
# WalletInfo
{
    "id": "3198bc9c-...",
    "name": "my-wallet",
    "created_at": "2026-03-09T...",
    "accounts": [
        {"chain_id": "eip155:1", "address": "0x...", "derivation_path": "m/44'/60'/0'/0/0"},
        # ... one per supported chain
    ],
}

# SignResult
{"signature": "bea6b4ee...", "recovery_id": 0}  # recovery_id is None for non-EVM/Tron

# SendResult
{"tx_hash": "0xabc..."}

# ApiKeyResult
{"token": "ows_...", "id": "key-uuid", "name": "my-key"}  # token shown once — save it
```

## Mnemonic

```python
from open_wallet_standard import generate_mnemonic, derive_address

phrase = generate_mnemonic(12)         # or 24
addr = derive_address(phrase, "evm")   # any chain: evm, solana, sui, bitcoin, cosmos, tron, ton, spark, filecoin, xrpl, nano, cardano
# derive_address(mnemonic, chain, index=None)
```

## Wallet Management

```python
from open_wallet_standard import (
    create_wallet,
    import_wallet_mnemonic,
    import_wallet_private_key,
    list_wallets,
    get_wallet,
    delete_wallet,
    rename_wallet,
    export_wallet,
)

# Create
wallet = create_wallet("my-wallet")
# create_wallet(name, passphrase=None, words=12, vault_path=None)

# Import from mnemonic
w1 = import_wallet_mnemonic("imported", "goose puzzle ...")
# import_wallet_mnemonic(name, mnemonic, passphrase=None, index=None, vault_path=None)

# Import from private key (default: evm/secp256k1)
w2 = import_wallet_private_key("from-evm", "4c0883a691...")

# Import Ed25519 key (solana/sui/ton)
w3 = import_wallet_private_key("from-sol", "9d61b19d...", chain="solana")

# Import Ed25519-Bip32 key (Cardano)
w3 = import_wallet_private_key("from-cardano", "cafe...", chain="cardano")

# Import explicit keys for all curves
w5 = import_wallet_private_key("all", "", secp256k1_key="4c08...", ed25519_key="9d61...", ed25519_bip32_key="cafe...")
# import_wallet_private_key(name, private_key_hex, chain=None, passphrase=None,
#                           vault_path=None, secp256k1_key=None, ed25519_key=None, ed25519_bip32_key=None)

# List / get / delete / rename / export
wallets = list_wallets()                    # list_wallets(vault_path=None)
w = get_wallet("my-wallet")                 # get_wallet(name_or_id, vault_path=None)
delete_wallet("my-wallet")                  # delete_wallet(name_or_id, vault_path=None)
rename_wallet("old", "new")                 # rename_wallet(name_or_id, new_name, vault_path=None)
secret = export_wallet("my-wallet")         # export_wallet(name_or_id, passphrase=None, vault_path=None)
# Returns mnemonic string or JSON: {"secp256k1":"hex","ed25519":"hex","ed25519_bip32":"hex"}
```

## Signing

```python
from open_wallet_standard import sign_message, sign_transaction, sign_and_send

# Sign message
sig = sign_message("my-wallet", "evm", "hello world")
# sig["signature"] => hex string
# sig["recovery_id"] => 0 or 1 (EVM/Tron only)
# sign_message(wallet, chain, message, passphrase=None, encoding=None, index=None, address=None, vault_path=None)

# Sign transaction
tx_sig = sign_transaction("my-wallet", "evm", "02f8...")
# sign_transaction(wallet, chain, tx_hex, passphrase=None, index=None, vault_path=None)

# Sign and broadcast
result = sign_and_send("my-wallet", "evm", "02f8...", rpc_url="https://rpc...")
# result["tx_hash"] => "0x..."
# sign_and_send(wallet, chain, tx_hex, passphrase=None, index=None, rpc_url=None, vault_path=None)
```

## EIP-712 Typed Data

```python
from open_wallet_standard import sign_typed_data

sig = sign_typed_data("my-wallet", "evm", '{"types":...}')
# sig["signature"] => hex string
# sig["recovery_id"] => 0 or 1
# sign_typed_data(wallet, chain, typed_data_json, passphrase=None, index=None, vault_path=None)
```

## Policy Management

```python
from open_wallet_standard import create_policy, list_policies, get_policy, delete_policy

# Register a policy from a JSON string
create_policy('{"id":"my-policy","rules":[...]}')
# create_policy(policy_json, vault_path=None)

# List all registered policies
policies = list_policies()  # list_policies(vault_path=None)

# Get a single policy by ID
policy = get_policy("my-policy")  # get_policy(id, vault_path=None)

# Delete a policy by ID
delete_policy("my-policy")  # delete_policy(id, vault_path=None)
```

## API Key Management

```python
from open_wallet_standard import create_api_key, list_api_keys, revoke_api_key

# Create an API key scoped to specific wallets and policies
key = create_api_key("claude-agent", ["wallet-id"], ["policy-id"], "passphrase")
# key["token"] => raw token (shown once — save it)
# key["id"] => key file ID
# key["name"] => "claude-agent"
# create_api_key(name, wallet_ids, policy_ids, passphrase, expires_at=None, vault_path=None)

# Optional: set expiry (ISO-8601)
tmp_key = create_api_key("tmp", ["wallet-id"], [], "passphrase", expires_at="2026-04-01T00:00:00Z")

# List all API keys (tokens are never returned)
keys = list_api_keys()  # list_api_keys(vault_path=None)

# Revoke an API key
revoke_api_key("key-id")  # revoke_api_key(id, vault_path=None)
```

## Custom Vault Path

Every function accepts `vault_path` for testing/isolation:

```python
import tempfile, shutil

vault = tempfile.mkdtemp(prefix="ows-")
wallet = create_wallet("test", vault_path=vault)
# ...
shutil.rmtree(vault)
```
