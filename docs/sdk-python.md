# Python SDK

> Native bindings for Python via PyO3. No CLI, no server, no subprocess &mdash; the Rust core runs in-process.

This document is non-normative reference implementation documentation. Package names and function signatures here do not define the OWS standard.

[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)

## Install

```bash
pip install open-wallet-standard
```

Prebuilt wheels are available for macOS (arm64, x64) and Linux (x64, arm64) on Python 3.9&ndash;3.13.

## Quick Start

```python
from ows import (
    generate_mnemonic,
    create_wallet,
    list_wallets,
    sign_message,
    sign_hash,
    sign_authorization,
    sign_typed_data,
    delete_wallet,
)

mnemonic = generate_mnemonic(12)
wallet = create_wallet("my-wallet")
sig = sign_message("my-wallet", "evm", "hello")
print(sig["signature"])
```

## API Reference

### Return Types

All functions return Python dicts. Wallet functions return:

```python
# WalletInfo
{
    "id": "3198bc9c-...",             # UUID v4
    "name": "my-wallet",
    "created_at": "2026-03-09T...",   # ISO 8601
    "accounts": [
        {
            "chain_id": "eip155:1",
            "address": "0xab16...",
            "derivation_path": "m/44'/60'/0'/0/0",
        },
        # ... one per supported chain
    ],
}

# SignResult
{
    "signature": "bea6b4ee...",       # Hex-encoded
    "recovery_id": 0,                 # EVM/Tron only (None for others)
}

# SendResult
{
    "tx_hash": "0xabc...",
}
```

### Mnemonic

#### `generate_mnemonic(words=12)`

Generate a new BIP-39 mnemonic phrase.

```python
phrase = generate_mnemonic(12)  # or 24
# => "goose puzzle decorate much stable beach ..."
```

#### `derive_address(mnemonic, chain, index=0)`

Derive an address from a mnemonic without creating a wallet.

```python
addr = derive_address(mnemonic, "evm")
# => "0xCc1e2c3D077b7c0f5301ef400bDE30d0e23dF1C6"

sol_addr = derive_address(mnemonic, "solana")
# => "DzkqyvQrBvLqKSMhCoXoGK65e9PvyWjb6YjS4BqcxN2i"
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `mnemonic` | `str` | &mdash; | BIP-39 mnemonic phrase |
| `chain` | `str` | &mdash; | `"evm"`, `"solana"`, `"xrpl"`, `"sui"`, `"bitcoin"`, `"cosmos"`, `"tron"`, `"ton"`, `"spark"`, `"filecoin"`, `"cardano"` |
| `index` | `int` | `0` | Account index in derivation path |

### Wallet Management

#### `create_wallet(name, passphrase=None, words=12, vault_path=None)`

Create a new wallet. Derives addresses for the current auto-derived chain set.

```python
wallet = create_wallet("agent-treasury")
for acct in wallet["accounts"]:
    print(f"{acct['chain_id']}: {acct['address']}")
```

#### `list_wallets(vault_path=None)`

List all wallets in the vault.

```python
wallets = list_wallets()
print(len(wallets))
```

#### `get_wallet(name_or_id, vault_path=None)`

Look up a wallet by name or UUID.

```python
wallet = get_wallet("agent-treasury")
```

#### `delete_wallet(name_or_id, vault_path=None)`

Delete a wallet from the vault.

```python
delete_wallet("agent-treasury")
```

#### `rename_wallet(name_or_id, new_name, vault_path=None)`

Rename a wallet.

```python
rename_wallet("old-name", "new-name")
```

#### `export_wallet(name_or_id, passphrase=None, vault_path=None)`

Export a wallet's secret.

- **Mnemonic wallets** return the phrase string.
- **Private key wallets** return a JSON string with per-curve key material (`secp256k1`, `ed25519`, `ed25519_bip32`).

```python
# Mnemonic wallet
phrase = export_wallet("mn-wallet")
# => "goose puzzle decorate much ..."

# Private key wallet
import json
keys = json.loads(export_wallet("pk-wallet"))
# => {"secp256k1": "4c0883a6...", "ed25519": "9d61b19d...", "ed25519_bip32": "..."}
```

### Import

#### `import_wallet_mnemonic(name, mnemonic, passphrase=None, index=None, vault_path=None)`

Import a wallet from a BIP-39 mnemonic. Derives all universal-wallet accounts via HD paths (13 chain families plus Cardano Preprod and Preview).

```python
wallet = import_wallet_mnemonic("imported", "goose puzzle decorate ...")
```

#### `import_wallet_private_key(name, private_key_hex, chain=None, passphrase=None, vault_path=None, secp256k1_key=None, ed25519_key=None, ed25519_bip32_key=None)`

Import a wallet from a hex-encoded private key. All chain families are supported (15 accounts, including Cardano Preprod and Preview): the provided key is used for its curve's chains, and random keys are generated for the other curves.

The optional `chain` parameter specifies which chain the key originates from to determine the curve. Defaults to `"evm"` (secp256k1).

Alternatively, provide explicit keys for each curve via `secp256k1_key`, `ed25519_key`, and `ed25519_bip32_key`. When all are given, `private_key_hex` and `chain` are ignored.

```python
# Import an EVM private key — generates random Ed25519 and Ed25519-BIP32 keys for other curves
wallet = import_wallet_private_key("from-evm", "4c0883a691...")
print(len(wallet["accounts"]))  # => 15

# Import a Solana private key — generates a random secp256k1 key for EVM/BTC/etc and Ed25519-BIP32 for Cardano.
wallet = import_wallet_private_key(
    "from-solana", "9d61b19d...", chain="solana"
)
print(len(wallet["accounts"]))  # => 15

# Import explicit keys for all curves
wallet = import_wallet_private_key(
    "all-keys", "",
    secp256k1_key="4c0883a691...",
    ed25519_key="9d61b19d...",
    ed25519_bip32_key="cafe..."
)
print(len(wallet["accounts"]))  # => 15
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | &mdash; | Wallet name |
| `private_key_hex` | `str` | &mdash; | Hex-encoded private key. Ignored when all three curve keys (`secp256k1Key`, `ed25519Key`, and `ed25519Bip32Key`) are provided. |
| `chain` | `str` | `"evm"` | Source chain: `"evm"`, `"bitcoin"`, `"cosmos"`, `"tron"`, `"filecoin"` (secp256k1) or `"solana"`, `"sui"`, `"ton"` (Ed25519) or `"cardano"` (Ed25519-BIP32) |
| `passphrase` | `str` | `None` | Encryption passphrase |
| `vault_path` | `str` | `None` | Custom vault directory |
| `secp256k1_key` | `str` | `None` | Explicit secp256k1 private key (hex) |
| `ed25519_key` | `str` | `None` | Explicit Ed25519 private key (hex) |
| `ed25519_bip32_key` | `str` | `None` | Explicit Ed25519-BIP32 private key (hex) |

### Signing

#### `sign_message(wallet, chain, message, passphrase=None, encoding=None, index=None, address=None, vault_path=None)`

Sign a message with chain-specific formatting.

```python
result = sign_message("agent-treasury", "evm", "hello world")
print(result["signature"])   # hex string
print(result["recovery_id"]) # 0 or 1
```

#### `sign_hash(wallet, chain, hash_hex, passphrase=None, index=None, vault_path=None)`

Sign a raw 32-byte hash without adding a message prefix.

This operation is only supported on secp256k1-backed chains. For EVM, the returned `recovery_id` is the raw `y_parity` value (`0` or `1`).

```python
result = sign_hash("agent-treasury", "base", "11" * 32)
print(result["signature"])
print(result["recovery_id"])  # 0 or 1
```

#### `sign_authorization(wallet, chain, address, nonce, passphrase=None, index=None, vault_path=None)`

Sign an EIP-7702 authorization tuple. This is equivalent to:

`sign_hash(wallet, chain, keccak256(0x05 || rlp([eip155_chain_id(chain), address, nonce])))`

`chain` must resolve to an EVM chain. `nonce` accepts decimal or `0x`-prefixed hex strings. If you need a nonstandard authorization tuple, such as chain ID `0`, precompute the digest and call `sign_hash`.

```python
result = sign_authorization(
    "agent-treasury",
    "base",
    "0x1111111111111111111111111111111111111111",
    "7",
)
print(result["signature"])
print(result["recovery_id"])  # 0 or 1
```

#### `sign_typed_data(wallet, chain, typed_data_json, passphrase=None, index=None, address=None, vault_path=None)`

Sign EIP-712 typed structured data (EVM only).

```python
import json

typed_data = json.dumps({
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "Transfer": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
    },
    "primaryType": "Transfer",
    "domain": {"name": "MyDApp", "chainId": "1"},
    "message": {"to": "0xabc...", "amount": "1000"},
})

result = sign_typed_data("agent-treasury", "evm", typed_data)
print(result["signature"])   # hex string
print(result["recovery_id"]) # 27 or 28
```

#### `sign_transaction(wallet, chain, tx_hex, passphrase=None, index=None, vault_path=None)`

Sign a raw transaction (hex-encoded bytes).

```python
result = sign_transaction("agent-treasury", "evm", "02f8...")
print(result["signature"])
```

#### `sign_and_send(wallet, chain, tx_hex, passphrase=None, index=None, rpc_url=None, vault_path=None)`

Sign and broadcast a transaction.

```python
result = sign_and_send(
    "agent-treasury", "evm", "02f8...",
    rpc_url="https://mainnet.infura.io/v3/..."
)
print(result["tx_hash"])
```

## Policy And API Key Management

The Python bindings also expose policy and API-key management directly:

```python
from ows import (
    create_policy,
    list_policies,
    get_policy,
    delete_policy,
    create_api_key,
    list_api_keys,
    revoke_api_key,
)
```

| Function | Description |
|----------|-------------|
| `create_policy(policy_json, vault_path=None)` | Register a policy from a JSON string |
| `list_policies(vault_path=None)` | List all registered policies |
| `get_policy(id, vault_path=None)` | Load a single policy by ID |
| `delete_policy(id, vault_path=None)` | Delete a policy |
| `create_api_key(name, wallet_ids, policy_ids, passphrase, expires_at=None, vault_path=None)` | Create an API key and return `{"token", "id", "name"}` |
| `list_api_keys(vault_path=None)` | List API keys (metadata only, no tokens) |
| `revoke_api_key(id, vault_path=None)` | Delete an API key file |

## Custom Vault Path

Every function accepts an optional `vault_path` parameter for testing or isolation:

```python
import tempfile
import shutil

vault = tempfile.mkdtemp(prefix="ows-test-")
try:
    wallet = create_wallet("test", vault_path=vault)
    # ... use wallet ...
finally:
    shutil.rmtree(vault)
```
