<!-- Generated from readme/templates/python.md + readme/partials/ — edit those, then run readme/generate.sh -->

# open-wallet-standard

Local, policy-gated signing and wallet management for every chain.

[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

## Why OWS

- **Local key custody.** Private keys stay encrypted at rest and are decrypted only inside the OWS signing path after the relevant checks pass. Current implementations harden in-process memory handling and wipe key material after use.
- **Every chain, one interface.** EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Nano, NEAR — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates agent (API key) operations before decryption — chain allowlists, expiry, and optional custom executables.
- **Built for agents.** Native SDK and CLI today. A wallet created by one tool works in every other.

## Install

```bash
pip install open-wallet-standard
```

The package is **fully self-contained** — it embeds the Rust core via native FFI. No additional dependencies required.

## Quick Start

```python
from ows import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Sui, XRPL, Nano, and NEAR

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

## API Reference

| Function | Description |
|----------|-------------|
| `create_wallet(name, passphrase?, words?, vault_path?)` | Create a new wallet with addresses for the current auto-derived chain set |
| `import_wallet_mnemonic(name, mnemonic, passphrase?, index?, vault_path?)` | Import a wallet from a BIP-39 mnemonic |
| `import_wallet_private_key(name, private_key_hex, chain?, passphrase?, vault_path?, secp256k1_key?, ed25519_key?, ed25519_bip32_key?)` | Import a wallet from a private key |
| `list_wallets(vault_path?)` | List all wallets in the vault |
| `get_wallet(name_or_id, vault_path?)` | Get details of a specific wallet |
| `delete_wallet(name_or_id, vault_path?)` | Delete a wallet |
| `export_wallet(name_or_id, passphrase?, vault_path?)` | Export a wallet's mnemonic or keys |
| `rename_wallet(name_or_id, new_name, vault_path?)` | Rename a wallet |
| `sign_message(wallet, chain, message, passphrase?, encoding?, index?, address?, vault_path?)` | Sign a message with chain-specific formatting |
| `sign_hash(wallet, chain, hash_hex, passphrase?, index?, vault_path?)` | Sign a raw 32-byte hash on a secp256k1-backed chain |
| `sign_authorization(wallet, chain, address, nonce, passphrase?, index?, vault_path?)` | Sign an EIP-7702 authorization tuple |
| `sign_typed_data(wallet, chain, typed_data_json, passphrase?, index?, address?, vault_path?)` | Sign EIP-712 typed data (EVM only) |
| `sign_transaction(wallet, chain, tx_hex, passphrase?, index?, vault_path?)` | Sign a raw transaction |
| `sign_and_send(wallet, chain, tx_hex, passphrase?, index?, rpc_url?, vault_path?)` | Sign and broadcast a transaction |
| `generate_mnemonic(words?)` | Generate a BIP-39 mnemonic phrase |
| `derive_address(mnemonic, chain, index?)` | Derive an address from a mnemonic |
| `create_policy(policy_json, vault_path?)` | Register a policy from a JSON string |
| `list_policies(vault_path?)` | List all registered policies |
| `get_policy(id, vault_path?)` | Get a single policy by ID |
| `delete_policy(id, vault_path?)` | Delete a policy by ID |
| `create_api_key(name, wallet_ids, policy_ids, passphrase, expires_at?, vault_path?)` | Create an API key for agent access |
| `list_api_keys(vault_path?)` | List all API keys (tokens never returned) |
| `revoke_api_key(id, vault_path?)` | Revoke an API key |

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |
| TON | Ed25519 | raw/bounceable | `m/44'/607'/0'` |
| Sui | Ed25519 | 0x + BLAKE2b-256 hex | `m/44'/784'/0'/0'/0'` |
| XRPL | secp256k1 | Base58Check (`r...`) | `m/44'/144'/0'/0/0` |
| Spark (Bitcoin L2) | secp256k1 | spark: prefixed | `m/84'/0'/0'/0/0` |
| Filecoin | secp256k1 | f1 base32 | `m/44'/461'/0'/0/0` |
| NEAR | Ed25519 | implicit hex (64 chars) | `m/44'/397'/0'` |
| Cardano | Ed25519-BIP32 (CIP-1852) | Shelley Bech32 base (`addr1…`) | Payment `m/1852'/1815'/0'/0/0` + stake `m/1852'/1815'/0'/2/0` |

## Architecture

```
Agent / CLI / App
       │
       │  OWS Interface (SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Caller invokes sign()
│  ┌────────────────┐  │     2. Policy engine evaluates for API tokens
│  │ Policy Engine   │  │     3. Key decrypted in hardened memory
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │  Signing Core   │  │
│  │   (in-process)  │  │     The OWS API never returns
│  └───────┬────────┘  │     raw private keys.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.ows/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Documentation

The full spec and docs are available at [openwallet.sh](https://openwallet.sh) and in the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT
