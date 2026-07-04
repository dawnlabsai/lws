---
name: ows
description: Secure, local-first multi-chain wallet management — create wallets, derive addresses, sign messages and transactions across EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Nano, and NEAR via CLI, Node.js, or Python.
version: 1.4.0
metadata:
  openclaw:
    requires:
      anyBins:
        - ows
        - node
        - python3
    emoji: "\U0001F511"
    homepage: https://openwallet.sh
    os:
      - darwin
      - linux
    install:
      - kind: node
        package: "@open-wallet-standard/core"
        bins: [ows]
        label: Install OWS Node.js SDK + CLI
---

# OWS — Open Wallet Standard

Secure, offline-first multi-chain wallet management. Private keys are encrypted at rest (AES-256-GCM, scrypt KDF) and decrypted only after policy checks pass, then immediately wiped from memory — the caller never sees the raw key.

Available as **CLI**, **Node.js SDK** (`@open-wallet-standard/core`), and **Python SDK** (`open-wallet-standard`).

## When to use

Use this skill when the user asks to:

- Create, import, list, delete, or manage crypto wallets
- Derive blockchain addresses from a mnemonic
- Sign messages or transactions for EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Nano, or NEAR
- Broadcast signed transactions to a chain
- Generate BIP-39 mnemonic phrases
- Fund a wallet with USDC (MoonPay) or check token balances
- Make paid requests to x402-enabled API endpoints or discover x402 services
- Create and manage policies for API key access control
- Create, list, or revoke API keys for agent access to wallets
- Work with `@open-wallet-standard/core` or `open-wallet-standard` in code

## Supported Chains

| Chain | Parameter | Curve | Address Format |
|-------|-----------|-------|----------------|
| EVM (Ethereum, Polygon, Base, etc.) | `evm` | secp256k1 | EIP-55 checksummed |
| Solana | `solana` | Ed25519 | base58 |
| Bitcoin | `bitcoin` | secp256k1 | BIP-84 bech32 |
| Cosmos | `cosmos` | secp256k1 | bech32 |
| Tron | `tron` | secp256k1 | base58check |
| TON | `ton` | Ed25519 | raw/bounceable |
| Sui | `sui` | Ed25519 | 0x + BLAKE2b-256 hex |
| Spark (Bitcoin L2) | `spark` | secp256k1 | spark: prefixed |
| XRPL | `xrpl` | secp256k1 | Base58Check (`r...`) |
| Filecoin | `filecoin` | secp256k1 | f1 secp256k1 |
| NEAR | `near`, `near-testnet` | Ed25519 | implicit hex (64 chars) |

## Installation

```bash
# CLI (one-liner)
curl -fsSL https://docs.openwallet.sh/install.sh | bash

# Node.js SDK (global install also provides the ows CLI)
npm install @open-wallet-standard/core

# Python SDK
pip install open-wallet-standard
```

---

## CLI

### Wallet Management

```bash
# Create (--show-mnemonic to display the phrase for backup)
ows wallet create --name "my-wallet"
ows wallet create --name "my-wallet" --words 24 --show-mnemonic

# Import from mnemonic (via stdin or OWS_MNEMONIC env)
echo "goose puzzle decorate ..." | ows wallet import --name "imported" --mnemonic

# Import from private key (via stdin or OWS_PRIVATE_KEY env)
echo "4c0883a691..." | ows wallet import --name "from-evm" --private-key
echo "9d61b19d..." | ows wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves (via env vars)
OWS_SECP256K1_KEY="4c0883a691..." OWS_ED25519_KEY="9d61b19d..." \
  ows wallet import --name "both"

# List / info / export / delete / rename
ows wallet list
ows wallet info
ows wallet export --wallet "my-wallet"
ows wallet delete --wallet "my-wallet" --confirm
ows wallet rename --wallet "my-wallet" --new-name "treasury"
```

### Signing

The `--wallet` flag can also be set via `OWS_WALLET` env var. Use `--json` for structured output, `--index N` to select an HD account index.

```bash
# Sign a message
ows sign message --wallet "my-wallet" --chain evm --message "hello world"
ows sign message --wallet "my-wallet" --chain solana --message "hello" --json

# Sign a message with EIP-712 typed data (EVM only)
ows sign message --wallet "my-wallet" --chain evm --message "" --typed-data '{"types":...}'

# Sign a raw transaction
ows sign tx --wallet "my-wallet" --chain evm --tx "02f8..."

# Sign and broadcast
ows sign send-tx --wallet "my-wallet" --chain evm --tx "02f8..." --rpc-url "https://..."
```

### Funding

```bash
# Create a MoonPay deposit (auto-converts to USDC on target chain)
ows fund deposit --wallet "my-wallet" --chain base --token USDC

# Check token balances
ows fund balance --wallet "my-wallet" --chain base
```

### Payments (x402)

```bash
# Make a paid request to an x402-enabled API endpoint
ows pay request https://api.example.com/data --wallet "my-wallet"
ows pay request https://api.example.com/data --wallet "my-wallet" --method POST --body '{"key":"value"}'

# Discover x402-enabled services from the Bazaar directory
ows pay discover
ows pay discover --query "weather" --limit 10
```

### Policies

```bash
# Register a policy from a JSON file
ows policy create --file policy.json

# List / show / delete policies
ows policy list
ows policy show --id "policy-id"
ows policy delete --id "policy-id" --confirm
```

### API Keys

```bash
# Create an API key for agent access (scoped to wallets + policies)
ows key create --name "claude-agent" --wallet "my-wallet" --policy "policy-id"
ows key create --name "tmp-key" --wallet "my-wallet" --expires-at "2026-04-01T00:00:00Z"

# List all API keys (tokens are never shown)
ows key list

# Revoke an API key
ows key revoke --id "key-id" --confirm
```

### Mnemonic Utilities

```bash
ows mnemonic generate --words 12
OWS_MNEMONIC="word1 word2 ..." ows mnemonic derive --chain evm
```

### System

```bash
ows update            # Update to latest version
ows update --force    # Force re-download
ows uninstall         # Remove CLI (keep wallet data)
ows uninstall --purge # Remove CLI + all wallet data
ows config show       # Show config and RPC endpoints
```

---

## Node.js SDK

`npm install @open-wallet-standard/core` — native NAPI bindings, Rust core runs in-process.

Quick start:

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("my-wallet");
const sig = signMessage("my-wallet", "evm", "hello world");
```

Full API reference, types, and examples: see `{baseDir}/references/node.md`

---

## Python SDK

`pip install open-wallet-standard` — native PyO3 bindings, Rust core runs in-process.

Quick start:

```python
from open_wallet_standard import create_wallet, sign_message

wallet = create_wallet("my-wallet")
sig = sign_message("my-wallet", "evm", "hello world")
```

Full API reference, return types, and examples: see `{baseDir}/references/python.md`

---

## Vault Layout

```
~/.ows/
  bin/
    ows                    # CLI binary
  wallets/
    <uuid>/
      wallet.json          # Encrypted keystore (AES-256-GCM, scrypt KDF)
      meta.json            # Name, chains, created_at
  policies/
    <id>.json              # Policy definitions
  keys/
    <id>.json              # API key metadata (token hash, scoped wallets/policies)
```

## Security Model

- Keys encrypted at rest with AES-256-GCM (scrypt N=2^16, r=8, p=1)
- Keys decrypted only after policy checks pass, then immediately wiped from memory
- Caller never sees raw private key during signing
- Optional passphrase adds second encryption layer
- Universal wallets: single mnemonic derives addresses for all supported chains via BIP-44 HD paths
- API keys use HKDF-SHA256 for token-based decryption; tokens shown once at creation, only hashes stored
