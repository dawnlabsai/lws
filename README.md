# OWS — Open Wallet Standard.

Local, policy-gated signing and wallet management for every chain.

[![CI](https://github.com/open-wallet-standard/core/actions/workflows/ci.yml/badge.svg)](https://github.com/open-wallet-standard/core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)
[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why OWS

- **Local key custody.** Private keys stay encrypted at rest and are decrypted only inside the OWS signing path after the relevant checks pass. Current implementations harden in-process memory handling and wipe key material after use.
- **Every chain, one interface.** EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates agent (API key) operations before decryption — chain allowlists, expiry, and optional custom executables.
- **Built for agents.** Native SDK and CLI today. A wallet created by one tool works in every other.

## Install

```bash
# Everything (CLI + Node + Python bindings)
curl -fsSL https://docs.openwallet.sh/install.sh | bash
```

Or install only what you need:

```bash
npm install @open-wallet-standard/core     # Node.js SDK
npm install -g @open-wallet-standard/core  # Node.js SDK + CLI (provides `ows` command)
npm install @open-wallet-standard/adapters # Framework adapters (viem, Solana, WDK)
pip install open-wallet-standard           # Python
cd ows && cargo build --workspace --release # From source
```

The language bindings are **fully self-contained** — they embed the Rust core via native FFI. Installing globally with `-g` also provides the `ows` CLI. The [`@open-wallet-standard/adapters`](https://www.npmjs.com/package/@open-wallet-standard/adapters) package plugs an OWS wallet into viem, `@solana/web3.js`, and the Tether WDK.

## Quick Start

```bash
# Create a wallet (derives addresses for the current auto-derived chain set)
ows wallet create --name "agent-treasury"

# Sign a message (EVM)
ows sign message --wallet agent-treasury --chain ethereum --message "hello"

# Sign on Solana
ows sign message --wallet agent-treasury --chain solana --message "hello"

# Sign a Bitcoin transaction
ows sign tx --wallet agent-treasury --chain bitcoin --tx "0200000001..."

# Use a bare EVM chain ID for Base
ows sign tx --wallet agent-treasury --chain 8453 --tx "02f8..."
```

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("agent-treasury");
// => accounts for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, Sui, and XRPL

const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);
```

```python
from ows import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, Sui, and XRPL

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

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
| Spark (Bitcoin L2) | secp256k1 | spark: prefixed | `m/84'/0'/0'/0/0` |
| Filecoin | secp256k1 | f1 base32 | `m/44'/461'/0'/0/0` |
| XRPL | secp256k1 | base58check | `m/44'/144'/0'/0/0`|
| Cardano | Ed25519-BIP32 (CIP-1852) | Shelley Bech32 base (`addr1…`) | Payment `m/1852'/1815'/0'/0/0` + stake `m/1852'/1815'/0'/2/0` |

## CLI Reference

| Command | Description |
|---------|-------------|
| `ows wallet create` | Create a new wallet with addresses for all chains |
| `ows wallet list` | List all wallets in the vault |
| `ows wallet info` | Show vault path and supported chains |
| `ows sign message` | Sign a message with chain-specific formatting |
| `ows sign tx` | Sign a raw transaction |
| `ows pay request` | Make a paid request to an x402-enabled API endpoint |
| `ows pay discover` | Discover x402-enabled services |
| `ows fund deposit` | Create a MoonPay deposit to fund a wallet with USDC |
| `ows fund balance` | Check token balances for a wallet |
| `ows mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `ows mnemonic derive` | Derive an address from a mnemonic |
| `ows policy create` | Register a policy from a JSON file |
| `ows policy list` | List all registered policies |
| `ows key create` | Create an API key for agent access |
| `ows key list` | List all API keys |
| `ows key revoke` | Revoke an API key |
| `ows update` | Update ows and bindings |
| `ows uninstall` | Remove ows from the system |

## Specification

The full spec lives in [`docs/`](docs/) and at [openwallet.sh](https://openwallet.sh):

1. [Specification](docs/00-specification.md) — Scope, document classes, conformance, and extensions
2. [Storage Format](docs/01-storage-format.md) — Vault layout, keystore schema, filesystem permissions
3. [Signing Interface](docs/02-signing-interface.md) — Sign, signAndSend, signMessage operations
4. [Policy Engine](docs/03-policy-engine.md) — Pre-signing transaction policies
5. [Agent Access Layer](docs/04-agent-access-layer.md) — Optional access profiles above the core spec
6. [Key Isolation](docs/05-key-isolation.md) — Optional deployment guidance for key isolation
7. [Wallet Lifecycle](docs/06-wallet-lifecycle.md) — Creation, recovery, deletion, and rotation
8. [Supported Chains](docs/07-supported-chains.md) — Chain families, canonical identifiers, and derivation rules
9. [Conformance and Security](docs/08-conformance-and-security.md) — Interop testing and security requirements

Reference implementation documentation:

- [Quickstart](docs/quickstart.md)
- [CLI Reference](docs/sdk-cli.md)
- [Node.js SDK](docs/sdk-node.md)
- [Python SDK](docs/sdk-python.md)
- [Policy Engine Implementation Guide](docs/03-policy-engine.md)

## License

MIT
