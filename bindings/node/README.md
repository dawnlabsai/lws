<!-- Generated from readme/templates/node.md + readme/partials/ — edit those, then run readme/generate.sh -->

# @open-wallet-standard/core

Local, policy-gated signing and wallet management for every chain.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

## Why OWS

- **Local key custody.** Private keys stay encrypted at rest and are decrypted only inside the OWS signing path after the relevant checks pass. Current implementations harden in-process memory handling and wipe key material after use.
- **Every chain, one interface.** EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Nano, NEAR — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates agent (API key) operations before decryption — chain allowlists, expiry, and optional custom executables.
- **Built for agents.** Native SDK and CLI today. A wallet created by one tool works in every other.

## Install

```bash
npm install @open-wallet-standard/core    # Node.js SDK
npm install -g @open-wallet-standard/core # Node.js SDK + CLI (provides `ows` command)
```

The package is **fully self-contained** — it embeds the Rust core via native FFI. Installing globally with `-g` also provides the `ows` CLI.

Using viem, `@solana/web3.js`, or the Tether WDK? Install [`@open-wallet-standard/adapters`](https://www.npmjs.com/package/@open-wallet-standard/adapters) alongside this package to drop an OWS wallet into those frameworks without ever exposing a private key.

## Quick Start

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("agent-treasury");
// => accounts for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin, Sui, XRPL, Nano, NEAR, and Cardano

const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);
```

### CLI

```bash
# Create a wallet (derives addresses for the current auto-derived chain set)
ows wallet create --name "agent-treasury"

# Sign a message
ows sign message --wallet agent-treasury --chain evm --message "hello"

# Sign a transaction
ows sign tx --wallet agent-treasury --chain evm --tx "deadbeef..."
```

## API Reference

| Function | Description |
|----------|-------------|
| `createWallet(name, passphrase?, words?, vaultPath?)` | Create a new wallet with addresses for the current auto-derived chain set |
| `importWalletMnemonic(name, mnemonic, passphrase?, index?, vaultPath?)` | Import a wallet from a BIP-39 mnemonic |
| `importWalletPrivateKey(name, privateKeyHex, passphrase?, vaultPath?, chain?, secp256k1Key?, ed25519Key?, ed25519Bip32Key?)` | Import a wallet from a private key |
| `listWallets(vaultPath?)` | List all wallets in the vault |
| `getWallet(nameOrId, vaultPath?)` | Get details of a specific wallet |
| `deleteWallet(nameOrId, vaultPath?)` | Delete a wallet |
| `exportWallet(nameOrId, passphrase?, vaultPath?)` | Export a wallet's mnemonic or keys |
| `renameWallet(nameOrId, newName, vaultPath?)` | Rename a wallet |
| `signMessage(wallet, chain, message, passphrase?, encoding?, index?, address?, vaultPath?)` | Sign a message with chain-specific formatting |
| `signTypedData(wallet, chain, typedDataJson, passphrase?, index?, address?, vaultPath?)` | Sign EIP-712 typed data (EVM only) |
| `signTransaction(wallet, chain, txHex, passphrase?, index?, vaultPath?)` | Sign a raw transaction |
| `signAndSend(wallet, chain, txHex, passphrase?, index?, rpcUrl?, vaultPath?)` | Sign and broadcast a transaction |
| `generateMnemonic(words?)` | Generate a BIP-39 mnemonic phrase |
| `deriveAddress(mnemonic, chain, index?)` | Derive an address from a mnemonic |
| `createPolicy(policyJson, vaultPath?)` | Register a policy from a JSON string |
| `listPolicies(vaultPath?)` | List all registered policies |
| `getPolicy(id, vaultPath?)` | Get a single policy by ID |
| `deletePolicy(id, vaultPath?)` | Delete a policy by ID |
| `createApiKey(name, walletIds, policyIds, passphrase, expiresAt?, vaultPath?)` | Create an API key for agent access |
| `listApiKeys(vaultPath?)` | List all API keys (tokens never returned) |
| `revokeApiKey(id, vaultPath?)` | Revoke an API key |

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
