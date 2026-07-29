<!-- Generated from readme/templates/node.md + readme/partials/ — edit those, then run readme/generate.sh -->

# @open-wallet-standard/core

Local, policy-gated signing and wallet management for every chain.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

{{> why-ows}}

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

{{> supported-chains}}

{{> cli-reference}}

{{> architecture}}

## Documentation

The full spec and docs are available at [openwallet.sh](https://openwallet.sh) and in the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT