# Node.js SDK

> Native bindings for Node.js via NAPI. No CLI, no server, no subprocess &mdash; the Rust core runs in-process.

This document is non-normative reference implementation documentation. Package names and function signatures here do not define the OWS standard.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)

## Install

```bash
npm install @open-wallet-standard/core
```

The package includes prebuilt native binaries for macOS (arm64, x64) and Linux (x64, arm64). No Rust toolchain required.

For viem, `@solana/web3.js`, or Tether WDK integrations, install [`@open-wallet-standard/adapters`](https://www.npmjs.com/package/@open-wallet-standard/adapters) alongside this package — it wraps an OWS wallet as a framework-native signer without exposing private keys.

## Quick Start

```javascript
import {
  generateMnemonic,
  createWallet,
  listWallets,
  signMessage,
  signHash,
  signAuthorization,
  signTypedData,
  deleteWallet,
} from "@open-wallet-standard/core";

const mnemonic = generateMnemonic(12);
const wallet = createWallet("my-wallet");
const sig = signMessage("my-wallet", "evm", "hello");
console.log(sig.signature);
```

## API Reference

### Types

```typescript
interface AccountInfo {
  chainId: string;        // CAIP-2 chain ID (e.g. "eip155:1")
  address: string;        // Chain-native address
  derivationPath: string; // BIP-44 path (e.g. "m/44'/60'/0'/0/0")
}

interface WalletInfo {
  id: string;             // UUID v4
  name: string;
  accounts: AccountInfo[];
  createdAt: string;      // ISO 8601
}

interface SignResult {
  signature: string;      // Hex-encoded signature
  recoveryId?: number;    // EVM/Tron recovery ID (v value)
}

interface SendResult {
  txHash: string;         // Transaction hash
}
```

### Mnemonic

#### `generateMnemonic(words?)`

Generate a new BIP-39 mnemonic phrase.

```javascript
const phrase = generateMnemonic(12);  // or 24
// => "goose puzzle decorate much stable beach ..."
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `words` | `number` | `12` | Word count (12 or 24) |

**Returns:** `string`

#### `deriveAddress(mnemonic, chain, index?)`

Derive an address from a mnemonic without creating a wallet.

```javascript
const addr = deriveAddress(mnemonic, "evm");
// => "0xCc1e2c3D077b7c0f5301ef400bDE30d0e23dF1C6"

const solAddr = deriveAddress(mnemonic, "solana");
// => "DzkqyvQrBvLqKSMhCoXoGK65e9PvyWjb6YjS4BqcxN2i"
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `mnemonic` | `string` | &mdash; | BIP-39 mnemonic phrase |
| `chain` | `string` | &mdash; | `"evm"`, `"solana"`, `"xrpl"`, `"sui"`, `"bitcoin"`, `"cosmos"`, `"tron"`, `"filecoin"`, `"cardano"` |
| `index` | `number` | `0` | Account index in derivation path |

**Returns:** `string`

### Wallet Management

#### `createWallet(name, passphrase?, words?, vaultPath?)`

Create a new wallet. Generates a mnemonic and derives addresses for the current auto-derived chain set.

```javascript
const wallet = createWallet("agent-treasury");
console.log(wallet.accounts);
// => [
//   { chainId: "eip155:1", address: "0x...", derivationPath: "m/44'/60'/0'/0/0" },
//   { chainId: "solana:5eykt4...", address: "7Kz9...", derivationPath: "m/44'/501'/0'/0'" },
//   { chainId: "bip122:000...", address: "bc1q...", derivationPath: "m/84'/0'/0'/0/0" },
//   { chainId: "cosmos:cosmoshub-4", address: "cosmos1...", derivationPath: "m/44'/118'/0'/0/0" },
//   { chainId: "tron:mainnet", address: "TKLm...", derivationPath: "m/44'/195'/0'/0/0" },
//   { chainId: "ton:mainnet", address: "UQ...", derivationPath: "m/44'/607'/0'" },
//   { chainId: "sui:mainnet", address: "0x...", derivationPath: "m/44'/784'/0'/0'/0'" },
//   { chainId: "xrpl:mainnet", address: "r...", derivationPath: "m/44'/144'/0'/0/0" },
//   { chainId: "fil:mainnet", address: "f1...", derivationPath: "m/44'/461'/0'/0/0" },
//   { chainId: "cip34:1-764824073", address: "addr1...", derivationPath: "m/1852'/1815'/0'/0/0" }, // payment; stake m/1852'/1815'/0'/2/0
//   { chainId: "cip34:0-1", address: "addr_test1...", derivationPath: "m/1852'/1815'/0'/0/0" }, // Cardano Pre-production
//   { chainId: "cip34:0-2", address: "addr_test1...", derivationPath: "m/1852'/1815'/0'/0/0" }, // Cardano Preview
// ]
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | &mdash; | Wallet name |
| `passphrase` | `string` | `undefined` | Encryption passphrase |
| `words` | `number` | `12` | Mnemonic word count |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

**Returns:** `WalletInfo`

#### `listWallets(vaultPath?)`

List all wallets in the vault.

```javascript
const wallets = listWallets();
console.log(wallets.length); // => 1
```

**Returns:** `WalletInfo[]`

#### `getWallet(nameOrId, vaultPath?)`

Look up a wallet by name or UUID.

```javascript
const wallet = getWallet("agent-treasury");
```

**Returns:** `WalletInfo`

#### `deleteWallet(nameOrId, vaultPath?)`

Delete a wallet from the vault.

```javascript
deleteWallet("agent-treasury");
```

#### `renameWallet(nameOrId, newName, vaultPath?)`

Rename a wallet.

```javascript
renameWallet("old-name", "new-name");
```

#### `exportWallet(nameOrId, passphrase?, vaultPath?)`

Export a wallet's secret.

- **Mnemonic wallets** return the phrase string.
- **Private key wallets** return a JSON string with per-curve key material:

```javascript
// Mnemonic wallet
const phrase = exportWallet("mn-wallet");
// => "goose puzzle decorate much ..."

// Private key wallet
const keysJson = exportWallet("pk-wallet");
const keys = JSON.parse(keysJson);
// => { secp256k1: "4c0883a6...", ed25519: "9d61b19d...", ed25519_bip32: "..." }
```

**Returns:** `string`

### Import

#### `importWalletMnemonic(name, mnemonic, passphrase?, index?, vaultPath?)`

Import a wallet from a BIP-39 mnemonic. Derives all 13 chain-family accounts via HD paths.

```javascript
const wallet = importWalletMnemonic("imported", "goose puzzle decorate ...");
```

**Returns:** `WalletInfo`

#### `importWalletPrivateKey(name, privateKeyHex, passphrase?, vaultPath?, chain?, secp256k1Key?, ed25519Key?, ed25519Bip32Key?)`

Import a wallet from a hex-encoded private key. All registered chains are supported: the provided key is used for its curve's chains, and a random key is generated for the other curves.

The optional `chain` parameter specifies which chain the key originates from to determine the curve. Defaults to `"evm"` (secp256k1).

Alternatively, provide explicit keys for each curve via `secp256k1Key`, `ed25519Key`, and `ed25519Bip32Key`. When all are given, `privateKeyHex` and `chain` are ignored.

```javascript
// Import an EVM private key — generates a random Ed25519 key for Solana/Sui/TON and a random Ed25519Bip32 key for Cardano
const wallet = importWalletPrivateKey("from-evm", "4c0883a691...");
console.log(wallet.accounts.length); // => 15

// Import a Solana private key — generates a random secp256k1 key for EVM/BTC/etc and a random Ed25519Bip32 for Cardano.
const wallet2 = importWalletPrivateKey(
  "from-solana", "9d61b19d...", undefined, undefined, "solana"
);
console.log(wallet2.accounts.length); // => 15

// Import explicit keys for all curves
const wallet3 = importWalletPrivateKey(
  "all-keys", "", undefined, undefined, undefined,
  "4c0883a691...",  // secp256k1 key
  "9d61b19d...",    // ed25519 key
  "cafe..."         // ed25519Bip32 key
);
console.log(wallet3.accounts.length); // => 15
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | &mdash; | Wallet name |
| `privateKeyHex` | `string` | &mdash; | Hex-encoded private key (with or without `0x` prefix). Ignored when all three curve keys (`secp256k1Key`, `ed25519Key`, and `ed25519Bip32Key`) are provided. |
| `passphrase` | `string` | `undefined` | Encryption passphrase |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |
| `chain` | `string` | `"evm"` | Source chain: `"evm"`, `"bitcoin"`, `"cosmos"`, `"tron"`, `"filecoin"` (secp256k1) or `"solana"`, `"sui"`, `"ton"` (Ed25519) or `"cardano"` (Ed25519-BIP32) |
| `secp256k1Key` | `string` | `undefined` | Explicit secp256k1 private key (hex). With `ed25519Key`, fills that curve; otherwise overrides random secp256k1 when using a primary `privateKeyHex`. |
| `ed25519Key` | `string` | `undefined` | Explicit Ed25519 private key (hex). Same pairing rules as `secp256k1Key`. |
| `ed25519Bip32Key` | `string` | `undefined` | Explicit Ed25519-BIP32 extended private key, 96/192 bytes as hex. Random if omitted. |

**Returns:** `WalletInfo`

### Signing

#### `signMessage(wallet, chain, message, passphrase?, encoding?, index?, address?, vaultPath?)`

Sign a message with chain-specific formatting.

```javascript
const result = signMessage("agent-treasury", "evm", "hello world");
console.log(result.signature);  // hex string
console.log(result.recoveryId); // 0 or 1
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `wallet` | `string` | &mdash; | Wallet name or ID |
| `chain` | `string` | &mdash; | Chain family |
| `message` | `string` | &mdash; | Message to sign |
| `passphrase` | `string` | `undefined` | Decryption passphrase |
| `encoding` | `string` | `"utf8"` | `"utf8"` or `"hex"` |
| `index` | `number` | `0` | Account index |
| `address` | `string` | `undefined` | Optional address that will be used to sign the message (e.g. stake/base/enterprise address on Cardano) |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

**Returns:** `SignResult`

#### `signHash(wallet, chain, hashHex, passphrase?, index?, vaultPath?)`

Sign a raw 32-byte hash without adding a message prefix.

This operation is only supported on secp256k1-backed chains. For EVM, the returned `recoveryId` is the raw `yParity` value (`0` or `1`).

```javascript
const result = signHash(
  "agent-treasury",
  "base",
  "11".repeat(32),
);
console.log(result.signature);
console.log(result.recoveryId); // 0 or 1
```

#### `signAuthorization(wallet, chain, address, nonce, passphrase?, index?, vaultPath?)`

Sign an EIP-7702 authorization tuple. This is equivalent to:

`signHash(wallet, chain, keccak256(0x05 || rlp([eip155_chain_id(chain), address, nonce])))`

`chain` must resolve to an EVM chain. `nonce` accepts decimal or `0x`-prefixed hex. If you need a nonstandard authorization tuple, such as chain ID `0`, precompute the digest and call `signHash`.

```javascript
const result = signAuthorization(
  "agent-treasury",
  "base",
  "0x1111111111111111111111111111111111111111",
  "7",
);
console.log(result.signature);
console.log(result.recoveryId); // 0 or 1
```

#### `signTypedData(wallet, chain, typedDataJson, passphrase?, index?, address?, vaultPath?)`

Sign EIP-712 typed structured data (EVM only).

```javascript
const typedData = JSON.stringify({
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "chainId", type: "uint256" },
    ],
    Transfer: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
  },
  primaryType: "Transfer",
  domain: { name: "MyDApp", chainId: "1" },
  message: { to: "0xabc...", amount: "1000" },
});

const result = signTypedData("agent-treasury", "evm", typedData);
console.log(result.signature);  // hex string
console.log(result.recoveryId); // 27 or 28
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `wallet` | `string` | &mdash; | Wallet name or ID |
| `chain` | `string` | &mdash; | Must be an EVM chain |
| `typedDataJson` | `string` | &mdash; | JSON string of EIP-712 typed data |
| `passphrase` | `string` | `undefined` | Decryption passphrase |
| `index` | `number` | `0` | Account index |
| `address` | `string` | `undefined` | Optional address that will be used to sign the message (e.g. stake/base/enterprise address on Cardano) |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

**Returns:** `SignResult`

#### `signTransaction(wallet, chain, txHex, passphrase?, index?, vaultPath?)`

Sign a raw transaction (hex-encoded bytes).

```javascript
const result = signTransaction("agent-treasury", "evm", "02f8...");
console.log(result.signature);
```

**Returns:** `SignResult`

#### `signAndSend(wallet, chain, txHex, passphrase?, index?, rpcUrl?, vaultPath?)`

Sign and broadcast a transaction. If `rpcUrl` is omitted, OWS resolves it from explicit config overrides or built-in defaults.

```javascript
const result = signAndSend(
  "agent-treasury", "evm", "02f8...",
  undefined, undefined, "https://mainnet.infura.io/v3/..."
);
console.log(result.txHash);
```

**Returns:** `SendResult`

### Policy Management

#### `createPolicy(policyJson, vaultPath?)`

Register a policy from a JSON string.

```javascript
const policy = JSON.stringify({
  id: "base-only",
  name: "Base only until April",
  version: 1,
  created_at: "2026-03-22T00:00:00Z",
  rules: [
    { type: "allowed_chains", chain_ids: ["eip155:8453"] },
    { type: "expires_at", timestamp: "2026-04-01T00:00:00Z" },
  ],
  action: "deny",
});

createPolicy(policy);
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `policyJson` | `string` | &mdash; | JSON string of the policy definition |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

#### `listPolicies(vaultPath?)`

List all registered policies.

```javascript
const policies = listPolicies();
console.log(policies); // => [{ id: "base-only", name: "Base only until April", ... }]
```

**Returns:** `object[]`

#### `getPolicy(id, vaultPath?)`

Get a single policy by ID.

```javascript
const policy = getPolicy("base-only");
console.log(policy.name); // => "Base only until April"
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | `string` | &mdash; | Policy ID |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

**Returns:** `object`

#### `deletePolicy(id, vaultPath?)`

Delete a policy by ID.

```javascript
deletePolicy("base-only");
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | `string` | &mdash; | Policy ID |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

### API Key Management

#### `createApiKey(name, walletIds, policyIds, passphrase, expiresAt?, vaultPath?)`

Create an API key for agent access to wallets. Returns the raw token (shown once &mdash; caller must save it) and key metadata.

```javascript
const key = createApiKey(
  "claude-agent",
  ["my-wallet"],
  ["base-only"],
  "my-passphrase",
);
console.log(key.token); // => "ows_key_a1b2c3d4..." (save this)
console.log(key.id);
console.log(key.name);
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | &mdash; | Human-readable key name |
| `walletIds` | `string[]` | &mdash; | Wallet names or IDs this key can access |
| `policyIds` | `string[]` | &mdash; | Policy IDs to enforce on this key |
| `passphrase` | `string` | &mdash; | Vault passphrase (needed to re-encrypt wallet secrets for the key) |
| `expiresAt` | `string` | `undefined` | ISO 8601 expiry timestamp |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

**Returns:** `ApiKeyResult` &mdash; `{ token: string, id: string, name: string }`

#### `listApiKeys(vaultPath?)`

List all API keys. Tokens are never returned.

```javascript
const keys = listApiKeys();
keys.forEach((k) => console.log(k.id, k.name));
```

**Returns:** `object[]`

#### `revokeApiKey(id, vaultPath?)`

Revoke (delete) an API key by ID.

```javascript
revokeApiKey("key-id");
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | `string` | &mdash; | API key ID |
| `vaultPath` | `string` | `~/.ows` | Custom vault directory root |

## Custom Vault Path

Every function accepts an optional `vaultPath` parameter. When omitted, the default vault root at `~/.ows/` is used. This is useful for testing or running isolated environments:

```javascript
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmpVault = mkdtempSync(join(tmpdir(), "ows-test-"));

const wallet = createWallet("test-wallet", undefined, 12, tmpVault);
// ... use wallet ...

rmSync(tmpVault, { recursive: true, force: true });
```
