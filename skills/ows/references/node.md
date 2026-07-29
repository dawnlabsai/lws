# Node.js SDK — `@open-wallet-standard/core`

```bash
npm install @open-wallet-standard/core
```

Native NAPI bindings — Rust core runs in-process, no subprocess or server.

## Types

```typescript
interface AccountInfo {
  chainId: string;        // CAIP-2 (e.g. "eip155:1")
  address: string;
  derivationPath: string; // e.g. "m/44'/60'/0'/0/0"
}

interface WalletInfo {
  id: string;             // UUID v4
  name: string;
  accounts: AccountInfo[];
  createdAt: string;      // ISO 8601
}

interface SignResult {
  signature: string;      // Hex-encoded
  recoveryId?: number;    // EVM/Tron only
}

interface SendResult {
  txHash: string;
}

interface ApiKeyResult {
  token: string;          // Raw token (shown once — caller must save it)
  id: string;             // Key file ID
  name: string;
}
```

## Mnemonic

```javascript
import { generateMnemonic, deriveAddress } from "@open-wallet-standard/core";

const phrase = generateMnemonic(12);       // or 24
const addr = deriveAddress(phrase, "evm"); // any chain: evm, solana, sui, bitcoin, cosmos, tron, ton, spark, filecoin, xrpl, nano, cardano
```

## Wallet Management

```javascript
import {
  createWallet,
  importWalletMnemonic,
  importWalletPrivateKey,
  listWallets,
  getWallet,
  deleteWallet,
  renameWallet,
  exportWallet,
} from "@open-wallet-standard/core";

// Create
const wallet = createWallet("my-wallet");
// createWallet(name, passphrase?, words?, vaultPath?)

// Import from mnemonic
const w1 = importWalletMnemonic("imported", "goose puzzle ...");
// importWalletMnemonic(name, mnemonic, passphrase?, index?, vaultPath?)

// Import from private key (default: evm/secp256k1)
const w2 = importWalletPrivateKey("from-evm", "4c0883a691...");

// Import Ed25519 key (solana/sui/ton)
const w3 = importWalletPrivateKey("from-sol", "9d61b19d...", undefined, undefined, "solana");

// Import explicit keys for all curves
const w4 = importWalletPrivateKey("all", "", undefined, undefined, undefined, "4c08...", "9d61...", "cafe...");
// importWalletPrivateKey(name, privateKeyHex, passphrase?, vaultPath?, chain?, secp256k1Key?, ed25519Key?, ed25519Bip32Key?)

// List / get / delete / rename / export
const wallets = listWallets();           // listWallets(vaultPath?)
const w = getWallet("my-wallet");        // getWallet(nameOrId, vaultPath?)
deleteWallet("my-wallet");               // deleteWallet(nameOrId, vaultPath?)
renameWallet("old", "new");              // renameWallet(nameOrId, newName, vaultPath?)
const secret = exportWallet("my-wallet"); // exportWallet(nameOrId, passphrase?, vaultPath?)
// Returns mnemonic string or JSON: {"secp256k1":"hex","ed25519":"hex","ed25519_bip32":"hex"}
```

## Signing

```javascript
import { signMessage, signTransaction, signAndSend } from "@open-wallet-standard/core";

// Sign message
const sig = signMessage("my-wallet", "evm", "hello world");
// sig.signature => hex string
// sig.recoveryId => 0 or 1 (EVM/Tron only)
// signMessage(wallet, chain, message, passphrase?, encoding?, index?, address?, vaultPath?)

// Sign transaction
const txSig = signTransaction("my-wallet", "evm", "02f8...");
// signTransaction(wallet, chain, txHex, passphrase?, index?, vaultPath?)

// Sign and broadcast
const result = signAndSend("my-wallet", "evm", "02f8...", undefined, undefined, "https://rpc...");
// result.txHash => "0x..."
// signAndSend(wallet, chain, txHex, passphrase?, index?, rpcUrl?, vaultPath?)
```

## EIP-712 Typed Data

```javascript
import { signTypedData } from "@open-wallet-standard/core";

const sig = signTypedData("my-wallet", "evm", '{"types":...}');
// sig.signature => hex string
// sig.recoveryId => 0 or 1
// signTypedData(wallet, chain, typedDataJson, passphrase?, index?, address?, vaultPath?)
```

## Policy Management

```javascript
import { createPolicy, listPolicies, getPolicy, deletePolicy } from "@open-wallet-standard/core";

// Register a policy from a JSON string
createPolicy('{"id":"my-policy","rules":[...]}');
// createPolicy(policyJson, vaultPath?)

// List all registered policies
const policies = listPolicies(); // listPolicies(vaultPath?)

// Get a single policy by ID
const policy = getPolicy("my-policy"); // getPolicy(id, vaultPath?)

// Delete a policy by ID
deletePolicy("my-policy"); // deletePolicy(id, vaultPath?)
```

## API Key Management

```javascript
import { createApiKey, listApiKeys, revokeApiKey } from "@open-wallet-standard/core";

// Create an API key scoped to specific wallets and policies
const key = createApiKey("claude-agent", ["wallet-id"], ["policy-id"], "passphrase");
// key.token => raw token (shown once — save it)
// key.id => key file ID
// key.name => "claude-agent"
// createApiKey(name, walletIds, policyIds, passphrase, expiresAt?, vaultPath?)

// Optional: set expiry (ISO-8601)
const tmpKey = createApiKey("tmp", ["wallet-id"], [], "passphrase", "2026-04-01T00:00:00Z");

// List all API keys (tokens are never returned)
const keys = listApiKeys(); // listApiKeys(vaultPath?)

// Revoke an API key
revokeApiKey("key-id"); // revokeApiKey(id, vaultPath?)
```

## Custom Vault Path

Every function accepts an optional `vaultPath` parameter (last argument). Useful for testing:

```javascript
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const vault = mkdtempSync(join(tmpdir(), "ows-"));
const wallet = createWallet("test", undefined, 12, vault);
```
