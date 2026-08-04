# Reference Implementation Quickstart

> Non-normative setup guide for the current OWS reference implementation.

This document is not part of the core OWS specification. It describes one implementation's installer, CLI workflows, SDK package names, and service-payment integrations.

## Install

```bash
curl -fsSL https://docs.openwallet.sh/install.sh | bash
```

This installs the `ows` CLI, Node.js SDK, and Python bindings. Or install only what you need:

```bash
npm install @open-wallet-standard/core     # Node.js
npm install @open-wallet-standard/adapters # Node.js — viem, Solana, WDK adapters
pip install open-wallet-standard           # Python
```

## Create a wallet

A single command derives addresses for every chain family the implementation registers (15 accounts in the reference build — EVM through Cardano).

```bash
ows wallet create --name "agent-treasury"
```

```
Created wallet 3198bc9c-...
  eip155:1        0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4   7Kz9...    m/44'/501'/0'/0'
  bip122:0000     bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmo    cosmos1... m/44'/118'/0'/0/0
  tron:mainnet    TKLm...    m/44'/195'/0'/0/0
  ton:mainnet     UQ...      m/44'/607'/0'
  sui:mainnet     0x...      m/44'/784'/0'/0'/0'
  cip34:1-764824073 addr1...       payment m/1852'/1815'/0'/0/0 + stake m/1852'/1815'/0'/2/0
  cip34:0-1         addr_test1...  same paths; Pre-production testnet
  cip34:0-2         addr_test1...  same paths; Preview testnet
```

## Fund the wallet

Deposit crypto from any chain — it auto-converts to USDC on your target chain.

```bash
ows fund deposit --wallet agent-treasury --chain base
```

Check your balance:

```bash
ows fund balance --wallet agent-treasury --chain base
```

## Pay for services

OWS handles the full [x402](https://www.x402.org/) payment flow automatically. When a server returns `402 Payment Required`, the CLI signs the payment credential and retries — no extra code needed.

```bash
# GET request — payment handled automatically
ows pay request "https://api.example.com/data" --wallet agent-treasury

# POST with a body
ows pay request "https://api.example.com/query" \
  --wallet agent-treasury \
  --method POST \
  --body '{"prompt": "summarize this document"}'
```

Discover available services:

```bash
ows pay discover
ows pay discover --query "weather"
```

## Sign messages and transactions

```bash
# Sign a message
ows sign message --wallet agent-treasury --chain ethereum --message "hello"

# Sign a transaction
ows sign tx --wallet agent-treasury --chain solana --tx "deadbeef..."
```

## Use in code

### Node.js

```javascript
import { createWallet, signMessage, signTransaction } from "@open-wallet-standard/core";

// Create a wallet (once)
const wallet = createWallet("agent-treasury");

// Sign a message
const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);

// Sign a transaction
const tx = signTransaction("agent-treasury", "evm", "02f8...");
console.log(tx.signature);
```

### Python

```python
from open_wallet_standard import create_wallet, sign_message, sign_transaction

# Create a wallet (once)
wallet = create_wallet("agent-treasury")

# Sign a message
sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])

# Sign a transaction
tx = sign_transaction("agent-treasury", "evm", "02f8...")
print(tx["signature"])
```

## Set up agent access

Create a scoped API key so your agent can sign autonomously — without ever seeing the private key.

### 1. Define a policy

```bash
cat > policy.json << 'EOF'
{
  "id": "agent-limits",
  "name": "Base chain only, expires end of year",
  "version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "action": "deny"
}
EOF
ows policy create --file policy.json
```

### 2. Create an API key

```bash
ows key create --name "my-agent" --wallet agent-treasury --policy agent-limits
# => ows_key_a1b2c3d4...  (save this — shown once)
```

### 3. Use the token to sign

The agent passes the API token where the passphrase would go. OWS detects the `ows_key_` prefix, evaluates all attached policies, and only signs if every policy allows it.

```bash
# Agent signs on Base — policy allows it
OWS_PASSPHRASE="ows_key_a1b2c3d4..." \
  ows sign tx --wallet agent-treasury --chain base --tx 0x02f8...

# Agent tries Ethereum mainnet — policy denies it
OWS_PASSPHRASE="ows_key_a1b2c3d4..." \
  ows sign tx --wallet agent-treasury --chain ethereum --tx 0x02f8...
# error: policy denied: chain eip155:1 not in allowlist
```

```javascript
import { signTransaction } from "@open-wallet-standard/core";

// Agent uses the API token as the passphrase
const result = signTransaction(
  "agent-treasury", "base", "02f8...",
  "ows_key_a1b2c3d4..."
);
```

```python
from open_wallet_standard import sign_transaction

# Agent uses the API token as the passphrase
result = sign_transaction(
    "agent-treasury", "base", "02f8...",
    passphrase="ows_key_a1b2c3d4..."
)
```

### 4. Revoke access

```bash
ows key revoke --id <key-id> --confirm
```

The token becomes useless immediately — no key rotation needed.

## How it works

```
Agent / CLI / App
       │
       │  OWS Interface (SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Agent calls ows.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Enclave decrypts key
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │ Signing Enclave │  │
│  │ (isolated proc) │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.ows/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Next steps

- [CLI Reference](doc.html?slug=sdk-cli) — full list of commands
- [Node.js SDK](doc.html?slug=sdk-node) — API reference for Node.js
- [Python SDK](doc.html?slug=sdk-python) — API reference for Python
- [Policy Engine](doc.html?slug=03-policy-engine) — custom policies, executable hooks, and access control
- [Agent Access Layer](doc.html?slug=04-agent-access-layer) — architecture and security model
