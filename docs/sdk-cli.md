# CLI Reference

> Command-line interface for managing wallets, signing, and key operations.

This document is non-normative reference implementation documentation. CLI syntax does not define the OWS standard.

## Install

```bash
curl -fsSL https://docs.openwallet.sh/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/open-wallet-standard/core.git
cd core/ows
cargo build --workspace --release
```

## Wallet Commands

### `ows wallet create`

Create a new wallet. Generates a BIP-39 mnemonic and derives addresses for all supported chains.

```bash
ows wallet create --name "my-wallet"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--show-mnemonic` | Display the generated mnemonic once at creation time |
| `--words <12\|24>` | Mnemonic word count (default: 12) |

Output:

```
Created wallet 3198bc9c-...
  eip155:1                              0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp  7Kz9...    m/44'/501'/0'/0'
  sui:mainnet                              0x...      m/44'/784'/0'/0'/0'
  bip122:000000000019d6689c085ae165831e93   bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmoshub-4                     cosmos1... m/44'/118'/0'/0/0
  tron:mainnet                           TKLm...    m/44'/195'/0'/0/0
  xrpl:mainnet                           rHsM...    m/44'/144'/0'/0/0
```

### `ows wallet import`

Import an existing wallet from a mnemonic or private key.

```bash
# Import from mnemonic (reads from OWS_MNEMONIC env or stdin)
echo "goose puzzle decorate ..." | ows wallet import --name "imported" --mnemonic

# Import from private key (reads from OWS_PRIVATE_KEY env or stdin)
echo "4c0883a691..." | ows wallet import --name "from-evm" --private-key

# Import an Ed25519 key (e.g. from Solana)
echo "9d61b19d..." | ows wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves via environment variables
OWS_SECP256K1_KEY="4c0883a691..." \
OWS_ED25519_KEY="9d61b19d..." \
  ows wallet import --name "both"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private key import (determines curve, default: evm) |
| `--index <N>` | Account index for HD derivation (mnemonic only, default: 0) |
| `OWS_SECP256K1_KEY` | Explicit secp256k1 private key via environment variable |
| `OWS_ED25519_KEY` | Explicit Ed25519 private key via environment variable |

Private key imports generate all 9 chain accounts: the provided key is used for its curve's chains, and a random key is generated for the other curve. Use `OWS_SECP256K1_KEY` and `OWS_ED25519_KEY` together to supply both keys explicitly.

### `ows wallet export`

Export a wallet's secret to stdout. Requires an interactive terminal.

```bash
ows wallet export --wallet "my-wallet"
```

- Mnemonic wallets output the phrase.
- Private key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.

If the wallet is passphrase-protected, you will be prompted.

### `ows wallet list`

List all wallets in the vault.

```bash
ows wallet list
```

### `ows wallet info`

Show vault path and supported chains.

```bash
ows wallet info
```

## Policy Commands

### `ows policy create`

Register a policy from a JSON file.

```bash
ows policy create --file base-policy.json
```

Policy JSON format:

```json
{
  "id": "base-only",
  "name": "Base and Sepolia until year end",
  "version": 1,
  "created_at": "2026-03-22T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
    { "type": "expires_at", "timestamp": "2026-12-31T00:00:00Z" }
  ],
  "action": "deny"
}
```

Rules are AND-combined — all must pass. Supported declarative rule types:

| Rule | Description |
|------|-------------|
| `allowed_chains` | Deny if chain is not in the list |
| `expires_at` | Deny if current time is past the timestamp |

Policies can also specify an `executable` field for custom validation — receives PolicyContext on stdin, writes `{"allow": true}` or `{"allow": false, "reason": "..."}` to stdout.

### `ows policy list`

```bash
ows policy list
```

### `ows policy show`

```bash
ows policy show --id base-only
```

### `ows policy delete`

```bash
ows policy delete --id base-only --confirm
```

## Key Commands

### `ows key create`

Create an API key for agent access to one or more wallets. The owner's passphrase is required to re-encrypt the mnemonic under the token.

```bash
ows key create --name "claude-agent" \
  --wallet my-wallet \
  --policy base-only \
  --policy agent-expiry
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Key name (required) |
| `--wallet <NAME>` | Wallet name or ID (repeatable) |
| `--policy <ID>` | Policy ID to attach (repeatable) |
| `--expires-at <TS>` | Optional expiry (ISO-8601) |

Output includes the raw token (`ows_key_...`) — shown once. The agent uses this token in place of the passphrase.

### `ows key list`

```bash
ows key list
```

Lists all keys with ID, name, wallets, policies, and creation time. Tokens are never displayed.

### `ows key revoke`

```bash
ows key revoke --id <key-id> --confirm
```

Deletes the key file. The encrypted secret copy is gone — the token becomes useless.

## End-to-End Example: Agent Access

```bash
# Create a wallet
ows wallet create --name agent-treasury

# Define a policy: Base chain only, expires at end of year
cat > policy.json << 'EOF'
{
  "id": "agent-limits",
  "name": "Agent Safety Limits",
  "version": 1,
  "created_at": "2026-03-22T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "action": "deny"
}
EOF
ows policy create --file policy.json

# Create an API key with the policy attached
ows key create --name "claude" --wallet agent-treasury --policy agent-limits
# Output: ows_key_a1b2c3d4... (save this)

# Agent signs on Base — policy allows it
OWS_PASSPHRASE="ows_key_a1b2c3d4..." \
  ows sign tx --wallet agent-treasury --chain base --tx 0x02f8...

# Agent tries Ethereum mainnet — policy denies it
OWS_PASSPHRASE="ows_key_a1b2c3d4..." \
  ows sign tx --wallet agent-treasury --chain ethereum --tx 0x02f8...
# error: policy denied: chain eip155:1 not in allowlist

# Owner signs with the wallet passphrase — no policy enforcement
OWS_PASSPHRASE="your-wallet-passphrase" \
  ows sign tx --wallet agent-treasury --chain ethereum --tx 0x02f8...
# Owner mode bypasses all policies

# Revoke the agent's access
ows key revoke --id <key-id> --confirm
# Token is now useless
```

## Signing Commands

### `ows sign message`

Sign a message with chain-specific formatting (e.g., EIP-191 for EVM, `\x19TRON Signed Message` for Tron).

```bash
# EVM (Ethereum mainnet)
ows sign message --wallet "my-wallet" --chain ethereum --message "hello world"

# Solana
ows sign message --wallet "my-wallet" --chain solana --message "hello world"

# Bitcoin
ows sign message --wallet "my-wallet" --chain bitcoin --message "hello world"

# Base via bare chain ID
ows sign message --wallet "my-wallet" --chain 8453 --message "hello world"
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain name (`ethereum`, `base`, `arbitrum`, …), CAIP-2 ID (`eip155:8453`), or bare EVM chain ID (`8453`) |
| `--message <MSG>` | Message to sign |
| `--encoding <ENC>` | Message encoding: `utf8` (default) or `hex` |
| `--address <ADDR>` | Address that will be used to sign the message (e.g. stake/base/enterprise address on Cardano) |
| `--typed-data <JSON>` | EIP-712 typed data JSON (EVM only) |
| `--index <N>` | Account index (HD derivation; default `0`) |
| `--json` | Output structured JSON |

### `ows sign tx`

Sign a raw transaction (hex-encoded bytes).

```bash
ows sign tx --wallet "my-wallet" --chain ethereum --tx "02f8..."
ows sign tx --wallet "my-wallet" --chain solana --tx "deadbeef..."
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain name (`ethereum`, `base`, `arbitrum`, …), CAIP-2 ID (`eip155:8453`), or bare EVM chain ID (`8453`) |
| `--tx <HEX>` | Hex-encoded transaction bytes |
| `--json` | Output structured JSON |

Passphrases and API tokens are supplied via `OWS_PASSPHRASE` or an interactive prompt, not a dedicated `--passphrase` flag.

## Mnemonic Commands

### `ows mnemonic generate`

Generate a new BIP-39 mnemonic phrase.

```bash
ows mnemonic generate --words 24
```

### `ows mnemonic derive`

Derive an address from a mnemonic for a given chain. Reads the mnemonic from the `OWS_MNEMONIC` environment variable or stdin.

```bash
echo "word1 word2 ..." | ows mnemonic derive --chain ethereum
```

## Payment Commands

### `ows pay request`

Make an HTTP request with automatic x402 payment handling. If the server returns 402, the CLI detects the payment requirements, signs an EIP-3009 `TransferWithAuthorization` for USDC, and retries with the payment header.

```bash
ows pay request "https://api.example.com/data" --wallet "my-wallet"
ows pay request "https://api.example.com/submit" --wallet "my-wallet" --method POST --body '{"query":"test"}'
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name (required) |
| `--method <METHOD>` | HTTP method: GET, POST, PUT, DELETE, PATCH (default: GET) |
| `--body <JSON>` | Request body (JSON string) |
| `--no-passphrase` | Skip passphrase prompt (use empty passphrase) |

### `ows pay discover`

Discover x402-enabled services from the Bazaar directory. Supports pagination and client-side search filtering.

```bash
ows pay discover
ows pay discover --query "weather"
ows pay discover --limit 20 --offset 100
```

| Flag | Description |
|------|-------------|
| `--query <SEARCH>` | Filter services by URL or description |
| `--limit <N>` | Max results per page (default: 100) |
| `--offset <N>` | Offset into results for pagination |

## Funding Commands

### `ows fund deposit`

Create a MoonPay deposit that generates multi-chain deposit addresses. Send crypto to any of the provided addresses and it will auto-convert to USDC on your chosen chain.

```bash
ows fund deposit --wallet "my-wallet"
ows fund deposit --wallet "my-wallet" --chain base
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name (required) |
| `--chain <CHAIN>` | Target chain (default: base) |

### `ows fund balance`

Check token balances for a wallet on a given chain.

```bash
ows fund balance --wallet "my-wallet" --chain base
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name (required) |
| `--chain <CHAIN>` | Chain to query (required) |

## System Commands

### `ows update`

Update the `ows` binary to the latest release. Also updates Node.js and Python bindings if they are installed.

```bash
ows update
ows update --force   # re-download even if already on latest
```

### `ows uninstall`

Remove `ows` from the system. Also uninstalls Node.js and Python bindings if present.

```bash
ows uninstall          # keep wallet data
ows uninstall --purge  # also remove ~/.ows (all wallet data)
```

## File Layout

```
~/.ows/
  bin/
    ows                     # CLI binary
  wallets/
    <uuid>.json             # Encrypted wallet (AES-256-GCM + scrypt)
  policies/
    <id>.json               # Policy definitions (not secret)
  keys/
    <uuid>.json             # API key files (0600 permissions)
  logs/
    audit.jsonl             # Audit log
```
