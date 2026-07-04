# Supported Chains

> Canonical reference for OWS chain families, identifiers, derivation paths, and address formats.

## Identifier Types

OWS uses [CAIP](https://chainagnostic.org/) identifiers throughout. All wallet files, policy contexts, audit logs, and API parameters use these canonical formats — never shorthand aliases.

```typescript
/** CAIP-2 chain identifier: namespace:reference */
type ChainId = `${string}:${string}`;
// e.g. "eip155:8453", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

/** CAIP-10 account identifier: chain_id:address */
type AccountId = `${ChainId}:${string}`;
// e.g. "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"

/** Asset identifier: chain_id:contract_address or chain_id:native */
type AssetId = `${ChainId}:${string}`;
// e.g. "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" (USDC on Base)
// e.g. "eip155:8453:native" (ETH on Base)
```

The `native` token refers to the chain's native currency (ETH, SOL, SUI, XRP, BTC, ATOM, TRX, TON, etc.).

## Chain Families

OWS groups chains into families that share a cryptographic curve and address derivation scheme. A single mnemonic derives accounts for all families.

| Family | Curve | Coin Type | Derivation Path | Address Format | CAIP-2 Namespace |
|---|---|---|---|---|---|
| EVM | secp256k1 | 60 | `m/44'/60'/0'/0/{index}` | EIP-55 checksummed hex (`0x...`) | `eip155` |
| Solana | ed25519 | 501 | `m/44'/501'/{index}'/0'` | Base58-encoded public key | `solana` |
| Bitcoin | secp256k1 | 0 | `m/84'/0'/0'/0/{index}` | Bech32 native segwit (`bc1...`) | `bip122` |
| Cosmos | secp256k1 | 118 | `m/44'/118'/0'/0/{index}` | Bech32 (`cosmos1...`) | `cosmos` |
| Tron | secp256k1 | 195 | `m/44'/195'/0'/0/{index}` | Base58Check (`T...`) | `tron` |
| TON | ed25519 | 607 | `m/44'/607'/{index}'` | Base64url wallet v5r1 (`UQ...`) | `ton` |
| Sui | ed25519 | 784 | `m/44'/784'/{index}'/0'/0'` | `0x` + BLAKE2b-256 hex (32 bytes) | `sui` |
| XRPL | secp256k1 | 144 | `m/44'/144'/0'/0/{index}` | Base58Check (`r...`) | `xrpl` |
| Spark | secp256k1 | 8797555 | `m/84'/0'/0'/0/{index}` | `spark:` + compressed pubkey hex | `spark` |
| Filecoin | secp256k1 | 461 | `m/44'/461'/0'/0/{index}` | `f1` + base32(blake2b-160) | `fil` |
| NEAR | ed25519 | 397 | `m/44'/397'/{index}'` | 64-char lowercase hex of pubkey (implicit account) | `near` |

## Known Networks

Each network has a canonical chain identifier. Endpoint discovery and transport configuration are implementation-specific and are therefore out of scope for the core specification.

### EVM Networks

| Name | CAIP-2 Chain ID |
|---|---|
| Ethereum | `eip155:1` |
| Polygon | `eip155:137` |
| Arbitrum | `eip155:42161` |
| Optimism | `eip155:10` |
| Base | `eip155:8453` |
| Plasma | `eip155:9745` |
| BSC | `eip155:56` |
| Avalanche | `eip155:43114` |
| Etherlink | `eip155:42793` |
| Tempo | `eip155:4217` |
| Hyperliquid | `eip155:999` |
| Sepolia | `eip155:11155111` |
| Base Sepolia | `eip155:84532` |
| Arbitrum Sepolia | `eip155:421614` |
| Optimism Sepolia | `eip155:11155420` |
| Polygon Amoy | `eip155:80002` |

### Non-EVM Networks

| Name | CAIP-2 Chain ID |
|---|---|
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| Bitcoin | `bip122:000000000019d6689c085ae165831e93` |
| Cosmos | `cosmos:cosmoshub-4` |
| Tron | `tron:mainnet` |
| TON | `ton:mainnet` |
| Sui | `sui:mainnet` |
| XRPL | `xrpl:mainnet` |
| Spark | `spark:mainnet` |
| Filecoin | `fil:mainnet` |
| NEAR | `near:mainnet` |
| NEAR (testnet) | `near:testnet` |

Implementations MAY ship convenience endpoint defaults, but those defaults are deployment choices rather than OWS interoperability requirements.

## Shorthand Aliases

Implementations MAY support shorthand aliases in CLI contexts:

```
ethereum  → eip155:1
base      → eip155:8453
plasma    → eip155:9745
polygon   → eip155:137
arbitrum  → eip155:42161
optimism  → eip155:10
bsc       → eip155:56
avalanche → eip155:43114
etherlink → eip155:42793
tempo       → eip155:4217
hyperliquid       → eip155:999
sepolia           → eip155:11155111
base-sepolia      → eip155:84532
arbitrum-sepolia  → eip155:421614
optimism-sepolia  → eip155:11155420
polygon-amoy      → eip155:80002
solana    → solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
bitcoin   → bip122:000000000019d6689c085ae165831e93
cosmos    → cosmos:cosmoshub-4
tron      → tron:mainnet
ton       → ton:mainnet
sui       → sui:mainnet
xrpl          → xrpl:mainnet
xrpl-mainnet  → xrpl:mainnet
xrpl-testnet  → xrpl:testnet
xrpl-devnet   → xrpl:devnet
spark     → spark:mainnet
filecoin  → fil:mainnet
near          → near:mainnet
near-testnet  → near:testnet
```

Aliases MUST be resolved to full CAIP-2 identifiers before any processing. They MUST NOT appear in wallet files, policy files, or audit logs.

## HD Derivation

OWS uses BIP-39 mnemonics as the root key material, with BIP-32/BIP-44 derivation for all chains:

```
Mnemonic (BIP-39)
    │
    ▼
Master Seed (512 bits via PBKDF2)
    │
    ├── m/44'/60'/0'/0/0    → EVM Account 0
    ├── m/44'/501'/0'/0'    → Solana Account 0
    ├── m/84'/0'/0'/0/0     → Bitcoin Account 0 (native segwit)
    ├── m/44'/118'/0'/0/0   → Cosmos Account 0
    ├── m/44'/195'/0'/0/0   → Tron Account 0
    ├── m/44'/607'/0'       → TON Account 0
    ├── m/44'/784'/0'/0'/0' → Sui Account 0
    ├── m/44'/144'/0'/0/0   → XRPL Account 0
    ├── m/84'/0'/0'/0/0     → Spark Account 0
    ├── m/44'/461'/0'/0/0   → Filecoin Account 0
    └── m/44'/397'/0'       → NEAR Account 0
```

For mnemonic-based wallets, a single mnemonic derives accounts across all supported chains. Those wallet files store the encrypted mnemonic, and the signer derives the appropriate private key using each chain's coin type and derivation path. Wallets imported from raw private keys instead store encrypted curve-key material directly.

## Adding a New Chain

1. Define a canonical chain identifier, preferably using CAIP-2.
2. Specify the derivation path and coin type, if applicable.
3. Specify the address encoding and checksum behavior.
4. Define the signing and message-signing behavior required by `02-signing-interface.md`.
5. Document any transaction serialization rules needed to produce deterministic signatures.

No changes to OWS core, the signing interface, or the policy engine are needed.

## References

- [CAIP-2: Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10: Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-44: Registered Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
