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
