# Cardano Support — Technical Specification

> Status: work in progress. This document specifies the Cardano integration parts
> that are **implemented** in this fork, and flags the parts that are still
> **planned**. The implemented surface is:
>
> 1. **Analysis, architecture, and setup** — codebase familiarization, build/test
>    pipeline, and a map of where Cardano fits into the existing abstractions (see
>    [Analysis, Architecture, and Setup](#analysis-architecture-and-setup)).
> 2. **CAIP-2 / CAIP-10 addressing abstraction**
> 3. **Key derivation and cryptography — Ed25519-BIP32**
> 4. **Implementing the chain plugin interface** — Shelley address encoding
>    (base/enterprise/reward), CIP-8 (COSE) message signing, and transaction
>    signing/witness encoding, all via `cardano-serialization-lib` and its
>    `cardano-message-signing` companion (see
>    [Transaction and Message Signing](#3-transaction-and-message-signing-chain-plugin-interface)).
> 5. **Policy engine support** — parsing an unsigned Cardano transaction (CBOR) into
>    the chain-agnostic `TransactionContext` that the OWS Policy Engine evaluates,
>    resolving input UTxO values via the configured Cardano RPC provider (Koios or
>    Blockfrost) so that ADA
>    and native-asset flows can be computed per address (see
>    [Policy Engine Support](#4-policy-engine-support)).
> 6. **Address balance fetching** — ADA and native-asset balances for a Cardano
>    address through `CardanoRpcProvider::get_balances` (see
>    [Address balance fetching](#5-address-balance-fetching)).
> 7. **Pluggable RPC providers** — a provider-agnostic `CardanoRpcProvider` trait
>    with keyless **Koios** as the default and **Blockfrost** as an authenticated
>    opt-in (see [Provider selection](#provider-selection)).
> 8. **Documentation and bindings** — this document, plus the optional `address`
>    argument exposed through the CLI and the Node/Python bindings (see
>    [§3.6](#36-address-aware-sign_message-across-all-chains)).
>
> Transaction *building* (input selection, fee/change calculation) remains out of
> scope and is tracked separately; the signer operates on an already-assembled
> unsigned transaction (CBOR).

## Abstract

This specification adds Cardano mainnet support to the Open Wallet Standard (OWS)
reference implementation while preserving OWS's chain-agnostic, local-first design.
It introduces the `cip34` CAIP-2 namespace and registers Cardano mainnet, preprod,
and preview networks with canonical chain identifiers, a coin type, and default
(keyless) Koios RPC endpoints, with optional Blockfrost support for deployments
that prefer an authenticated provider. On the cryptographic side, it adds a new
`Ed25519Bip32` curve (Ed25519-V2 / BIP32-Ed25519) implemented generically via the
`ed25519-bip32` crate, together with the Cardano Icarus master-key scheme and
CIP-1852 hierarchical derivation. Cardano accounts are derived from two credentials
— a payment credential (`role = 0`) and a stake credential (`role = 2`) — which
diverges from OWS's prior assumption that one account maps to a single derivation
path; the key-storage and derivation layers were extended to carry the two
96-byte extended private keys required to assemble a Shelley base address. On top
of this foundation, the chain plugin interface (`ChainSigner`) is fully
implemented: Shelley **base**, **enterprise**, and **reward** address encoding;
raw Ed25519 signing; CIP-8 message signing (COSE `COSE_Sign1` structures); and
transaction signing that produces and CBOR-encodes the `Vkeywitness`es required to
make a transaction submittable. Address encoding, transaction (de)serialization,
and witness construction use `cardano-serialization-lib` (CSL), while the COSE
message structures use Emurgo's `cardano-message-signing` companion library.
Finally, it wires Cardano into the OWS Policy Engine: `make_transaction_context`
parses an unsigned transaction (CBOR) and, because UTxO inputs carry no value,
resolves them through the configured Cardano RPC provider to compute per-address ADA
and native-asset flows (`TransactionEffect`s) that built-in and executable policies
can evaluate before a key is used.

## Motivation

OWS already supports Ed25519 chains (Solana, TON, NEAR) using SLIP-10 derivation,
and secp256k1 chains using BIP-32. Cardano cannot reuse either path:

- **Curve / derivation scheme.** Cardano uses BIP32-Ed25519 ("Ed25519-V2"),
  which extends a 64-byte Ed25519 extended secret key with a 32-byte chain code
  (96 bytes total) and supports both hardened and **non-hardened** child
  derivation. SLIP-10 ed25519 (used by Solana et al.) is hardened-only and is not
  compatible with Cardano wallets.
- **Master key generation.** Cardano (Icarus) derives the root key from the raw
  BIP-39 **entropy** via PBKDF2-HMAC-SHA512, not from the BIP-39 _seed_ used by
  BIP-32 / SLIP-10.
- **Multi-credential addresses.** A Cardano Shelley address is built from two
  independent credentials at two different CIP-1852 derivation paths (payment and
  stake). OWS previously assumed a single derivation path produces a single
  address.
- **Identifier namespace.** Cardano is not an EVM/`eip155`, `solana`, `cosmos`,
  etc. chain; it needs its own CAIP-2 namespace and a deterministic chain
  identifier.

The existing abstractions (`Curve`, `HdDeriver`, `ChainType`, `Chain`,
`ChainSigner`) therefore had to be extended rather than reused as-is.

## Analysis, Architecture, and Setup

### Cryptographic stack

OWS already ships a broad cryptographic toolkit in `ows-signer`. The relevant
existing primitives and the libraries that provide them:

| Concern                       | Library (crate)                          | Used by / notes                                   |
| ----------------------------- | ---------------------------------------- | ------------------------------------------------- |
| secp256k1 ECDSA               | `k256`                                   | EVM, Bitcoin, Cosmos, Tron, XRPL, Spark, Filecoin |
| BIP-32 derivation (secp256k1) | `coins-bip32`                            | all secp256k1 families                            |
| Ed25519 signatures            | `ed25519-dalek`                          | Solana, TON, Sui, NEAR                            |
| SLIP-10 ed25519 derivation    | in-house (HMAC-SHA512 over `hmac`/`sha2`)| hardened-only ed25519 families                    |
| BIP-39 mnemonics              | `coins-bip39`                            | seed + entropy extraction                         |
| Hashing                       | `sha2`, `sha3`, `ripemd`, `blake2`       | address + tx hashing across families              |
| Address encodings             | `bech32`, `bs58` (+check), `base64`      | segwit/bech32, base58check, etc.                  |
| At-rest encryption            | `aes-gcm` + `scrypt`/`hkdf` (`CryptoEnvelope`) | encrypted wallet files                      |
| Secret hygiene                | `zeroize` (`SecretBytes`)                | all key material is zeroized on drop              |

Cardano introduces two additional, Cardano-specific dependencies:

- **`ed25519-bip32` (0.4.1)** — BIP32-Ed25519 ("Ed25519-V2") key derivation:
  96-byte extended private keys (`XPRV_SIZE`), `DerivationScheme::V2`, hardened
  **and** non-hardened children, and `normalize_bytes_force3rd` for valid root
  keys. Chosen so derivation stays in the generic `HdDeriver`, rather than pulling
  a full chain SDK into the key path.
- **`cardano-serialization-lib` (CSL, 14.1.1)** — the canonical Cardano library
  for network parameters (`NetworkInfo`), address construction
  (`BaseAddress`/`EnterpriseAddress`/`RewardAddress`, `Credential`), extended-key
  helpers (`Bip32PrivateKey`), and CBOR transaction (de)serialization
  (`FixedTransaction`, `make_vkey_witness`, `Vkeywitness`). It is used for network
  parameters, Shelley address encoding, and transaction signing/witness encoding.
  Note CSL also pulls in `pbkdf2`, which we use directly for the Icarus master-key
  step.
- **`emurgo-cardano-message-signing` (1.1.0)** — Emurgo's COSE companion to CSL,
  used exclusively for CIP-8 message signing. It provides the `COSESign1Builder`,
  `HeaderMap`/`Headers`/`ProtectedHeaderMap`/`Label`, `AlgorithmId::EdDSA`, and
  `SignedMessage`/CBOR helpers needed to build and serialize the COSE `Sig_structure`
  and `COSE_Sign1` payload that Cardano wallets expect.

### Peculiarities of Cardano vs. other OWS chains

Several ways Cardano departs from chains already supported in OWS, each of which
drove a specific design decision later in this document:

1. **Extended-key derivation (96 bytes, V2).** Unlike SLIP-10 ed25519
   (32-byte keys, hardened-only) or BIP-32 secp256k1, Cardano uses BIP32-Ed25519
   with 64-byte extended secret keys + a 32-byte chain code, and allows
   **non-hardened** derivation. This is a new `Curve`, not a tweak to an existing
   one.
2. **Master key from entropy, not seed.** Most chains derive from the BIP-39
   *seed* (PBKDF2 over the mnemonic phrase). Cardano's Icarus scheme derives the
   root key from the raw BIP-39 **entropy** (PBKDF2-HMAC-SHA512, empty password,
   entropy as salt, 4096 iterations). Reusing the seed would yield addresses no
   other Cardano wallet could reproduce.
3. **Two credentials per address.** A Shelley **base** address combines a payment
   credential (CIP-1852 `role = 0`) and a stake credential (`role = 2`), each at
   its own derivation path. OWS's "one path → one address" assumption does not
   hold; the key-storage layer carries 192 bytes (payment ‖ stake).
4. **CIP-1852 purpose, not BIP-44.** Cardano uses purpose `1852'` (not `44'`)
   with coin type `1815'`, and a `role` segment between account and index.
5. **CAIP-2 via CIP-34.** The chain identifier encodes both a network id and a
   network magic (`cip34:<networkId>-<networkMagic>`), rather than a single
   numeric/string reference.
6. **CBOR transactions + pluggable RPC.** Transactions are CBOR (parsed and
   witness-encoded by CSL's `FixedTransaction`). Network access goes through a
   provider-agnostic `CardanoRpcProvider` trait; the default is keyless Koios,
   with Blockfrost available when the RPC URL points at Blockfrost and a
   `BLOCKFROST_PROJECT_ID` is set.
7. **COSE message signing (CIP-8).** Unlike most OWS chains, which sign a hashed
   or prefixed byte string, Cardano message signing follows CIP-8: the message is
   wrapped in a COSE `COSE_Sign1` structure whose protected headers carry the
   signing address, and the signature is over the COSE `Sig_structure`, not the
   raw message.

General specifications worth reading alongside this section:
[CIP-1852](https://cips.cardano.org/cip/CIP-1852),
[CIP-3 (Icarus master key)](https://cips.cardano.org/cip/CIP-3),
[CIP-19 (addresses)](https://cips.cardano.org/cip/CIP-19),
[CIP-34 (chain identification)](https://cips.cardano.org/cip/CIP-34),
the [BIP32-Ed25519 paper](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf),
and the in-repo [`docs/07-supported-chains.md`](07-supported-chains.md).

## Specification

### 1. CAIP-2 / CAIP-10 addressing

#### 1.1 Namespace and chain identifiers

Cardano is identified with the **`cip34`** CAIP-2 namespace, following
[CIP-34](https://cips.cardano.org/cip/CIP-34). The CIP-34 reference encodes the
network as `<networkId>-<networkMagic>`:

| Network | OWS name          | CAIP-2 chain id     | networkId | networkMagic |
| ------- | ----------------- | ------------------- | --------- | ------------ |
| Mainnet | `cardano`         | `cip34:1-764824073` | 1         | 764824073    |
| Preprod | `cardano-preprod` | `cip34:0-1`         | 0         | 1            |
| Preview | `cardano-preview` | `cip34:0-2`         | 0         | 2            |

A new `ChainType::Cardano` variant is added to the chain-family enum
(`ows/crates/ows-core/src/chain.rs`). The namespace mapping is wired in both directions:

- `ChainType::Cardano.namespace()` → `"cip34"`
- `ChainType::from_namespace("cip34")` → `Some(ChainType::Cardano)`
- `ChainType::Cardano.default_coin_type()` → `1815` (SLIP-44 coin type for ADA)

The three networks above are registered in `KNOWN_CHAINS`, so `parse_chain`
resolves both friendly names (`cardano`, `cardano-preprod`, `cardano-preview`) and
raw CAIP-2 ids (`cip34:1-764824073`, `cip34:0-1`, `cip34:0-2`). `cardano` is the
first Cardano entry in the registry, so it is the default for the family
(`default_chain_for_type(ChainType::Cardano)` → mainnet).

#### 1.2 CAIP-10 accounts

CAIP-10 account identifiers follow the existing OWS convention
`chain_id:address`, e.g.

```
cip34:1-764824073:addr1...
```

The account id is assembled in `derive_all_accounts` as
`format!("{}:{}", chain.chain_id, address)`, identical to every other family.

#### 1.3 Universal wallet membership

`ChainType::Cardano` is appended to `ALL_CHAIN_TYPES`. Because a
universal wallet derives one account per family plus the explicitly listed
testnet extras, Cardano contributes three rows:

- `UNIVERSAL_WALLET_EXTRA_CHAIN_NAMES = ["cardano-preprod", "cardano-preview"]`
- `universal_wallet_chains()` therefore yields mainnet (via the family default)
  plus the two testnets, in a stable order.

#### 1.4 RPC configuration (Koios and Blockfrost)

Cardano network access is implemented behind a provider-agnostic
`CardanoRpcProvider` trait in `ows/crates/ows-core/src/cardano_rpc/`. Two concrete providers
are supported:

| Provider    | Authentication | Default |
| ----------- | -------------- | ------- |
| **Koios**   | None (keyless) | Yes     |
| **Blockfrost** | `project_id` API key via the `BLOCKFROST_PROJECT_ID` environment variable | No (opt-in via RPC URL override) |

Both providers implement the same three operations: broadcast a signed
transaction (CBOR), fetch the CBOR of a set of transactions (used to resolve
transaction inputs, see [§4.2](#42-parsing-and-input-resolution-cardanorpcproviderfetch_txs_cbor)),
and fetch address token balances. `resolve_cardano_provider` selects the implementation from the
configured RPC URL (see [Provider selection](#provider-selection) below).

**Default endpoints (Koios).** Built-in defaults are registered in
`Config::default_rpc()`:

| Chain id            | Default RPC                         |
| ------------------- | ----------------------------------- |
| `cip34:1-764824073` | `https://api.koios.rest/api/v1`     |
| `cip34:0-1`         | `https://preprod.koios.rest/api/v1` |
| `cip34:0-2`         | `https://preview.koios.rest/api/v1` |

**Blockfrost endpoints.** To use Blockfrost instead, override the RPC URL in
user config to the Blockfrost API base for the target network, for example:

| Network | Blockfrost RPC URL                                      |
| ------- | ------------------------------------------------------- |
| Mainnet | `https://cardano-mainnet.blockfrost.io/api/v0`          |
| Preprod | `https://cardano-preprod.blockfrost.io/api/v0`          |
| Preview | `https://cardano-preview.blockfrost.io/api/v0`          |

Set `BLOCKFROST_PROJECT_ID` to your Blockfrost project id (API key) before any
Cardano RPC call; without it, `resolve_cardano_provider` fails when the URL
selects Blockfrost.

##### Provider selection

`resolve_cardano_provider` (`ows/crates/ows-core/src/cardano_rpc/mod.rs`) inspects the RPC
URL string and returns a `Box<dyn CardanoRpcProvider>`:

- **Blockfrost** — when the URL contains `blockfrost.io/api` **or** is prefixed
  with `blockfrost|`. The prefix form is for custom Blockfrost-compatible hosts
  that would not match the substring heuristic (e.g. `blockfrost|https://my-proxy.example/api/v0`).
  The `project_id` is read from **`BLOCKFROST_PROJECT_ID`**; if the variable is
  unset, resolution returns an error.
- **Koios** — when the URL contains `koios.rest/api` **or** is prefixed with
  `koios|` (same rationale for custom hosts).
- **Any other URL** — rejected as unsupported.

After selection, the `koios|` / `blockfrost|` prefix is stripped before the
provider issues HTTP requests. All Cardano call sites — `broadcast_cardano`
(`ows-lib`), `make_transaction_context` (`ows-signer`), and balance fetching
(`ows-pay`) — go through `resolve_cardano_provider`, so the same URL override
and provider-selection rules apply everywhere.

RPC URL lookup reuses the generic precedence already in place: explicit override
→ user config exact `chain_id` → user config namespace match → built-in default.

#### 1.5 Signer resolution

`signer_for_chain` constructs `CardanoSigner::from_chain_id(chain.chain_id)`, which
selects network parameters from the CAIP-2 id (`cip34:0-1` → preprod, `cip34:0-2`
→ preview, anything else → mainnet). Network parameters come from
`cardano-serialization-lib`'s `NetworkInfo`.

### 2. Key derivation and cryptography

#### 2.1 New curve

A third `Curve` variant, `Ed25519Bip32`, is added (`ows/crates/ows-signer/src/curve.rs`):

- `private_key_len()` → `ed25519_bip32::XPRV_SIZE` (96 bytes: 64-byte extended
  secret key + 32-byte chain code)
- `public_key_len()` → 32 bytes

#### 2.2 Master key generation (Icarus)

For `Curve::Ed25519Bip32`, `HdDeriver::derive_from_mnemonic` does **not** use the
BIP-39 seed. Instead it follows the Cardano Icarus scheme
(`ed25519_bip32_master_xprv_from_entropy`):

1. Extract the raw BIP-39 **entropy** (checksum bits excluded) from the mnemonic.
   `Mnemonic::entropy()` was added for this purpose.
2. `PBKDF2-HMAC-SHA512` with an **empty password**, the entropy as the **salt**,
   `4096` iterations, producing a 96-byte output. The password slot is left empty
   on purpose: Cardano software wallets (Eternl, Yoroi, …) pass no
   spending password into this step, so filling it — for example with the BIP-39
   passphrase — would derive a different root key and produce addresses no other
   Cardano wallet could reproduce from the same mnemonic.
3. Normalize the result with `XPrv::normalize_bytes_force3rd` to obtain a valid
   master extended private key.

This is verified against published Icarus test vectors (including the all-zero
"abandon … about" mnemonic).

#### 2.3 Child derivation

`HdDeriver::derive` accepts a 96-byte master `XPrv` for `Ed25519Bip32`
(seed-length validation requires exactly `XPRV_SIZE`; the 16–64 byte rule that
applies to secp256k1/ed25519 is bypassed). Path components are walked with the
`ed25519-bip32` crate using **`DerivationScheme::V2`**, supporting both hardened
(`'`) and non-hardened indices. The result is the 96-byte child `XPrv`.

All curves share a single path parser (`parse_path_components`), so
`validate_path` and every per-curve derivation branch agree on what a path means:
each component is `<index>` or `<index>'`, and the bare index must be **below
2³¹** (`0x80000000`). The bound matters most for Cardano, the only curve that also
accepts non-hardened components: without it `m/2147483648` and `m/0'` would derive
the same child index and be two spellings of one path. On the hardened-only
SLIP-10 branch the same parser additionally rejects any non-hardened component
(`Ed25519NonHardened`).

The deriver continues to expose the same surface for all curves:
`derive`, `derive_from_mnemonic`, and the cached `derive_from_mnemonic_cached`
(the cache key incorporates the `ed25519_bip32` curve tag so it cannot collide
with secp256k1/ed25519 keys for the same path).

#### 2.4 CIP-1852 paths

`CardanoSigner` exposes the CIP-1852 hierarchy
`m / 1852' / 1815' / account' / role / index`, where `role` is
`0` = external/payment, `1` = internal/change, `2` = stake:

| Helper                            | Path                          |
| --------------------------------- | ----------------------------- |
| `payment_derivation_path(index)`  | `m/1852'/1815'/{index}'/0/0`  |
| `stake_derivation_path(index)`    | `m/1852'/1815'/{index}'/2/0`  |

Per the agreed scope, only **one base address per account at address index 0** is
supported initially, so the generic `index` that OWS threads through derivation is
used as the CIP-1852 **account** index and the address index stays `0`.
`default_derivation_path(index)` returns the payment leaf
(`m/1852'/1815'/{index}'/0/0`). Generic single-path key resolution no
longer derives this leaf directly; instead generic call sites use
`default_derivation_paths` and `encode_keys` (see
[§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys)),
which for Cardano materialize both the payment leaf and the stake key
(`m/1852'/1815'/{index}'/2/0`) as a single 192-byte buffer.

#### 2.5 `ChainSigner` integration

`CardanoSigner` implements `ChainSigner`:

- `chain_type()` → `ChainType::Cardano`
- `curve()` → `Curve::Ed25519Bip32`
- `coin_type()` → `1815`
- `default_derivation_path(index)` → payment leaf (see above)

`derive_address`, `sign`, `sign_message`, `sign_transaction`, and
`encode_signed_transaction` are now fully implemented; mnemonic key resolution uses
`default_derivation_paths` and `encode_keys` (see [§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys));
they are specified in [§3](#3-transaction-and-message-signing-chain-plugin-interface).
The key material these methods consume is a 192-byte buffer = payment `XPrv` (96) ‖
stake `XPrv` (96) at matching CIP-1852 indices (or a bare 96-byte payment `XPrv`,
which yields an enterprise address with no staking component).

#### 2.6 Multi-credential key storage

Because a Cardano account needs two credentials, the multi-curve key material was
extended (`ows/crates/ows-lib/src/ops.rs`):

- The `KeyPair` struct (used for raw-private-key imports) gains an
  `ed25519_bip32` field, serialized as
  `{"secp256k1":"…","ed25519":"…","ed25519_bip32":"…"}`. The `KeyType::PrivateKey`
  doc comment in `wallet_file.rs` is updated accordingly. The wallet-file schema
  version (`ows_version`) is unchanged at `2`; the new field is additive.
- For imported private-key wallets, `random_ed25519_bip32()` generates **two**
  normalized 96-byte `XPrv`s (payment ‖ stake = 192 bytes) so the layout matches
  the base-address encoding.
- `KeyPair::key_for_curve(Curve::Ed25519Bip32)` returns this material; empty
  material yields a clear "private key for chain is empty" error for wallets
  imported before Cardano support existed.
- An explicitly supplied `ed25519_bip32` key is validated at import time
  (`validate_ed25519_bip32_key` in `import_wallet_private_key`): the blob must be
  exactly 96 or 192 bytes, and each 96-byte half must pass
  `XPrv::from_slice_verified`, i.e. satisfy the Ed25519-BIP32 scalar clamping
  rules. A malformed key is rejected with an `InvalidInput` error naming the
  offending half (`payment` / `stake`) instead of being stored and failing later
  at signing time.
- Mnemonic wallets reach the same 192-byte layout through `default_derivation_paths`
  and `encode_keys` (see
  [§3.5](#35-key-material-abstraction-default_derivation_paths-and-encode_keys)) rather than through
  `KeyPair`, so both wallet kinds present an identical payment ‖ stake buffer to the
  signer.

#### 2.7 Broadcast plumbing

`broadcast` dispatches `ChainType::Cardano` to `broadcast_cardano`, which calls
`resolve_cardano_provider` on the configured RPC URL and submits the signed CBOR
via `CardanoRpcProvider::broadcast_tx` (Koios: `POST {rpc}/submittx` with
`Content-Type: application/cbor`, HTTP `202`; Blockfrost:
`POST {rpc}/tx/submit`). The fully signed CBOR produced by
`encode_signed_transaction` (see [§3.4](#34-transaction-signing)) is what feeds
this path.

### 3. Transaction and message signing (Chain Plugin Interface)

This deliverable implements the `ChainSigner` plugin surface for Cardano:
address encoding, raw signing, CIP-8 message signing, and transaction
signing/witness encoding. Address construction, transaction (de)serialization, and
witness encoding use `cardano-serialization-lib` (CSL); COSE message structures use
Emurgo's `cardano-message-signing` companion crate.

All signer methods accept the **key material** layout described in
[§2.5](#25-chainsigner-integration): either a 192-byte payment `XPrv` ‖ stake
`XPrv`, or a bare 96-byte payment `XPrv`. Two small private helpers slice this
buffer:

- `payment_bip32(key_material)` → payment `Bip32PrivateKey` (accepts 96 or 192
  bytes; anything else is a clear `InvalidPrivateKey` error).
- `stake_bip32(key_material)` → `Some(stake)` when 192 bytes are supplied, `None`
  for the 96-byte payment-only case.

#### 3.1 Shelley address encoding

`derive_address` chooses the address kind from whether a stake key is present:

| Key material            | Address kind | Helper                          | Example prefix |
| ----------------------- | ------------ | ------------------------------- | -------------- |
| payment ‖ stake (192 B) | base         | `base_address_bech32`           | `addr1q…`      |
| payment only (96 B)     | enterprise   | `enterprise_address_bech32`     | `addr1v…`      |
| stake only (signing)    | reward       | `reward_address_bech32`         | `stake1…`      |

Each helper hashes the relevant public key (`to_public().to_raw_key().hash()`),
wraps it in a `Credential::from_keyhash`, builds the matching CSL address type
(`BaseAddress` / `EnterpriseAddress` / `RewardAddress`) bound to the signer's
`network_id`, and bech32-encodes it. The reward address is not produced by
`derive_address` directly; it is used during message signing when a stake/reward
address is the requested signer.

#### 3.2 Raw signing (`sign`)

`sign` produces a bare 64-byte Ed25519 signature over the supplied bytes using the
**payment** key, returning the signature plus the payment public key. It performs
no hashing or prefixing (the caller decides what to sign) and is the low-level
primitive used by transaction witnessing.

#### 3.3 CIP-8 message signing (`sign_message`)

`sign_message` follows [CIP-8](https://cips.cardano.org/cip/CIP-8): the message is
embedded in a COSE `COSE_Sign1` structure and the signature is computed over the
COSE `Sig_structure`, not the raw message. The flow:

1. **Select the signing credential from the optional `address`.** The address (a
   bech32 string) determines which key signs and is embedded in the protected
   headers:
   - `Reward` (`stake1…`) → sign with the **stake** key; requires 192-byte
     material, else `InvalidPrivateKey`.
   - `Base` (`addr1q…`) → sign with the **payment** key; also requires the stake
     key so the base address can be reconstructed and verified.
   - `Enterprise` (`addr1v…`) → sign with the **payment** key.
   - Any other address kind → `AddressMismatch`.
   In each case the signer **re-derives** the address from the key material and
   compares it to the requested one, returning `AddressMismatch` on any
   discrepancy. This guarantees the embedded `address` header is one the key
   actually controls.
2. **No `address` supplied** → sign with the payment key and embed the address
   derived from the key material (base if a stake key is present, else
   enterprise).
3. **Build the COSE structure.** A `HeaderMap` of protected headers is populated
   with `AlgorithmId::EdDSA` and an `"address"` label whose value is the **raw
   address bytes** (CBOR byte string). A `COSESign1Builder` is constructed over
   these headers and the message payload; `make_data_to_sign()` yields the
   `Sig_structure`, which is signed with the selected raw Ed25519 key.
4. **Serialize.** The signature is folded back into the builder, wrapped as a
   `SignedMessage::new_cose_sign1`, and serialized to CBOR. `SignOutput.signature`
   is the serialized `COSE_Sign1`; `public_key` is the signing key's public key
   wrapped in a serialized **`COSE_Key`** (`EdDSA25519Key::new(raw_pubkey).build()`,
   CBOR-encoded — `kty: OKP`, `alg: EdDSA`, `crv: Ed25519`, `x: <32-byte key>`),
   not the bare 32 raw bytes. This is the `key` half of the `(signature, key)`
   pair CIP-30's `signData` returns, so a CIP-8 verifier can consume the output
   directly.

#### 3.4 Transaction signing

`sign_transaction` consumes the unsigned transaction CBOR (it does **not** build
transactions — input selection, fees, and change are the caller's responsibility):

1. Parse the bytes into a CSL `FixedTransaction` (`InvalidTransaction` on failure).
2. Always create a payment witness with `make_vkey_witness(tx_hash, payment_raw_key)`.
3. Determine whether the body needs a **stake** signature. Two independent sources
   are consulted:
   - **Structural requirements** (`stake_key_hashes_required_by_body`) — the key
     hashes the ledger will demand regardless of what the builder declared:
     - **certificate stake credentials** (`add_cert_key_hashes`), covering the
       Conway `reg_cert` (a legacy `stake_registration` with no explicit deposit
       needs no witness, so it is skipped), stake deregistration, stake/vote
       delegation and the combined registration+delegation certificates, and vote
       delegation — mirroring the stake-credential arms of the ledger's
       `witsVKeyNeeded`. Script credentials are witnessed by the script, not a
       vkey, so only key-hash credentials are collected. Pool **owners** on a pool
       registration are stake key hashes and are collected; the pool operator's
       cold key, genesis delegates, committee credentials, and DRep credentials
       can never be a CIP-1852 stake key and are not.
     - **withdrawals** — the reward account of every withdrawal in the body.
   - **`required_signers`** — consulted only to decide whether *this* wallet's
     stake key should sign, never to decide that a stake key is missing: a hash
     listed there routinely belongs to a co-signer.
4. If stake key material is present and its hash is in either set, a stake witness
   is appended. If **no** stake key is available but the body structurally requires
   a stake signature for anything other than the payment credential,
   `sign_transaction` fails with `InvalidTransaction` rather than returning a
   transaction that would fail phase-1 validation on submission.
5. `SignOutput.signature` is the CBOR-encoded **`Vkeywitnesses` set** (payment,
   optionally followed by stake); `public_key` is the payment witness's public key.

`encode_signed_transaction` assembles the submittable transaction: it re-parses the
unsigned CBOR into a `FixedTransaction`, decodes the signature buffer back into a
`Vkeywitnesses` set (`Vkeywitnesses::from_bytes`), adds each witness with
`add_vkey_witness`, and returns the CBOR of the now-witnessed transaction.
This is the byte string handed to `broadcast_cardano` ([§2.7](#27-broadcast-plumbing)).

#### 3.5 Key-material abstraction (`default_derivation_paths` and `encode_keys`)

To let a chain decide how mnemonic-derived key material is shaped, `ChainSigner`
exposes two overridable hooks:

- `default_derivation_paths(index)` — all BIP paths bound to one account. The
  default returns a single-element vector containing `default_derivation_path(index)`,
  so every other chain is unaffected.
- `encode_keys(keys)` — packs the resolved key bundle into the single opaque blob
  that signing methods consume. The default returns the primary (first) key
  unchanged.

`CardanoSigner` overrides both: `default_derivation_paths` returns the payment leaf
`m/1852'/1815'/{index}'/0/0` and the stake key `m/1852'/1815'/{index}'/2/0`;
`encode_keys` concatenates the two 96-byte `XPrv`s into the 192-byte payment ‖
stake buffer the address and signing methods expect. Generic call sites were
migrated to this pattern — `derive_all_accounts`, `secret_to_signing_key`,
`derive_address` (the public lib function), the CLI `derive` command, and the
signer integration test now call `signer.default_derivation_paths(index)`, derive
keys via `HdDeriver`, then `signer.encode_keys(&keys)` instead of deriving a single
path inline. This is what lets Cardano transparently carry two credentials through
code that still assumes "one account → one key blob".

#### 3.6 Address-aware `sign_message` across all chains

CIP-8 needs to know *which* of a wallet's Cardano addresses a signature is for, so
the `sign_message` signature gained an `address: Option<&str>` parameter across the
whole `ChainSigner` trait, every chain implementation, the `ows-lib` entry points
(`sign_message`, `sign_typed_data`, and their API-key variants), the CLI (a new
`--address` flag on `sign message`), and the Node/Python bindings.

For non-Cardano chains the parameter is an optional safety check: a new default
trait method `verify_sign_message_address` re-derives the address from the private
key and compares it (case-insensitively, ignoring a `0x` prefix) to the requested
one, returning the new `SignerError::AddressMismatch` on a mismatch. Each chain
calls it at the top of `sign_message` (and EVM's typed-data path calls it too), so
passing an `address` that the key does not control is rejected everywhere, while
passing `None` keeps the prior behavior. Cardano does not use the default check —
it performs richer, address-kind-aware selection and verification inline (see
[§3.3](#33-cip-8-message-signing-sign_message)).

### 4. Policy engine support

OWS gates every signing request through a **Policy Engine**: before a key is
decrypted and used, the request is turned into a chain-agnostic
`PolicyContext` (`ows/crates/ows-core/src/policy.rs`) that built-in rules and custom
**executable** policies evaluate and can veto. The core of that context is a
`TransactionContext`, whose `effects` field is a list of per-address asset
deltas:

```rust
pub struct TransactionEffect {
    pub address: String,
    pub diff: Vec<(String, i64)>, // (asset_id, signed change)
}

pub struct TransactionContext {
    pub effects: Vec<TransactionEffect>,
    pub raw_hex: String,          // the raw unsigned transaction
    pub data: Option<String>,     // calldata (EVM only)
}
```

Each `ChainSigner` produces this context from raw transaction bytes via
`make_transaction_context(tx_bytes, rpc_url)`. The trait's default implementation
returns empty `effects` (just the `raw_hex`), which suffices for chains where the
transaction already carries enough information — or where flow analysis is not yet
implemented. This deliverable overrides it for Cardano so that a policy can reason
about the **actual ADA and native-asset movement** a transaction causes, per
address.

#### 4.1 Why Cardano needs the RPC provider

Cardano is UTxO-based. A transaction body lists its inputs only as
`(transaction_hash, index)` references — it does **not** carry the value or assets
locked at those UTxOs. To compute how much each address gains or loses, the signer
must resolve every referenced input to its underlying UTxO. This is the
architectural consequence flagged in the scope: unlike the account-based effects on
other chains, building a Cardano `TransactionContext` **depends on network access**
to the configured RPC provider (Koios or Blockfrost).

Accordingly, `make_transaction_context` takes an `Option<&str>` RPC URL, and the
`ows-lib` call sites that build the policy context — `sign_and_send`
(`ops.rs`) and `sign_with_api_key` (`key_ops.rs`) — resolve the Cardano RPC
endpoint and pass it through. Resolution reuses the generic precedence
(explicit override → config exact `chain_id` → config namespace → built-in
default; see [§1.4](#14-rpc-configuration-koios-and-blockfrost)); `resolve_rpc_url`
was made `pub(crate)`-visible for this. For every non-Cardano chain the URL
stays `None`, so no network call is introduced anywhere else.

#### 4.2 Parsing and input resolution (`CardanoRpcProvider::fetch_txs_cbor`)

`CardanoSigner::make_transaction_context` (`ows/crates/ows-signer/src/chains/cardano.rs`):

1. Parse the bytes into a CSL `FixedTransaction` (`InvalidTransaction` on failure),
   and record the raw hex for `TransactionContext.raw_hex`.
2. Collect input references as `(tx_hash_hex, index)` pairs from `tx.body().inputs()`.
3. If there are inputs, an RPC URL is **required** (else `InvalidMessage`);
   `resolve_cardano_provider` selects Koios or Blockfrost from the URL (see
   [§1.4](#14-rpc-configuration-koios-and-blockfrost)). Inputs are resolved *not*
   by asking the provider for UTxO values, but by fetching the **CBOR of each
   referenced transaction** (`CardanoRpcProvider::fetch_txs_cbor`, one request set
   per unique tx hash) and reading the referenced output out of it:
   - **Koios** — `POST {rpc}/tx_cbor` with `{"_tx_hashes": [...]}`, **chunked** at
     10 hashes per call.
   - **Blockfrost** — per-transaction `GET {rpc}/txs/{hash}/cbor` (no batch
     endpoint); a `404` is skipped, so the result may be partial.
   - Both providers use a blocking `reqwest` client with a `45s` timeout.
   - Failures map to `SignerError::RpcError`.
4. Each returned CBOR is decoded into a `FixedTransaction` and its
   `transaction_hash()` is compared against the hash it was requested under; a
   mismatch is a hard `RpcError`. A hash missing from the response is likewise an
   `RpcError`, and an input whose index is past the end of the source
   transaction's outputs is an `InvalidTransaction`.

Each resolved `Utxo` carries the input's `address`, its lovelace amount, and a list
of native assets keyed by `policy_id ‖ asset_name` (hex), all read from the source
transaction's output.

#### 4.3 Computing per-address effects

The signer builds two `address → (asset_id → amount)` maps and diffs them:

- **Inputs** map is populated from the resolved provider UTxOs (lovelace →
  `lovelace`,
  each native asset → `policy_id ‖ asset_name`).
- **Outputs** map is read directly from `tx.body().outputs()`: the `coin` becomes
  `lovelace`, and each `multiasset` entry becomes `policy_id_hex ‖ asset_name_hex`.
- **Withdrawals** (`tx.body().withdrawals()`) are folded into the **inputs** map:
  lovelace leaves the reward account and enters the transaction, so each
  withdrawal counts as an input from the bech32 **reward address**
  (`stake1…`) it is drawn from.
- **Certificate deposits and refunds** (`cert_deposit_or_refund`) are attributed to
  the reward address of the certificate's credential, built from that credential
  and the signer's `network_id`. A **deposit** locks lovelace under the credential
  and is therefore counted as an *output* to that reward address; a **refund**
  unlocks it and is counted as an *input*. Covered certificates are the Conway
  `reg_cert`/`unreg_cert` (only when they carry an explicit `coin` on the wire),
  stake registration-and-delegation, stake-vote registration-and-delegation, vote
  registration-and-delegation, and DRep registration/deregistration. Legacy
  Shelley certificates without an on-wire amount are skipped, because their
  deposit comes from protocol parameters that the transaction bytes do not carry.
- ADA is represented by the reserved asset id **`"lovelace"`**; every native asset
  is keyed by the concatenation of its (hex) policy id and (hex) asset name, so the
  same token nets out across inputs and outputs.

For every address touched by either side, and every asset id it involves, the
effect is `output_balance − input_balance` as a signed `i64`. Zero-diff assets and
zero-diff addresses are dropped; the remaining `diff` entries are sorted by asset
id and the `effects` list is sorted by address, so the context is deterministic
(important for reproducible policy decisions and stable test vectors). A pure
self-transfer, for example, yields a single effect on the sender with only the
negative fee.

The result is returned as `TransactionContext { effects, raw_hex, data: None }` and
handed to the policy engine, which passes it (as part of `PolicyContext`) to
built-in rules and to executable policies over stdin.

### 5. Address balance fetching

Balance queries go through the same provider abstraction.
`get_cardano_balances` (`ows/crates/ows-pay/src/cardano.rs`) resolves the
configured RPC URL with `resolve_cardano_provider` and calls
`CardanoRpcProvider::get_balances(address)`, returning the generic
`TokenBalance` list that every other chain in `ows-pay` produces:

- ADA is reported with `address: "lovelace"`, symbol `ADA`, and 6 decimals; the
  amount is the lovelace total scaled by `10^-6`.
- Each native asset is reported with `address` set to its **asset fingerprint**
  (`asset1…`), `name` set to `policy_id.asset_name`, and `symbol`/`decimals`
  taken from the token-registry metadata — falling back to the first 10
  characters of the asset name and `0` decimals when no metadata exists. On
  Blockfrost the fingerprint comes from the per-asset lookup, so when
  `GET {rpc}/assets/{unit}` returns a non-success status the `address` falls back
  to the raw `policy_id ‖ asset_name` hex instead of an `asset1…` fingerprint.
  Zero-quantity entries are dropped, and the list is sorted by descending
  amount.
- **Koios** reads `POST {rpc}/address_info` (summing `asset_list` across the
  UTxO set) and resolves metadata via `POST {rpc}/asset_info`, chunked.
  **Blockfrost** reads `GET {rpc}/addresses/{address}` and one
  `GET {rpc}/assets/{unit}` per native asset; a `404` on the address means "no
  balances" rather than an error.

The provider API is blocking, so the `async` wrapper runs it on
`tokio::task::spawn_blocking`. Errors are mapped onto `PayErrorCode`: a failure to
select a provider from the configured RPC URL — an unsupported host, or a
Blockfrost URL with no `BLOCKFROST_PROJECT_ID` (see
[§1.4](#14-rpc-configuration-koios-and-blockfrost)) — is `InvalidInput`, while the
provider's own errors map transport → `HttpTransport`, non-success status →
`HttpStatus`, and an undecodable response body or amount → the new `InvalidData`.

## Rationale

- **`cip34` namespace.** CIP-34 is the Cardano-native CAIP-2 registration and
  encodes network id + network magic deterministically, which lets a single
  identifier disambiguate mainnet/preprod/preview without inventing OWS-specific
  aliases. CIP-34 is still in _Proposed_ status, which is a known risk we accept
  and monitor.
- **Generic `ed25519-bip32` instead of `cardano-serialization-lib` for
  derivation.** The simplest route would be to derive keys with
  `cardano-serialization-lib` (CSL). OWS deliberately keeps derivation
  chain-agnostic and generic (a single `HdDeriver` across all families), so we
  implement BIP32-Ed25519 with the lightweight `ed25519-bip32` crate and only use
  CSL for Cardano-specific concerns (network parameters, address encoding, and
  transaction/witness encoding). This avoids leaking a chain-specific library into
  the generic key path while still using the canonical library for the parts that
  must match the ecosystem byte-for-byte.
- **CSL + `cardano-message-signing` for the chain plugin, per IOHK.** As recorded
  in the deliverable description (IOHK agreed on 8.4.2026 to use
  `cardano-serialization-lib`), address encoding and transaction signing go through
  CSL, and CIP-8 message signing uses Emurgo's `cardano-message-signing` COSE
  helpers rather than a hand-rolled COSE encoder. This keeps the produced
  addresses, witnesses, and signed messages compatible with mainstream Cardano
  wallets and tooling.
- **Base address with payment + stake.** Per agreement with IOHK, the initial
  implementation targets exactly one base address per account at address index 0,
  combining a payment credential (role 0) and a stake credential (role 2). This
  keeps the scope bounded while still producing a normal, stake-delegatable
  Shelley address rather than an enterprise (payment-only) address.
- **Two 96-byte keys in `KeyPair`.** Storing payment ‖ stake (192 bytes) up front
  makes the imported-key representation forward-compatible with base-address
  assembly without another schema change.
- **`default_derivation_paths` + `encode_keys` instead of widening the signer
  surface.** Rather than special-casing Cardano in every generic call site,
  overridable `ChainSigner::default_derivation_paths` and `encode_keys` let a chain
  declare how many keys per account it needs and how to pack them into one blob.
  The defaults keep single-path behavior for all other chains; only Cardano returns
  the 192-byte payment ‖ stake buffer. This localizes the "two credentials per
  account" peculiarity to the Cardano signer.
- **`address`-driven message signing.** CIP-8 embeds the signing address in the
  COSE protected headers, so `sign_message` must know which address the caller
  intends. Threading an optional `address` through the trait (rather than a
  Cardano-only API) also gave every other chain a cheap opt-in guard against
  signing with the wrong key (`verify_sign_message_address` →
  `AddressMismatch`).
- **A CBOR witness set as the signature.** `sign_transaction` returns the CBOR
  encoding of the whole `Vkeywitnesses` set, and `encode_signed_transaction`
  decodes it back with `Vkeywitnesses::from_bytes`. This keeps
  `SignOutput.signature` a flat byte string (consistent with other chains) while
  supporting the multi-witness (payment + stake) case without the caller having to
  know a fixed per-witness length.
- **Stake witnessing driven by the transaction body, not by `required_signers`.**
  A builder is not obliged to list the stake key in `required_signers`, so keying
  the decision off that field alone silently produced unsubmittable delegation and
  withdrawal transactions. `sign_transaction` therefore derives the required stake
  key hashes from the certificates and withdrawals themselves (mirroring the
  ledger's `witsVKeyNeeded`) and keeps `required_signers` only as an additional
  trigger — never as the reason to declare a stake key missing, since a hash listed
  there frequently belongs to a co-signer. When a stake signature is structurally
  required and no stake key is available, failing early is preferable to handing
  back a transaction that dies in phase-1 validation.
- **`COSE_Key` as the message-signing public key.** CIP-30's `signData` returns a
  `(signature, key)` pair where `key` is a COSE key, not raw bytes. Returning the
  serialized `COSE_Key` in `SignOutput.public_key` lets wallet/dApp verifiers use
  the output as-is instead of re-wrapping the raw Ed25519 key themselves.
- **Deposits, refunds, and withdrawals attributed to the reward address.** Staking
  lovelace is locked under a *credential*, not at a payment address, so the only
  faithful place to book it is the credential's reward address. Treating deposits
  as outputs and refunds/withdrawals as inputs keeps the netting arithmetic
  identical to the UTxO side, so a policy sees "2 ADA left this payment address and
  2 ADA is now locked at this `stake1…`" instead of an unexplained outflow.
- **RPC-resolved transaction effects for policy.** Cardano inputs carry no value,
  so a meaningful `TransactionContext` cannot be built from the transaction bytes
  alone. Rather than inventing a Cardano-only policy path, the existing
  `make_transaction_context` hook is overridden to resolve inputs via the
  configured `CardanoRpcProvider` (Koios or Blockfrost) and emit
  the same chain-agnostic `TransactionEffect` shape every other chain uses — so
  executable policies see uniform per-address asset deltas regardless of chain. The
  RPC dependency is threaded only for Cardano; all other chains keep passing `None`.
- **Reject missing input UTxOs.** If the provider omits a referenced transaction,
  returns CBOR whose hash does not match, or the referenced output index does not
  exist, `make_transaction_context` errors instead of proceeding. An unresolved
  input would silently understate the ADA/asset outflow and could let a spending
  policy pass a transaction it should have denied, so a partial resolution is
  treated as a hard failure.

  > **⚠️ Warning — chained/unconfirmed transactions.** This same strictness breaks
  > transaction *chaining*. If a transaction spends an input that was created by an
  > earlier transaction which has **not yet been confirmed in a block**, the RPC
  > provider does not know that transaction yet and omits it from the response.
  > Because the returned data is then incomplete,
  > `make_transaction_context` fails (surfaced as `InvalidTransaction` or
  > `RpcError`) and the signing request is rejected, even though
  > the transaction itself is well-formed. In other words, a transaction cannot be
  > signed through the policy engine until every input it references has been
  > confirmed and indexed by the provider. Building and submitting a chain of dependent
  > transactions back-to-back (before the parents confirm) is therefore not currently
  > supported.
- **Deterministic effect ordering.** Effects are sorted by address and each `diff`
  by asset id, and ADA is normalized to the single `"lovelace"` key. This makes the
  context stable across runs, so policy decisions are reproducible and reference
  vectors are exact.

### Acceptance Criteria

These deliverables are considered complete when:

1. `ChainType::Cardano` exists and round-trips through serde, `namespace()`,
   `from_namespace()`, `default_coin_type()`, and `Display`/`FromStr`.
2. `parse_chain` resolves `cardano`, `cardano-preprod`, `cardano-preview`, and the
   corresponding `cip34:*` ids; `default_chain_for_type(Cardano)` is mainnet.
3. Default Koios RPC endpoints are registered for all three networks and resolved
   by the generic RPC lookup; Blockfrost is selectable by RPC URL override plus
   `BLOCKFROST_PROJECT_ID`.
4. `Curve::Ed25519Bip32` reports correct key lengths (96 / 32).
5. `HdDeriver` produces the correct Icarus master `XPrv` from entropy (matches
   published vectors) and performs V2 child derivation, including the CIP-1852
   payment/stake/account paths.
6. `CardanoSigner` reports curve `Ed25519Bip32`, coin type `1815`, and the
   CIP-1852 payment leaf as its default path.
7. Multi-curve key storage carries an `ed25519_bip32` entry (192 bytes for
   imported keys) without changing the wallet schema version, and an explicitly
   supplied key is accepted only in the 96/192-byte shapes with valid
   Ed25519-BIP32 clamping.
8. `derive_address` produces the correct mainnet Shelley **base** address from
   192-byte key material and the correct **enterprise** address from 96-byte
   payment-only material (verified against fixed vectors for 12- and 24-word
   mnemonics).
9. `sign_message` produces a CIP-8 `COSE_Sign1` matching reference vectors for the
   no-address, base, enterprise, and reward-address cases, returns the signing
   key as a serialized `COSE_Key`, and rejects an address the key does not control
   with `AddressMismatch`.
10. `sign_transaction` produces correct `Vkeywitness`(es) — payment only, and
    payment + stake when the transaction's certificates, withdrawals, or
    `required_signers` demand it — and `encode_signed_transaction` round-trips the
    witness set into a submittable transaction matching reference CBOR vectors.
11. `default_derivation_paths` returns both CIP-1852 paths for Cardano, and
    `encode_keys` returns the 192-byte payment ‖ stake buffer; all other chains
    remain on their single-path defaults.
12. `make_transaction_context` parses an unsigned Cardano transaction, resolves its
    inputs via the configured provider (Koios or Blockfrost), and produces
    per-address `TransactionEffect`s with correct signed ADA and native-asset diffs
    (verified against mocked provider responses for self-transfer, external+change,
    asset-carrying, and multi-input/multi-output cases); withdrawals and
    certificate deposits/refunds are booked against the corresponding reward
    address; it errors when the RPC URL is missing for a transaction with inputs,
    or when the provider returns incomplete UTxO data.
13. Address balance fetching returns ADA under `lovelace` plus one entry per
    native asset (fingerprint, `policy_id.asset_name`, token-registry
    symbol/decimals) on both providers, and an amount that cannot be decoded
    fails with `PayErrorCode::InvalidData` instead of reporting `0`.

### Implementation Plan

Everything specified above is landed and covered by unit/integration tests (see
[Testing](#testing)): the chain-registry/addressing layer, Ed25519-BIP32 key
derivation, the chain plugin interface (Shelley base/enterprise/reward address
encoding, raw signing, CIP-8 message signing, and transaction signing/witness
encoding), policy-engine support (`make_transaction_context` with provider-based
input resolution), address balance fetching, a pluggable Cardano RPC layer (Koios
default, Blockfrost opt-in), and the CLI/binding surface for the optional
`address` argument. Remaining Cardano work (separate deliverables) proceeds as:
transaction *building* (input selection, fee/change) and persisting both payment
and stake paths per `WalletAccount`.

## Backwards Compatibility Assessment

- **Wallet file schema unchanged.** `ows_version` stays at `2`. The new
  `ed25519_bip32` key field is additive; existing mnemonic wallets need no
  migration (Cardano keys are derived on demand). Private-key wallets imported
  before Cardano support simply have no `ed25519_bip32` material and surface a
  clear error if used for Cardano, rather than silently degrading.
- **Existing families untouched.** secp256k1 and SLIP-10 ed25519 derivation paths
  are unchanged; the `Ed25519Bip32` branch is additive in `Curve`, `HdDeriver`,
  and `KeyPair`. Characterization tests on EVM/Solana derivation continue to pass.
- **`sign_message` signature changed (binding-level).** Adding `address:
  Option<&str>` to `ChainSigner::sign_message` and to the `ows-lib`/binding entry
  points is a source-breaking change for direct callers, mitigated by making the
  parameter optional: passing `None` reproduces the prior behavior exactly, and
  every chain's non-Cardano message signing is unchanged when no address is given.
  `default_derivation_paths` and `encode_keys` are purely additive (defaults mirror
  the old inline single-path derivation).
- **Policy context is additive.** `make_transaction_context` already existed on
  `ChainSigner` with a default-empty implementation; Cardano overrides it and the new
  `SignerError::RpcError` variant is additive, so no other chain's behavior changes.
  The lib call sites resolve an RPC URL only for Cardano (all other chains keep
  passing `None`), so no new network call is introduced for existing chains.
- **New network dependency for Cardano signing requests.** Building a Cardano
  policy context now performs an RPC call when the transaction has inputs; a Cardano
  signing request that previously would have proceeded with empty effects now
  requires provider reachability (and errors if none is configured/available). This
  is intended — the policy engine needs the flow to make a decision — but it is a
  behavioral change for Cardano relative to the prior default-empty context.
- **Known abstraction gap.** `WalletAccount` still stores a single
  `derivation_path`, so the stored Cardano account currently records only the
  payment leaf even though the signer now derives both payment and stake keys at
  runtime via `default_derivation_paths` and `encode_keys`. Persisting both paths
  per account is a noted
  follow-up (`TODO` in `derive_all_accounts`).

## Security Considerations

- **Key material handling.** All derived keys are wrapped in `SecretBytes`
  (zeroized on drop). Intermediate buffers in HD derivation are explicitly
  zeroized. The 96-byte extended private keys are treated as secrets identical to
  other curve keys. Every buffer that transiently holds an Ed25519-BIP32 secret is
  covered: the PBKDF2 output and normalized master `XPrv`
  (`ed25519_bip32_master_xprv_from_entropy`), the randomly generated import keys,
  the decoded hex of an explicitly supplied key, the `KeyPair` fields and the JSON
  blob they are serialized into, and the bit accumulator and phrase copy inside
  `Mnemonic::entropy()` — all are `Zeroizing`/explicitly wiped rather than left to
  the allocator.
- **Malformed imported keys are rejected.** A user-supplied `ed25519_bip32` key is
  shape- and clamping-checked at import (see
  [§2.6](#26-multi-credential-key-storage)), so an unusable key surfaces at import
  time rather than as an opaque failure on first use.
- **Icarus master key.** Uses the standard PBKDF2-HMAC-SHA512 (4096 iterations,
  empty password, entropy as salt) and `normalize_bytes_force3rd`, matching
  ecosystem wallets; deviating would produce incompatible (and potentially
  unrecoverable-by-other-wallets) addresses.
- **Non-hardened derivation.** BIP32-Ed25519 V2 permits non-hardened child keys.
  This is required for Cardano interoperability, but callers should remain aware
  that a non-hardened branch's xpub + a single child xprv can expose sibling keys;
  the default account/payment/stake paths use hardened account-level segments.
  Path components at or above 2³¹ are rejected on every curve, so a bare
  `m/2147483648` cannot be used as an alias for the hardened `m/0'` (see
  [§2.3](#23-child-derivation)) — two spellings of one path would otherwise let the
  same key be reached under a path a policy or an account record does not
  recognize.
- **Key cache isolation.** The derivation cache key includes the curve tag, so
  Ed25519-BIP32 keys cannot be confused with secp256k1/ed25519 keys derived at the
  same BIP path string.
- **RPC providers.** Koios needs no API key, avoiding credential storage for the
  default deployment. Blockfrost authenticates with a `project_id` read from
  `BLOCKFROST_PROJECT_ID` (not stored in the wallet config). Broadcast and input
  resolution rely on whichever provider the RPC URL selects, so provider
  availability and trust are deployment considerations.
- **Address-bound message signing.** `sign_message` always re-derives the address
  from the supplied key material and refuses to sign for an `address` the key does
  not control (`AddressMismatch`). The signing address is embedded in the CIP-8
  COSE protected headers, so a verifier can confirm which credential signed. Across
  other chains the same `verify_sign_message_address` guard prevents signing a
  message under an address the wallet did not derive.
- **Selective stake witnessing.** `sign_transaction` only attaches a stake witness
  when the transaction body actually calls for one — a certificate stake
  credential, a pool-owner hash, a withdrawal reward account, or an explicit
  `required_signers` entry matching the stake key hash — so a routine payment
  transaction is never signed with the stake key. Conversely, when the body
  structurally requires a stake signature the wallet cannot provide, signing fails
  instead of emitting a transaction that would be rejected on submission.
  Transaction *content* is not otherwise inspected or policy-checked here —
  the signer trusts the caller-provided unsigned CBOR — so transaction building and
  vetting remain the responsibility of upstream layers.
- **Trust in the RPC-derived context.** Cardano input values come from the
  configured RPC provider, so the `TransactionContext` a policy evaluates is only
  as trustworthy as that endpoint. Fetching whole source transactions rather than
  provider-computed UTxO values narrows that trust: each returned CBOR is re-hashed
  and must match the hash it was requested under, so a provider cannot fabricate
  input values under a tx hash the transaction actually references (it can still
  withhold a transaction, which fails closed). The keyless Koios default
  trades authentication for operational simplicity; deployments with stronger
  requirements can point RPC config at Blockfrost (with `BLOCKFROST_PROJECT_ID`) or
  another trusted host via the `koios|` / `blockfrost|` URL prefixes. To limit
  silent under-reporting, a transaction with inputs and no RPC URL is rejected,
  and incomplete UTxO resolution aborts context construction rather than degrading
  to a partial view. On the balance path the same strictness applies to both
  providers: an unparseable lovelace balance or asset quantity is a hard `Decode`
  error (surfaced as `PayErrorCode::InvalidData`) rather than a silent `0`, so a
  malformed response cannot understate holdings. Nullable Koios fields
  (`asset_list`, `asset_name`, token-registry `decimals`) are modelled as optional
  and default to empty/`0`, because their absence is a normal response shape rather
  than corrupt data.

## Implementation

Components modified or added:

- `ows/crates/ows-core/src/chain.rs` — `ChainType::Cardano`; `cip34` namespace mapping;
  coin type `1815`; mainnet/preprod/preview registry entries;
  `UNIVERSAL_WALLET_EXTRA_CHAIN_NAMES`; `parse_chain` support.
- `ows/crates/ows-core/src/config.rs` — default Koios RPC endpoints for the three networks.
- `ows/crates/ows-core/src/cardano_rpc/` — `CardanoRpcProvider` trait,
  `resolve_cardano_provider`, `KoiosProvider`, and `BlockfrostProvider`.
- `ows/crates/ows-core/src/wallet_file.rs` — `KeyType::PrivateKey` doc updated to include
  `ed25519_bip32`.
- `ows/crates/ows-signer/src/curve.rs` — `Curve::Ed25519Bip32` and key lengths.
- `ows/crates/ows-signer/src/mnemonic.rs` — `Mnemonic::entropy()` (raw BIP-39 entropy).
- `ows/crates/ows-signer/src/hd.rs` — Icarus master-key generation and V2 child derivation;
  a single shared path parser (`parse_path_components`) that bounds every index
  below 2³¹.
- `ows/crates/ows-signer/src/chains/cardano.rs` — `CardanoSigner`, CIP-1852 path helpers,
  network selection, and the full `ChainSigner` impl: base/enterprise/reward
  address encoding, `sign`, CIP-8 `sign_message`, `sign_transaction`,
  `encode_signed_transaction`, the `default_derivation_paths` / `encode_keys`
  overrides, and the `make_transaction_context` override (resolves inputs via
  `resolve_cardano_provider` and `CardanoRpcProvider::fetch_txs_cbor`, and books
  withdrawals and certificate deposits/refunds against the reward address).
- `ows/crates/ows-signer/src/traits.rs` — `sign_message` gains `address: Option<&str>`; new
  default methods `verify_sign_message_address`, `default_derivation_paths`, and
  `encode_keys`; new `SignerError::AddressMismatch` and `SignerError::RpcError`.
  (`make_transaction_context` already existed as a default-empty hook; Cardano now
  overrides it.)
- `ows/crates/ows-lib/src/ops.rs` & `ows/crates/ows-lib/src/key_ops.rs` — `sign_and_send` and
  `sign_with_api_key` resolve the Cardano RPC URL and pass it into
  `make_transaction_context`; `broadcast_cardano` uses `resolve_cardano_provider`;
  `resolve_rpc_url` is exposed for reuse.
- `ows/crates/ows-pay/src/cardano.rs` & `ows/crates/ows-pay/src/error.rs` — address balance fetching via
  `CardanoRpcProvider::get_balances`; new `PayErrorCode::InvalidData` for a
  provider response whose amounts cannot be decoded.
- `ows/crates/ows-signer/src/chains/*.rs` — every chain's `sign_message` updated to the new
  signature and calls `verify_sign_message_address`.
- `ows/crates/ows-signer/src/chains/mod.rs` & `lib.rs` — register `CardanoSigner` in
  `signer_for_chain`; integration test uses `default_derivation_paths` and
  `encode_keys`.
- `ows/crates/ows-lib/src/ops.rs` — `KeyPair.ed25519_bip32`, random 192-byte generation,
  `validate_ed25519_bip32_key` on private-key import,
  curve dispatch, `broadcast_cardano`; `sign_message`/`sign_typed_data` thread the
  `address` argument; mnemonic derivation routes through `default_derivation_paths`
  and `encode_keys`.
- `ows/crates/ows-lib/src/key_ops.rs` — API-key `sign_message`/`sign_typed_data` thread
  `address` and call `verify_sign_message_address`.
- `ows/crates/ows-cli` — `sign message --address` flag; `derive` uses
  `default_derivation_paths` and `encode_keys`.
- `bindings/node` & `bindings/python` — `sign_message`/`sign_typed_data` expose
  the optional `address` argument.

Dependencies added:

- `ed25519-bip32 = "0.4.1"` — generic BIP32-Ed25519 derivation
  (`ows/crates/ows-signer/Cargo.toml`, `ows/crates/ows-lib/Cargo.toml`).
- `pbkdf2 = "0.12"` — Icarus master-key derivation
  (`ows/crates/ows-signer/Cargo.toml`).
- `cardano-serialization-lib = "14.1.1"` — Cardano network parameters
  (`NetworkInfo`), Shelley address encoding, and transaction/witness encoding
  (`ows/crates/ows-signer/Cargo.toml`).
- `emurgo-cardano-message-signing = "1.1.0"` — CIP-8 COSE message-signing helpers
  (`ows/crates/ows-signer/Cargo.toml`).
- `reqwest = "0.12"` (`json`, `rustls-tls`, no default features; `blocking` in
  `ows-core`) — HTTP client for the Cardano RPC providers
  (`ows/crates/ows-core/Cargo.toml`, `ows/crates/ows-pay/Cargo.toml`).
- `mockito = "1"` (dev-dependency) — mocks provider endpoints in the
  `make_transaction_context`, `cardano_rpc`, and balance tests
  (`ows/crates/ows-core/Cargo.toml`, `ows/crates/ows-pay/Cargo.toml`,
  `ows/crates/ows-signer/Cargo.toml`).

## Testing

Implemented and passing for these deliverables:

- **Curve** (`curve.rs`): key-length and equality tests for `Ed25519Bip32`.
- **Master key / derivation** (`hd.rs`): Icarus master `XPrv` vectors (named and
  all-zero "abandon" mnemonic); V2 hardened child derivation against
  `ed25519-bip32` crate vectors; rejection of a 64-byte BIP-39 seed for the
  Ed25519-BIP32 curve; equivalence of mnemonic-based vs master-`XPrv`-based
  derivation for `m/1852'/1815'/0'/0/0`.
- **Path validation** (`hd.rs`): indices at or above 2³¹ are rejected by
  `validate_path` and by `derive` on all three curves, while `2147483647`(`'`) is
  still accepted; repeated hardened markers (`m/44''`) are rejected; and
  `m/2147483648` no longer aliases `m/0'` on the Ed25519-BIP32 curve.
- **Mnemonic** (`mnemonic.rs`): `entropy()` returns all-zero entropy for the
  "abandon" vector, and matches the Trezor BIP-39 vectors for 12- and 24-word
  phrases (the 24-word cases pin the checksum-byte truncation, since 24 words
  carry 264 bits).
- **Chain registry** (`chain.rs`): serde round-trip including Cardano; namespace,
  coin type, and `from_namespace("cip34")` mappings; `parse_chain` for friendly
  names and `cip34:*` ids; universal-wallet order/count (mainnet + preprod +
  preview).
- **Config** (`config.rs`): default RPC lookups for all three Koios endpoints.
- **Signer** (`cardano.rs`): CIP-1852 path construction; chain type/curve/coin
  type; default path equals payment leaf.
- **Address encoding** (`cardano.rs`): mainnet **base** address from 12- and
  24-word mnemonics (via `default_derivation_paths` and `encode_keys`) against fixed
  `addr1q…` vectors;
  **enterprise** address from a payment-only key against fixed `addr1v…` vectors.
- **Message signing** (`cardano.rs`): CIP-8 `COSE_Sign1` output against reference
  vectors for the no-address, base, enterprise, and reward-address cases
  (including the expected serialized `COSE_Key` per signing credential).
- **Transaction signing** (`cardano.rs`): a CBOR test-transaction builder takes a
  body-customization closure and exercises the payment-only witness path, the
  payment + `required_signers` stake path, a stake-delegation certificate, and a
  withdrawal; `sign_transaction` signatures and the `encode_signed_transaction`
  output are asserted against reference CBOR, and the certificate/withdrawal cases
  assert that the witness set carries exactly the payment and stake public keys.
- **Key import** (`ows/crates/ows-lib/src/ops.rs`): a private-key wallet imports both the
  96-byte payment and the 192-byte payment ‖ stake Ed25519-BIP32 shapes and
  exports them unchanged; a 64-byte key and a 96-byte key with invalid scalar
  clamping are both rejected at import.
- **Cross-chain `sign_message`** (`evm.rs`, etc.): `AddressMismatch` is returned
  for a wrong `address`, and signing succeeds when the derived address is passed;
  `None` reproduces prior signatures (`solana.rs`, `bitcoin.rs`).
- **Integration** (`lib.rs`): `signer_for_chain` derives a mainnet `addr1…` base
  address via `default_derivation_paths`, `encode_keys`, and `derive_address`, now
  passing end-to-end.
- **Policy context** (`cardano.rs`, `cardano_rpc/`): `make_transaction_context` is
  exercised with a mocked Koios `tx_cbor` endpoint (`mockito`, via the `koios|`
  URL prefix, serving real CBOR for the source transactions) across the flow shapes
  that matter for policy evaluation — a
  self-transfer (only the negative fee shows up), a single input with an external
  payment plus change, the same with a native asset split between external and
  change outputs, and multi-input/multi-output transactions that rebalance across
  the wallet's own addresses and to a third party. Three staking shapes are covered
  on top of those: a **withdrawal** (reward address debited, payment address
  credited with the withdrawal minus the fee), a **stake registration deposit**
  (payment address debited by deposit + fee, reward address credited with the
  locked deposit), and a **stake deregistration refund** (the mirror image). Each
  asserts the exact sorted
  `effects` (per-address signed lovelace and asset diffs) and that the mock
  endpoint was hit. `KoiosProvider` and `BlockfrostProvider` have dedicated unit
  tests for broadcast, transaction-CBOR fetch, and balance queries.

## References

- [CIP-34: Cardano Blockchain identification](https://cips.cardano.org/cip/CIP-34) (status: Proposed)
- [CIP-1852: HD Wallets for Cardano](https://cips.cardano.org/cip/CIP-1852)
- [CIP-3: Wallet key generation (Icarus master key)](https://cips.cardano.org/cip/CIP-3)
- [CIP-8: Message signing](https://cips.cardano.org/cip/CIP-8)
- [CIP-30: Cardano dApp-Wallet Web Bridge (`signData`)](https://cips.cardano.org/cip/CIP-30)
- [CIP-19: Cardano addresses](https://cips.cardano.org/cip/CIP-19)
- [BIP32-Ed25519 (Khovratovich & Law)](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf)
- [`ed25519-bip32` crate](https://docs.rs/ed25519-bip32/0.4.1/)
- [`cardano-serialization-lib`](https://github.com/Emurgo/cardano-serialization-lib)
- [`cardano-message-signing`](https://github.com/Emurgo/message-signing)
- [RFC 8152: CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc8152)
- [Koios API](https://api.koios.rest/)
- [Blockfrost API](https://blockfrost.io/)
- [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) and [CAIP-10](https://chainagnostic.org/CAIPs/caip-10)
- [SLIP-44: Registered coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) (ADA = 1815)
