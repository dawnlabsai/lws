# `ows mnemonic derive` — Midnight address derivation

**Purpose:** derive and print a Midnight address from a mnemonic, without touching the vault.

```sh
OWS_MNEMONIC="…" ows mnemonic derive --chain midnight:preview
# → mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
```

The mnemonic is read from `OWS_MNEMONIC` (or stdin), used, and immediately zeroized. No
network access, no wallet file — pure derivation.

## Reproduce it

Every output below comes from the BIP-39 test phrase
`abandon abandon … abandon about` at index 0 — the same vector the unit tests pin, so you
can run these verbatim and match byte-for-byte:

```sh
export OWS_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

ows mnemonic derive --chain midnight:mainnet
# → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
ows mnemonic derive --chain midnight:preview
# → mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
ows mnemonic derive --chain midnight:preprod
# → mn_addr_preprod1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q49ekgd

ows mnemonic derive --chain midnight            # 'midnight' alias resolves to mainnet
# → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
ows mnemonic derive --chain midnight:feature-x  # any ad-hoc reference is kept verbatim
# → mn_addr_feature-x1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qgl8r2t
ows mnemonic derive --chain midnight:preview --index 1
# → mn_addr_preview14vxp6lccnpxc2zecz5a7fls8cc63kme540jwgajrakhmvc9xkxmqpmzrx8
```

Two things to notice. The mainnet address matches the `midnight_derive_addresses_mainnet_vector`
unit vector exactly. And across mainnet / preview / preprod / feature-x the Bech32m *data*
part is identical (`dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q`) — only the HRP and
its checksum change. One key, one hash; the network id lives in the human-readable prefix.

## What it prints

`ows mnemonic derive --chain midnight:*` prints **only the unshielded (Night) address**.
It does not print the shielded or dust addresses. This is deliberate: `derive` is the
generic one-address-per-chain command shared with EVM, Solana, Bitcoin, etc., and every
other chain has exactly one address. Midnight's shielded and dust addresses only surface
together, in a command that shows all three at once.

Because Midnight is in the wallet's default account set (`ALL_CHAIN_TYPES`), `derive` with no
`--chain` — which enumerates that set — also emits a `midnight:mainnet` line (the default
network). Pass `--chain midnight:<network>` to select preview/preprod or an ad-hoc reference.

## The code path

`commands/derive.rs` is chain-agnostic and routes address derivation through the multi-key
bundle — every chain's key material flows `encode_keys` → `derive_address`:

```rust
let signer = signer_for_chain(&chain);                      // → MidnightSigner for midnight:*
let paths  = signer.default_derivation_paths(index);        // three role paths for Midnight
let keys   = HdDeriver::derive_keys_from_mnemonic_cached(&mnemonic, "", paths, curve)?;
let signing_key = signer.encode_keys(&keys)?;               // packed MNK1 bundle
let address = signer.derive_address(signing_key.expose())?; // unshielded address
```

For Midnight, `signer_for_chain` resolves to `MidnightSigner`, `curve()` is secp256k1, and
`default_derivation_paths` returns the three role paths. `encode_keys` packs the derived
seeds into the `MNK1` bundle; `MidnightSigner::derive_address` decodes it back to the
unshielded seed and builds the address. A single-key chain's `encode_keys` returns its one
key unchanged, so the same call shape serves every chain — the `MNK1` magic prefix is what
`derive_address` uses to tell a bundle (decode it) from a bare imported key (use directly).

## How the unshielded address is built

`MidnightSigner::derive_unshielded_address_with_hrp` (`ows-signer/src/chains/midnight.rs`):

1. Interpret the 32-byte seed as a secp256k1 **BIP-340 Schnorr** signing key.
2. Take its 32-byte **x-only** public key (`verifying_key().to_bytes()`).
3. `SHA-256` that public key.
4. Bech32m-encode the 32-byte hash under the network's unshielded HRP.

The HRP is `mn_addr` on mainnet and `mn_addr_{reference}` on every other network. The
network `reference` is the CAIP-2 part after `midnight:`, kept **verbatim** (lowercased)
and never mapped to a fixed set — so `midnight:preview`, `midnight:preprod`, and any ad-hoc
feature testnet like `midnight:feature-x` all derive a correctly-tagged address
(`mn_addr_preview…`, `mn_addr_preprod…`, `mn_addr_feature-x…`) rather than being cast to
mainnet or rejected. This follows the Midnight WalletEngine specification for the Night
address.

## Why the derivation looks the way it does

Midnight uses a **multi-role** BIP-44 tree rather than the single derivation path most
chains use:

```
m/44'/2400'/0'/{role}/{index}
                ^role: 0 = unshielded (Night), 2 = dust, 3 = shielded (Zswap)
```

- **SLIP-44 coin type `2400`** identifies Midnight.
- **Account `0'`** is fixed — OWS is single-address-per-wallet, so per-address selection
  is the address `index`, not the account.
- The three **roles** produce the three independent domain seeds.

`derive` prints only the unshielded (role 0) address, but — because address derivation
routes every chain through the bundle — it assembles the full three-seed `MNK1` bundle and
`derive_address` extracts role 0 from it. That same packed bundle is what the shielded and
dust operations use to *act* in those domains — see the packed-key section in
[wallet.md](./wallet.md).

The role constants and path builder live in one place (`MidnightSigner::derivation_path`
/ `role_from_path`) so the coin type and account are a single source of truth, and a
derived key can be mapped *back* to its role when the bundle is decoded.

## How this differs from other chains

| | Other chains | Midnight |
|---|---|---|
| Addresses per account | 1 | 3 (unshielded / shielded / dust) |
| What `derive` prints | the address | the **unshielded** address only |
| Derivation | one path | three role paths under coin type 2400 |
| Address math | curve-specific (keccak, base58, …) | Bech32m of `SHA-256(x-only BIP-340 pubkey)`, network HRP |

## Validation

Unit vectors in `ows-signer/src/chains/midnight.rs` lock the derivation:

- `midnight_derive_addresses_mainnet_vector` pins the exact mainnet unshielded / shielded /
  dust address bytes for the abandon-phrase test wallet.
- `midnight_preview_unshielded_address_uses_preview_hrp` and
  `midnight_derive_addresses_preview_uses_preview_hrps` confirm the preview HRPs
  (`mn_addr_preview…`, `mn_shield-addr_preview…`, `mn_dust_preview…`).
- `midnight_from_chain_id_preserves_arbitrary_reference` /
  `…_lowercases_reference` confirm an ad-hoc `midnight:feature-x` network derives
  `mn_addr_feature-x…` (and normalizes case) instead of falling back to mainnet.
