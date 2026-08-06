# `ows wallet …` — Midnight in the universal wallet

**Purpose:** Midnight is a first-class account in **mnemonic** wallets — `wallet create`,
`import --mnemonic`, `list`, and `info` surface a `midnight:*` account automatically. This doc
covers how that account is derived, and why **raw private-key** wallets deliberately have no
Midnight account.

## Midnight in the default account set

`ChainType::Midnight` is part of `ALL_CHAIN_TYPES`, the set every universal-wallet command
iterates. So a mnemonic wallet derives a Midnight account with no per-command special-casing —
the signer resolves through `signer_for_chain_type` like any other chain:

```sh
export OWS_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
export OWS_PASSPHRASE="…"
ows wallet import --name demo --mnemonic
# Wallet imported: …
#   eip155:1 → 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
#   … other chains …
#   midnight:mainnet → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
```

`wallet info` lists Midnight among the supported chains, and `mnemonic derive` with no
`--chain` includes a `midnight:mainnet` line. The account is the **unshielded (Night)** address
only — one address per chain, like every other chain; the shielded and dust addresses surface
together in the balance command.

## The packed signing key (why it's mnemonic-only)

Listing the address needs only the unshielded seed, but *acting* on Midnight needs all three
role seeds. When a Midnight signing key is resolved from a mnemonic, `MidnightSigner::encode_keys`
concatenates the three 32-byte role seeds behind a 4-byte magic prefix `MNK1`, producing a
100-byte opaque signing key:

```
MNK1 || unshielded(32) || shielded(32) || dust(32)
```

`decode_keys` splits it back by position; `encode_keys` looks each seed up **by its path role**,
so the packed order is independent of arrival order. The three seeds come from
`default_derivation_paths` (the role paths under coin type 2400). This bundle only exists via
mnemonic derivation — which is exactly why Midnight has no raw private-key import.

## No raw private-key import

`wallet import --private-key` derives one account per chain from a **single** raw curve key.
That can't produce a Midnight account: the account *is* the three-seed `MNK1` bundle, and a lone
32-byte key is neither the bundle nor usably one-third of it. Rather than manufacture a crippled
or random Midnight address, Midnight opts out via an intrinsic signer gate:

```rust
// ows-signer: ChainSigner default
fn supports_private_key_import(&self) -> bool { true }
// MidnightSigner overrides it to false
```

`derive_all_accounts_from_keys` skips any signer whose `supports_private_key_import()` is false,
so **private-key wallets simply have no Midnight account** — the rest of the import is
unaffected. Only mnemonic-backed wallets carry Midnight.

Export needs no Midnight-specific handling either: `wallet export` is wallet-level — it returns
the mnemonic phrase, or (for private-key wallets) the `{secp256k1, ed25519}` key pair — never a
per-chain key. A private-key wallet holds nothing Midnight to export; a mnemonic wallet exports
the phrase, which already carries full Midnight capability.

## The three addresses

`MidnightSigner::derive_addresses` decodes a packed key and produces all three addresses for a
network:

- **unshielded (Night)** — `SHA-256(x-only BIP-340 pubkey)`, HRP `mn_addr{suffix}`.
- **shielded (Zswap)** — `coinPublicKey || encryptionPublicKey`, HRP `mn_shield-addr{suffix}`.
- **dust** — the SCALE-encoded dust public key, HRP `mn_dust{suffix}`.

`{suffix}` is empty on mainnet and `_{reference}` on every other network (`mn_addr_preview`,
`mn_shield-addr_preview`, `mn_dust_preview`, …). The wallet account and `derive` expose only the
unshielded one; shielded and dust surface together in the balance command.

## Validation

- `mnemonic_wallet_includes_midnight_account` (`ows-lib/src/ops.rs`) pins the Midnight account a
  mnemonic wallet derives; `privkey_wallet_import_both_curve_keys` asserts a private-key wallet
  has **no** Midnight account.
- `midnight_opts_out_of_private_key_import` (`ows-signer/src/chains/midnight.rs`) locks the gate;
  `test_all_chain_types` (`ows-core`) confirms Midnight is in `ALL_CHAIN_TYPES`.
- `midnight_derive_addresses_mainnet_vector` pins the exact three-address output; the packed key
  round-trips via `encode_decode_keys_round_trip` / `midnight_decode_keys_rejects_non_midnight_blobs`.
