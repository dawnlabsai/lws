# `ows sign message` — Midnight: sign a message with the unshielded key

**Purpose:** sign an arbitrary message for a `midnight:<network>` wallet with its **unshielded**
(Night) key, producing a detached signature — the Midnight arm of the cross-chain `ows sign message`.

```sh
OWS_PASSPHRASE="…" ows sign message \
  --wallet demo --chain midnight:preview --message "hello world"
```

## What it signs with

Midnight message signing uses the wallet's **unshielded** signing key (the same key that authorizes
unshielded intents), derived inside `ows-signer`'s `MidnightCryptoProvider` from the packed `MNK1`
role seeds. The shielded and dust keys are not involved. As with every Midnight key operation, the
bearer key material never leaves `ows-signer`; the CLI and `ows-midnight` only ever see the resulting
signature.

## The credential

`OWS_PASSPHRASE` carries the **owner envelope passphrase** or an **api-key token**, resolved before
signing; a token routes through the same policy-enforcing channel as `sign send-tx`. Without a
credential the provider can't be built and the command errors (there is nothing public to sign with).

## Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; required to build the signing provider. |
| `OWS_WALLET` | Default for `--wallet`. |

## The code path

- CLI: `commands/sign_message.rs` → resolves the credential and calls the signer.
- Signing: `ows-signer/src/chains/midnight.rs` (`sign_unshielded_message`), using the provider's
  unshielded key. The per-network id / address HRPs come from `MidnightNetwork`.
