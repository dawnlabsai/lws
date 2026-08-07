# `ows key create` — API tokens for the Midnight agent path

**Milestones:** Midnight 1 (PR #14, token-routed `fund balance`) and Midnight 3
(PR #18, effect-gated `sign tx`).
**Purpose:** mint an API token (`ows_key_…`) that an autonomous agent uses in place of the
owner passphrase, scoped to specific wallets and policies.

```sh
ows key create --name mn3-agent --wallet length-wallet --policy mn3-move-cap
# → ows_key_a126…            (printed once; store it)
```

`key create` is generic, but it is the linchpin of Midnight's **agent** model: every
Midnight command that needs the key accepts *either* the owner passphrase *or* a token in
`OWS_PASSPHRASE`, and the token is what turns on policy enforcement.

## Owner vs token — one env var, two meanings

`OWS_PASSPHRASE` is inspected by prefix (`key_store::TOKEN_PREFIX` = `ows_key_`):

- **No `ows_key_` prefix** → treated as the **owner envelope passphrase**. Decrypts the
  stored mnemonic with scrypt. Full authority, no policy gate. (Imported wallets use an
  empty passphrase, so owner unlock is literally `OWS_PASSPHRASE=`.)
- **`ows_key_` prefix** → treated as an **API token**. The key is looked up by token hash,
  the token's expiry and wallet-scope are checked (`load_authorized_wallet`), policies are
  evaluated, and only on allow is the key decrypted (via HKDF). This is the agent path.

Both converge on the same packed Midnight key and the same downstream code — only
credential resolution and policy-gating differ.

## Where the token matters for Midnight

### `fund balance` (Midnight 1)

A token routes balance reads through the policy-enforcing channel
(`enforce_policies_and_decrypt_key`) rather than the raw envelope decrypt. Balance has no
transaction to bind spending policies against, so here the token proves *access* — it lets
an agent read shielded/dust balances without holding the owner passphrase. A bad or
unknown token fails cleanly (`error: API key not found`, exit 1, no panic — validated as
balance case **M6**). A no-policy token yields the full balance (case **M4**).

### `sign tx` (Midnight 3)

A token turns on **both** policy passes for the connector pipeline
(see [sign-tx.md](./sign-tx.md)):

1. the first pass gates the request shape (declarative rules),
2. the second, effect-aware pass gates the wallet-relative movement (executable policies).

Attach the effect-aware policy at mint time with `--policy <id>` (see
[policy-create.md](./policy-create.md)); the token then enforces it on every `sign tx`.

> **⚠ A declarative-only token does not cap movement.** The second pass runs **only
> executable** policies. A token whose policies carry *only* declarative rules
> (`AllowedChains`, expiry, …) passes the second pass unconditionally — it gates *which*
> transactions may be signed, not *how much they move*. To bound value, the token must carry
> an **executable** effect policy; minted with shape rules only, it lets the agent move
> unlimited value on Midnight.

## Scope and lifecycle

- `--wallet` is repeatable — a token is scoped to the wallet ids it is minted for, and
  `load_authorized_wallet` rejects use against any other wallet.
- `--policy` is repeatable — attach one or more policy ids.
- `--expires-at` sets an optional ISO-8601 expiry, checked on every use.
- `ows key list` shows the keys (never the tokens); `ows key revoke --id <id> --confirm`
  removes one.

## How this differs from other chains

The token machinery is chain-agnostic. The Midnight-specific consequences are the two
places above — token-routed balance reads across three domains, and the **two-pass**
policy enforcement on the connector `sign tx` path (only Midnight has a second,
effect-aware pass).

## Validation

- **Balance:** cases **M4** (token → full balance) and **M6** (bad token → clean error) in
  `e2e.md` / `e2e/results-2026-07-16.md` Suite A.
- **Signing:** cases **C1–C2** in `e2e/policy-second-pass.md` mint a scoped, policy-bearing
  key and exercise the deny/allow gate on `sign tx`.
</content>
