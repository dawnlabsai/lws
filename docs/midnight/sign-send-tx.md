# `ows sign send-tx` — Midnight: balance, sign, prove, seal, and submit a transaction

**Purpose:** take a DApp-connector request for a `midnight:<network>` wallet, balance it with the
wallet's own inputs, sign and prove it, seal it, and broadcast it to the node — the full
`sign → prove → seal → submit` pipeline behind one command.

```sh
OWS_PASSPHRASE="…" ows sign send-tx \
  --wallet demo --chain midnight:preview \
  --json --tx '<connector-request-json>'
```

On a `midnight:*` chain the `--tx` payload is a **DApp-connector request JSON** (not raw signed
bytes). The wallet reads it, funds/balances it against its own state, and submits the result. On
every other chain `send-tx` keeps its original meaning (sign hex bytes and broadcast).

As a shorthand, `--tx` also accepts a **bare** MIP-0005 `zswapoffer…` bech32 offer or a **bare** hex
transaction directly, with no JSON envelope. The wallet normalizes it into the equivalent request: a
bare offer or a fully-sealed maker becomes `balanceSealedTransaction`, any other proven hex a
`balanceUnsealedTransaction` (`ows sign tx` accepts the same forms).

## The connector methods

The request is routed by its JSON `method` field:

- **`balanceUnsealedTransaction`** (also the default when `method` is absent, for backward
  compatibility) — the DApp hands over a proven, *unsealed* transaction with a deficit; the wallet
  balances it with its own inputs across all three value domains, then seals and submits.
- **`makeTransfer`** — the wallet *builds* the outputs (a deficit), balances them with its own inputs,
  and seals. The intent keys off a fallible segment; unshielded NIGHT movement rides that segment's
  fallible offer (a multi-UTXO move would overrun the guaranteed section's tight `time_to_dismiss`
  budget), while shielded outputs ride the guaranteed section.
- **`makeIntent`** — build an imbalanced *maker offer* (real inputs + declared wanted outputs), able
  to contribute shielded inputs with per-token whole-coin change returned to the maker's own keys.
- **`balanceSealedTransaction`** — the *taker* completes a proven maker offer. The maker input may be
  a proven-hex offer, a bare `zswapoffer` bech32 (**MIP-0005**), or a **MIP-0006** offer-file JSON
  object.

An out-of-spec request (a proof-preimage input, a pre-existing dust registration, a `ClaimRewards`
mint claim, or a not-yet-supported sealed-maker encoding) is rejected with a **precise** error rather
than a generic "unsupported".

`ows sign tx` returns the fully sealed, proven Midnight transaction on `SignResult.transaction`
(`None` for other chains) — the seal-*without*-broadcast capability: the same bytes `send-tx`
broadcasts, surfaced through a command that never submits.

## What it does

1. **Parse** the connector request and classify the method.
2. **Plan (inert).** Select the wallet's own inputs to cover the deficit — per intent segment,
   across unshielded Night, shielded Zswap, and dust — **without** building any spend witness. The
   plan carries only public selection data; no bearer instrument exists yet. This is the point a
   policy pass can gate on the plan's key-derived effects (the `prepare_signable_tx` seam).
3. **Authorize (past the seam).** Inside `ows-signer`, build and prove the shielded/dust spend
   preimages, sign the unshielded intent (detached BIP-340), and fold the proven sections back in.
   The spend witness is born and consumed behind the key boundary and never reaches the balancer.
4. **Seal** the proven, signed transaction.
5. **Submit** the sealed bytes to the node over its Substrate RPC and print the resulting tx hash.

## End-to-end on preprod

`e2e/midnight-sign-send-tx.sh` exercises this command against the live preprod node. It builds `ows`
from the checkout, confirms the command is wired, and checks that a malformed request is rejected with
a precise error (all offline); then it runs the live path in two steps — **seal** the request with
`sign tx` (no broadcast, printing the sealed tx), then **submit** it with `sign send-tx`. A DApp
normally supplies the proven (`proof,embedded-fr`) input; the checkout bundles one built on preprod at
`e2e/shielded-movement-cap/tx-proven-preprod.hex`, so the live run works out of the box (override it
with `TX_JSON=<path>`). That maker is input-free, so each run re-selects fresh wallet inputs and is
reusable.

A real preprod round-trip landed on-chain at
`0x379f10efcd2b82bac2c5e281d2d175b0367aef195b8845cdb75388737632fed3` (block 1762181), crediting the
wallet's own address with the balanced outputs.

## The three value domains

- **Unshielded (Night).** Balanced from the wallet's UTXO set; authorized with a detached BIP-340
  intent signature.
- **Shielded (Zswap).** Balanced from the wallet's own synced coins (whole-coin selection, self-change
  to the wallet's keys); each spend witness is built and proved inside the signer via the crypto
  provider.
- **Dust (fees).** The fee is sized against the node's real fee gate. Whether a dust registration is
  added is decided at run time by a `dust_ledger_is_live` probe against the indexer (see
  [fund-balance.md](./fund-balance.md)), not a compiled-in flag; fees are paid with a generationless
  registration or a proof-bearing spend when NIGHT is fully registered. By default (`payFees: true`)
  the wallet pays the fee; if the probe can't confirm the dust ledger is live it errors rather than
  emit a fee-less tx the node would reject — pass `payFees: false` to opt out on a genuinely fee-less
  network.

## The credential

`OWS_PASSPHRASE` carries either the **owner envelope passphrase** (decrypts the packed `MNK1` role
seeds and builds the `MidnightCryptoProvider`) or an **api-key token** (routes through the same
policy-enforcing channel). All bearer key material stays in `ows-signer`; `ows-midnight` holds none
(enforced by the `no_key_material_gate` workspace test).

## Node RPC

Submission talks to the Substrate node RPC, resolved **separately from the balance indexer**. Provide
it with `--rpc-url <url>`, else it resolves from `~/.ows/config.json` (`rpc["midnight:<network>"]`,
node endpoint); defaults ship for mainnet/preview/preprod.

## Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; required to build the provider that signs/proves. |
| `OWS_WALLET` | Default for `--wallet`. |

## The code path

- CLI: `commands/send_transaction.rs` → `ows_lib::sign_and_send` (token) / `sign_encode_and_broadcast`
  (owner); Midnight routes through `decode_tx_input` → `prepare_signable_tx` (the plan/authorize seam).
- Balancing + seam: `ows-midnight/src/balance_tx.rs` (`plan_unsealed_proven_tx`, `authorize_proven_tx`),
  `balance_tx/fee_sizing.rs`, `dapp_connector/{mod,balance_unsealed}.rs`, `prover.rs`.
- Authorization (bearer instruments): `ows-signer/src/chains/midnight.rs`
  (`authorize_shielded`, `authorize_dust`, `sign_proven_intent`, `seal_signed_proven`).
- Submission: `ows-midnight/src/submit.rs`; node RPC config in `ows-core/src/config.rs`.
