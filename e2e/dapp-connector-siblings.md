# e2e — DApp Connector sibling methods (live, preview)

Validates the four connector methods end-to-end through the real pipeline
(`decode_tx_input → prepare_signable_tx → plan_connector_tx → ConnectorPlan::authorize
→ sign → prove → seal`). All four flow through the connector `--tx`, which carries the
**connector request JSON verbatim** (see `decode_tx_input`).

These require a local prover (circuit keys, fetched on first use into
`~/.ows/chains/midnight/proving-keys`) + a funded preview wallet + indexer — they can't
run in CI. Run them by hand on preview.

## Prerequisites

- Built release CLI: `cargo build --manifest-path ows/Cargo.toml --release`
- A funded preview wallet (the notes use `length-wallet`, unlocked by an empty passphrase).
- **Sealing vs broadcasting** (there is no `--no-submit`):
  - `ows sign tx --json` plans → authorizes → proves → **seals** and returns the sealed hex on
    `SignResult.transaction`. It does **not** broadcast — use it to inspect/hand off the hex.
  - `ows sign send-tx --json` does the same **and broadcasts**, returning `{ "tx_hash": "0x…" }`.
- Recipient addresses: use your own wallet's addresses (self-transfer) so value doesn't leave, or a
  second wallet you control. The `Addresses:` block of `ows fund balance` prints them:
  `mn_addr_preview1…` = unshielded, `mn_shield-addr_preview1…` = shielded.

```sh
OWS=ows/target/release/ows
CHAIN=midnight:preview
WALLET=length-wallet
export OWS_PASSPHRASE=          # empty unlocks length-wallet
```

## 1. makeTransfer — build + balance + prove + seal (+ broadcast)

The wallet constructs the outputs (a deficit), then balances with its own inputs. Fees are paid in
**dust**, not in the transferred token.

```sh
# Seal without broadcasting (inspect the hex):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "method": "makeTransfer",
  "desiredOutputs": [
    { "kind": "unshielded", "type": "night", "value": "1000000", "recipient": "<mn_addr_preview1…self>" }
  ],
  "options": { "payFees": true }
}'
# → { "recovery_id", "signature", "transaction": "0x…sealed hex" }

# Broadcast (returns the txhash):
$OWS sign send-tx --chain $CHAIN --wallet $WALLET --json --tx '{ …same request… }'
# → { "chain": "midnight:preview", "tx_hash": "0x…" }
```

Verify on-chain (and check the recipient credit equals the requested value):

```sh
curl -s https://indexer.preview.midnight.network/api/v4/graphql \
  -H 'content-type: application/json' \
  -d '{"query":"{ transactions(offset:{hash:\"0x<HASH>\"}){ block{height} unshieldedCreatedOutputs{ owner value tokenType } } }"}'
```

Also try a shielded output (`"kind":"shielded"`, a `mn_shield-addr_preview1…` recipient). Note the wallet
must hold the shielded token being sent — native **shielded** NIGHT is often 0; use a custom shielded
token the wallet holds (`"type":"<0x…32-byte-hex>"`).

## 2. makeIntent — imbalanced maker offer (export, do NOT submit)

Maker contributes real unshielded inputs and declares wanted outputs; the result is deliberately
imbalanced, so seal it with `sign tx` (no broadcast) and hand the hex to the taker (step 3).

```sh
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "method": "makeIntent",
  "desiredInputs":  [ { "kind": "unshielded", "type": "<other-token-hex>", "value": "10" } ],
  "desiredOutputs": [ { "kind": "unshielded", "type": "night", "value": "500000", "recipient": "<mn_addr_preview1…self>" } ],
  "intentSegment": 1,
  "options": { "payFees": true }
}'
```

Expect: a proven, imbalanced maker offer. `sign tx` seals it as a **fully-sealed**
(`proof,pedersen-schnorr`) offer — which a taker completes by MERGING in its complement (step 3a).

## 3. balanceSealedTransaction — taker completes the maker offer

Feed a maker offer as `makerTx`; the taker's wallet funds the imbalance, balances, signs and seals.
**The accepted maker format matters:**

```sh
# 3a. A FULLY-SEALED maker offer (proof,pedersen-schnorr — e.g. the step-2 output) is completed by MERGING:
$OWS sign tx --chain $CHAIN --wallet <taker-wallet> --json --tx '{
  "method": "balanceSealedTransaction",
  "makerTx": "<fully-sealed-maker-hex>",
  "options": { "payFees": true }
}'
#   → { … "transaction": "0x…merged+sealed hex" }
#     the taker builds the per-token complement of the maker's imbalance, funds the merged tx's dust fee,
#     seals its half, and Transaction::merge's the two into a balanced, submittable whole.

# 3b. A PROVEN (proof,embedded-fr) maker offer is the happy path — balanced + sealed:
$OWS sign tx --chain $CHAIN --wallet <taker-wallet> --json --tx '{
  "method": "balanceSealedTransaction",
  "makerTx": "<proof,embedded-fr maker hex>",
  "options": { "payFees": true }
}'
#   → { … "transaction": "0x…balanced+sealed hex" }
```

> **Note (changed since `--no-submit`):** the old `sign send-tx --no-submit` produced a
> `proof,embedded-fr` offer that this method could complete directly. `sign tx`'s makeIntent output is
> now *fully sealed*, so the step-2→step-3 chain lands on 3a — the taker completes it by MERGING (above).
> Step 3b (a `proof,embedded-fr` maker, e.g. `e2e/shielded-movement-cap/tx-proven.hex`) still balances in
> place. Either way the taker needs **dust** for fees; a freshly-funded wallet with only NIGHT and no dust
> cannot be the taker.

> **Supported maker shapes (in-place balancing).** The in-place proven path — 3b and
> `balanceUnsealedTransaction` (§4) — balances a maker that carries **no unshielded inputs of its own**.
> The taker supplies *and signs* the balancing inputs and cannot sign an input belonging to the maker, so
> a proven tx that already holds foreign unshielded inputs is rejected (`transaction carries dapp-provided
> unshielded inputs, which is unsupported`). A maker that funds its own unshielded side — e.g. a
> `makeIntent` giving NIGHT — must therefore be **sealed** and completed via the merge path (3a), where its
> inputs carry its own signature and the taker only adds its complement. In-place balancing is for
> deficit-style and shielded-only (zswap) makers.

## 4. balanceUnsealedTransaction — regression (unchanged)

The dapp hands the wallet an already-**proven** (`proof,embedded-fr`) unsealed tx; the wallet balances it
against its own inputs, then signs and seals.

```sh
# 4a. proof,embedded-fr → balanced + sealed (the spec-conformant input):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "tx": "<proof,embedded-fr hex, e.g. e2e/shielded-movement-cap/tx-proven.hex>",
  "options": { "payFees": true }
}'
#   → { … "transaction": "0x…" }

# 4b. proof-preimage → REJECTED (the dapp must prove its own part first):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "tx": "<proof-preimage hex, e.g. e2e/shielded-movement-cap/tx.hex>",
  "options": { "payFees": true }
}'
#   → error: … expects a proven (proof,embedded-fr) transaction … received a proof-preimage transaction
```

## Coverage note

Now supported (previously deferred): `makeIntent` **shielded inputs** — whole-coin spend with per-token
change to the maker, live-validated via the makeIntent → `balanceSealed` merge round-trip — and
`balanceSealed` **MIP-0005** (`zswapoffer` bech32) / **MIP-0006** (offer-file JSON) inputs, which decode
and balance. A pure-shielded offer wraps to a tx with no intent, so the balancer synthesizes a fresh
intent to carry the taker's dust fee; MIP balancing is unit-tested, with a live run pending a
DApp-produced offer artifact.

Still out of spec (reject with a precise error): a `proof-preimage` maker, a pre-existing dust
registration, and a `ClaimRewards` mint.

See `e2e/results-2026-07-16.md` for a full live run with on-chain txhashes.
