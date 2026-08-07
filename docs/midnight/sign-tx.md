# `ows sign tx --chain midnight:*` — the DApp-connector pipeline

**Milestones:** Midnight 2 (PR #15, the pipeline + four connector methods) and
Midnight 3 (PR #18, the effect-aware second policy pass).
**Purpose:** turn a DApp Connector request into a fully proven, signed, **sealed**
transaction — without broadcasting it.

```sh
OWS_PASSPHRASE= ows sign tx --chain midnight:preview --wallet length-wallet --json --tx '{
  "method": "makeTransfer",
  "desiredOutputs": [
    { "kind": "unshielded", "type": "night", "value": "1000000", "recipient": "<mn_addr…>" }
  ],
  "options": { "payFees": true }
}'
# → { "recovery_id": …, "signature": "…", "transaction": "0x…sealed hex" }
```

On every other chain, `sign tx` accepts hex-encoded unsigned transaction bytes and returns
a signature. On Midnight the wallet **is** the DApp Connector: the `--tx` argument is a
JSON connector request describing *what the user wants*, and the wallet constructs,
balances, proves, signs, and seals a complete transaction. `sign tx` seals it and returns
the sealed hex on `SignResult.transaction`; it does **not** broadcast. (Broadcasting is
[`sign send-tx`](./sign-send-tx.md).)

## Why `--tx` is JSON, not hex

`decode_tx_input` (`ows-lib/src/ops.rs`) hex-decodes for every chain **except** Midnight,
where it carries the argument through unchanged as UTF-8 bytes. This is because a Midnight
connector request is a JSON document, not a wire transaction, and it must be parsed by the
*key-aware* step (the wallet's own inputs are needed to balance it). Decoding needs no key,
so it can run before policy evaluation on the agent path.

## The pipeline

```
decode_tx_input            carry the JSON request through (no key)
        │
prepare_signable_tx        the key-aware step (ows-lib):
        │   ├─ build ONE MidnightCryptoProvider from the credential (ows-lib holds the key)
        │   ├─ plan_connector_tx  → an inert ConnectorPlan (no proofs, no signatures)
        │   ├─ plan.effects(…)    → the wallet-relative net movement
        │   ├─ ── POLICY SEAM ──  gate(effects)   ← second, effect-aware policy pass
        │   └─ plan.authorize(…)  → build + prove + sign the binding + serialize
        │
sign / seal                extract signable bytes, sign, encode_signed_transaction (seal)
        │
SignResult.transaction     the sealed, submit-ready tx hex (NOT broadcast)
```

The key design point is that **the plan is inert** — `ConnectorPlan` carries no bearer
instrument (no proofs, no signatures). That lets the wallet derive the transaction's
*effects* and run a policy check on them **before** any expensive proving happens. If the
policy denies, the key is dropped unused and nothing is ever proved.

`ows-lib` is the only layer that touches the decrypted key: it builds the
`MidnightCryptoProvider` once and hands only `&provider` into `ows-midnight`.

## Owner mode vs agent (token) mode

`sign tx` reads `OWS_PASSPHRASE`:

- **Owner passphrase** → decrypt the key directly, full authority. `prepare_signable_tx`
  is called with a gate that always allows — no policy at all.
- **API token** (`ows_key_…`) → two policy passes:
  1. **First pass** (`enforce_policies_and_decrypt_key`) — before the key is released,
     the request's *shape* is gated. `make_transaction_context` surfaces the raw request;
     `effects` is empty here because nothing has been planned yet. Declarative rules
     (allowed chains, allowed methods, …) fire here.
  2. **Second pass** (the policy seam, `enforce_effect_policies`) — after planning, the
     plan's key-derived, wallet-relative **effects** are filled in and the key's
     **executable** policies are re-evaluated. This is the Midnight-3 addition.

Both `sign tx` and `sign send-tx` run this same two-pass connector pipeline on the agent
path — `sign_and_send` routes Midnight through `decode_tx_input` + `prepare_signable_tx`
exactly as `sign tx` does. The only difference is the tail: `sign tx` seals and returns
the hex; `sign send-tx` also broadcasts. So a policy denial at either pass blocks a
broadcast too — the transaction is never proved, let alone submitted.

## The four connector methods

`plan_connector_tx` routes on the request's top-level `method`. An **absent** `method`
resolves to `balanceUnsealedTransaction`, the wallet's original (pre-multi-method)
behavior. Each method has its own submodule under `ows-midnight/src/dapp_connector/`.

### `makeTransfer`

*"Send these outputs."* The wallet builds an outputs-only transaction (a deliberate
deficit), then balances it with its **own** inputs, proves, signs, and seals. Fees are
paid in **dust**, never in the transferred token.

- Unshielded outputs ride the guaranteed section of an intent keyed at a **fallible
  segment (≥1)** — the ledger reserves segment 0 for the guaranteed section and rejects an
  intent declared there (surfaced on-chain as `Custom error: 167`). The outputs still
  execute unconditionally; only the *intent* is off segment 0.
- Shielded outputs ride the guaranteed Zswap offer directly.
- The outputs-only proven transaction reuses the same `plan_unsealed_proven_tx →
  authorize_proven_tx` tail as `balanceUnsealed` — one "diagonal" that every method funnels
  into.

### `makeIntent`

*"Build a maker swap offer."* The wallet contributes real inputs and declares wanted
outputs, producing a deliberately **imbalanced** maker offer (a swap intent). `sign tx`
seals it as a fully-sealed offer (`proof,pedersen-schnorr`) for hand-off to a taker.
Shielded *inputs* to a maker offer are supported — the wallet selects whole shielded coins,
returns the excess as change to the maker, and the spend witnesses are built and proved in
the signer.

**`options.intentId`** — the segment the maker's intent keys at, per the spec: a number, or
`"random"` to let the wallet draw one (its suggested mode for swaps; a wide draw is what keeps
two independently-built intents from colliding when the taker merges its own in). Omitted, it
is segment 1. Segment 0 is rejected — that is the guaranteed section, where the ledger rejects
an intent outright (`Custom error: 167`) — as is anything past the 16-bit segment space.

**`options.payFees`** — `true` is **rejected** here, with an error saying so. A maker offer is
imbalanced and fee-free by construction: the taker funds the DUST fee when it completes the
swap. The spec's blanket default for `payFees` is `true`, but its own reference SDK defaults
`initSwap` to `false`, and an error is the honest answer to a request this wallet cannot
satisfy — better than returning an offer that quietly does the opposite. Omitted or `false`
builds the fee-free offer. (The other three methods do honor `payFees` in both directions.)

**`options.ttl` — when the offer expires.** Optional; Unix epoch seconds. Omitted, the wallet
picks the widest window the ledger accepts (`global_ttl` past now — currently an hour, and the
reference wallet SDK's default too), which is what every offer got before this option existed.

The expiry matters more here than on the other methods. `Intent.ttl` is inside the seal cover
and `makeIntent` runs no balancing tail, so **nothing downstream can change it** — not the
taker, not a service relaying the offer. It is also the maker's only unilateral way out: a
sealed offer is a bearer artifact, cancellable only by letting it expire or by double-spending
one of its inputs. A maker quoting a price it re-quotes often is therefore writing a free option
against itself for the whole window, and wants a short one:

```sh
# this quote stands for 30 seconds
"options": { "ttl": 1785878998 }
```

The request is rejected at parse — before any proving is paid for — if the instant is not in the
future (born expired) or is further than `global_ttl` ahead, the two bounds the ledger enforces
against the block the offer lands in (`IntentTtlExpired`, `IntentTtlTooFarInFuture`).

A taker should read the maker's TTL before completing an offer: the merged transaction has to
land inside it, and the taker's own tip-aligned TTL does not extend it — the ledger checks each
intent's TTL separately.

> `ttl` is **not** in the DApp Connector specification, which defines no expiry option on any
> method and leaves the choice to the wallet. It is an OWS extension, kept optional precisely so
> that a spec-compliant dApp that never sends it is unaffected, and proposed upstream for the
> spec to adopt.

### `balanceSealedTransaction`

*"Complete a maker's offer as the taker."* The wallet funds the maker's imbalance with its
own inputs, balances, signs, and seals. The accepted maker format matters:

- A **proven** maker (`proof,embedded-fr`) is the happy path — the taker funds the
  imbalance with its own inputs, balances, signs, and seals.
- A **fully-sealed** maker (`proof,pedersen-schnorr`) cannot be balanced in place (its
  binding fixes the value balance), so the taker completes it by **MERGING**: it builds the
  per-token complement of the maker's imbalance, funds the merged tx's DUST fee, seals its
  half, and `Transaction::merge`s the two.
- A bare `zswapoffer` bech32 (MIP-0005) or a MIP-0006 offer JSON is accepted too — wrapped
  or materialized into a proven maker, then balanced.

### `balanceUnsealedTransaction`

*"Balance this proven, unsealed transaction against my inputs."* The dApp hands the wallet
an already-**proven** (`proof,embedded-fr`) transaction; the wallet balances it, signs, and
seals. This is the original method (and the default when `method` is absent).

- A `proof-preimage` transaction is **rejected** with a precise "out-of-spec, not
  unsupported" message — the dApp must prove its own part first.

> The only **rejected-by-design** input is a `proof-preimage` maker (above) — out of spec,
> not unsupported. `makeIntent` shielded inputs, the sealed-maker merge, and the MIP-0005 /
> MIP-0006 offer forms are all supported (added in [Midnight 2.5]).

## Fees are always dust

Every method pays fees in **dust**, sized against the node's real fee gate. Two fee modes
exist depending on the wallet's NIGHT registration state:

- **Generationless DUST** — when the wallet has *unregistered* NIGHT inputs, a dust
  registration is derived from them on the fly.
- **DUST spend proofs** — when all NIGHT is already registered, existing dust is spent with
  proofs.

Fee sizing is done by mock-proving the shielded/dust fragments offline (through the crypto
provider's `build_preimage_dust_spends`) so the fee is right before the real proof is
built. The best-Dust NIGHT coin is reserved for the fee registration, and leftover NIGHT is
rotated through a fallible offer so change returns cleanly.

## The effect model (what the policy seam gates on)

`ConnectorPlan::segment_effects` computes the transaction's **wallet-relative net
movement**, grouped by the transaction segment each piece executes in — `0` guaranteed
(applied unconditionally once the tx lands), non-zero fallible (may revert on its own).
Within a segment it is one `TransactionEffect` per value domain that nets non-zero, keyed
by the wallet's own address for that domain. How it is derived depends on the method:

- **`balanceUnsealed` / `balanceSealed` / `makeTransfer`** → *plan-derived*, from an inert
  `BalancedPlan`: the wallet's inputs netted against its own change and outputs. This
  **includes the DUST fee** the transfer burns, so a `sum(|diff|)` cap sees the whole
  movement. For `makeTransfer` the plan is sized on demand at the seam — the outputs are
  **mock-proven** (proofs are fixed-size, so the fee is exact) and the balancing is planned
  against the wallet's synced UTXOs, so **no real proving happens before the gate**. It does
  mean the seam **syncs the wallet and selects inputs** for a `makeTransfer`; a transfer the
  wallet cannot fund fails at planning, before the gate ever runs.
- **`makeIntent`** → *request-derived*, from the declared inputs (outflow) and self-outputs
  (inflow). A maker offer is deliberately imbalanced and **pays no fee** (the taker does), so
  the request already is the complete movement — there is nothing to plan.
- **`balanceSealedMerge`** (a fully-sealed maker completed by merging) → the taker's own half,
  request-derived like `makeIntent`, **plus the DUST fee the merge burns** (when `payFees` on a
  live-DUST chain). The fee covers the whole merged tx and the maker never pays, so it is sized
  against a **mock-proven taker complement** — fixed-size proofs give the exact fee with no real
  proving — and folded in as a dust outflow, so a `sum(|diff|)` cap sees the burn.

Shielded value a dapp routes back to the wallet is netted in as well: the base offers'
outputs are trial-decrypted with the shielded viewing key and each recognized receipt is
keyed by its own offer's segment. Without it the list would only carry the wallet's own
balancing contribution, over-stating outflow — a conservative cap bound rather than the
wallet's true net. Recognizing a receipt needs no spend key.

There is deliberately **no flat, segment-summed view**. Summing the segments discards the
guaranteed-versus-fallible distinction, which is the whole point of what the seam hands a
policy: a fallible inflow must never be allowed to offset a guaranteed outflow. See
[policy-create.md](./policy-create.md) for how a policy is expected to read this, and for
the sibling `chain_extra.contracts` list that answers *who* the transaction talks to.

So a `makeTransfer` of `V` NIGHT to someone else nets to `-V` in NIGHT plus the DUST fee it
burns — the NIGHT matching the recipient's on-chain credit `+V` (change returns to self).
Verified against a real broadcast: a 1,000,000-NIGHT transfer credited the recipient exactly
1,000,000 — see `e2e/results-2026-07-16.md`, "effects-vs-actual".

## The second policy pass in detail (Midnight 3)

`enforce_effect_policies` (`ows-lib/src/key_ops.rs`) is the gate `prepare_signable_tx`
runs at the plan→authorize seam. It fills the plan's per-segment movement into the
transaction context under `chain_extra` — leaving the flat `effects` field empty, since
the wallet can only account for its **own** movement, not the transaction's full effects —
and calls `evaluate_executable_policies`: **only the executable policies**, not the
declarative rules (those already gated the request shape in the first pass). A denial
returns a `PolicyDenied` error, so the key is never used to prove anything.

This is what lets a policy express a rule like *"cap the summed movement at 1,000,000"* —
a rule that is impossible to enforce at the first pass, because the first pass sees empty
effects; the real movement is only known after planning. See [policy-create.md](./policy-create.md).

## How this differs from other chains

| | Other chains | Midnight |
|---|---|---|
| `--tx` input | hex unsigned tx bytes | **JSON** DApp Connector request |
| What signing produces | a signature | a fully **sealed** transaction (`SignResult.transaction`) |
| Who balances / pays fees | the caller | the **wallet** (fees in dust) |
| Proof | none | zero-knowledge proofs built at authorize time |
| Policy passes | one (request shape) | **two** (shape, then effects) |

## Validation

Connector methods — cases **B1–B4** (`e2e/dapp-connector-siblings.md`, re-run live in
`e2e/results-2026-07-16.md` Suite B). These need a local prover, a funded wallet, and the
indexer, so they run by hand on preview:

| Case | Method | Result |
|------|--------|--------|
| B1 / B1n / B1s | `makeTransfer` unshielded self / non-self / shielded custom token | ✅ broadcast (3 on-chain txhashes) |
| B2 | `makeIntent` imbalanced maker, sealed via `sign tx` | ✅ |
| B3a | `balanceSealed` with a fully-sealed maker | ✅ merged (taker complement + merged dust fee) |
| B3b | `balanceSealed` with a proven (`proof,embedded-fr`) maker | ✅ balanced + sealed |
| B4a | `balanceUnsealed` with `proof,embedded-fr` | ✅ balanced + sealed |
| B4b | `balanceUnsealed` with `proof-preimage` | ✅ rejects (out-of-spec error) |

Second policy pass — cases **C1–C2** (`e2e/policy-second-pass.md`, re-run in
`e2e/results-2026-07-16.md` Suite C):

| Case | Case | Result |
|------|------|--------|
| C1 | Over-cap (5,000,000 > 1,000,000) → **denied at the second pass**, no prover/network | ✅ `policy denied: summed movement 5000000 (cap 1000000)` |
| C2 | Under-cap (500,000) → **passes the gate**, fails later in authorize | ✅ (an authorize-stage error, *not* "policy denied") |

The effect-recording policy captured the two-pass behavior directly: pass 1 sees `[]`
(empty effects), pass 2 sees the key-derived `[{diff:[["00…00", -value]]}]`, with the
pass-2 magnitude equal to the declared transfer value exactly.
</content>
