# `ows policy create` — effect-aware policies for Midnight

**Milestone:** Midnight 3 (PR #18) — this is where policies gain access to a Midnight
transaction's *effects*.
**Purpose:** register a policy (from a JSON file) that a minted API key can enforce.

```sh
ows policy create --file /tmp/policy.json
```

`policy create` itself is generic — it stores a `Policy` JSON. What Midnight 3 added is a
*reason* to write an **executable** policy that reads a transaction's wallet-relative
effects, because that is the only kind of policy the connector's second pass consults.

## Two kinds of policy, two passes

A Midnight `sign tx` on the agent path is gated **twice** (see [sign-tx.md](./sign-tx.md)):

1. **First pass — declarative rules**, over the request's *shape*. Rules like
   `AllowedChains` fire here. At this point the transaction has not been planned, so there
   is no movement to see.
2. **Second pass — executable policies**, over the transaction's *effects*. After the
   wallet plans the balancing, the plan's key-derived, wallet-relative effects are filled
   in **per transaction segment** and **only the executable programs** are re-evaluated
   (`evaluate_executable_policies`).

The Midnight effects are handed to the program under **`transaction.chain_extra`**, not the
generic `transaction.effects` field. That field would imply a full account of *all* a
transaction's effects; the wallet can only account for its **own** movement, per segment, so
it leaves `effects` empty and populates `chain_extra` instead.

So a policy that needs to reason about *how much value moves* must be **executable** — a
program that reads `transaction.chain_extra.segment_effects` from the policy context. A
purely declarative rule can never see the movement, because the movement is unknown until
after planning.

> **⚠ Deploy footgun — declarative-only keys don't cap movement.** The second pass runs
> **only** executable policies (declarative rules are settled in the first pass). So a key
> whose policies carry *only* declarative rules (`AllowedChains`, expiry, …) passes the
> second pass **unconditionally** — it moves unlimited value at the seam. Shape rules gate
> *which* transactions may be signed; **only an executable effect policy caps how much they
> move.** Don't ship an agent key with shape rules only and assume movement is bounded.

## Anatomy of an effect-aware executable policy

The policy JSON points `executable` at a program (any language) that reads the policy
context on stdin and prints an `{allow, reason}` verdict. The effects are under
`transaction.chain_extra.segment_effects`, one entry **per transaction segment** —
`{segment, effects:[{address, diff:[[token, delta], …]}]}`, each domain effect keyed by the
wallet's own address. `segment == 0` is the guaranteed section (always executed); anything
non-zero is a fallible section (executed in segment order, allowed to fail). A cap that treats
all movement the same sums across every segment; one that only bounds what *will* execute can
restrict itself to segment 0:

```python
#!/usr/bin/env python3
import sys, json
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
segs = extra.get("segment_effects", [])
total = sum(abs(d) for s in segs for e in s.get("effects", []) for _, d in e.get("diff", []))
print(json.dumps({"allow": total <= 1_000_000,
                  "reason": f"summed movement {total} (cap 1000000)"}))
```

> **⚠ A fallible segment id is an identifier, not a sequence number.** It is whatever `u16`
> the transaction's author picked for that intent — a real preprod transaction carries intents
> at segments 2260 and 15441, not 1 and 2. Never assume small or contiguous ids: test
> guaranteed-versus-fallible as `segment == 0` versus `segment != 0`.

Registered as a policy that `deny`s on failure:

```json
{ "id": "mn3-move-cap", "name": "Midnight movement cap", "version": 1,
  "created_at": "2026-07-15T00:00:00Z", "rules": [],
  "executable": "/tmp/cap.py", "action": "deny" }
```

Then minted into a key (`ows key create … --policy mn3-move-cap`, see
[key-create.md](./key-create.md)). When the agent runs `sign tx`, the second pass hands
this program the real effects and it caps the movement — a cap that fires **before** any
proving, so a denied transaction costs no prover work.

## Who the transaction talks to — `chain_extra.contracts`

`segment_effects` answers *how much the wallet moves*, and deliberately nothing else: no
counterparty, no provenance. The counterparty lives in its own sibling key,
**`transaction.chain_extra.contracts`** — one entry per contract action the transaction
performs, so a policy can gate on *who* as well as *how much*:

```json
{ "segment": 0,
  "kind": "call",
  "address": "9f3c…",
  "entry_point": "swap",
  "sent_to":       [["0000…", 1000]],
  "received_from": [["a71b…", 25]] }
```

- **`segment`** — the segment this action executes in, same convention as the effects: `0`
  guaranteed, non-zero fallible. A call declaring both a guaranteed and a fallible transcript
  appears **twice**, once per transcript, each at its own segment — so a record is read on
  its own rather than by where it sits in the list.
- **`kind`** — `call`, `deploy`, or `maintain`. Only a `call` names an `entry_point`; a
  deploy or a maintenance update declares no value movement, so its amounts are empty.
- **`sent_to` / `received_from`** — per token, the value the contract's transcript declares
  it takes in and pays out, named from the wallet's side.

Only the `balance*` methods can carry contract actions — they complete a transaction someone
else authored. `makeTransfer` and `makeIntent` build the wallet's own transfer from the
request alone, so their `contracts` is always empty.

> **⚠ The amounts are contract-*declared*, not proven wallet movement.** They are what the
> transcript says the contract takes in and pays out, so they equal what *the wallet* sends
> and receives only when the wallet is that contract's sole counterparty in the segment — the
> normal shape for a wallet-authored connector transaction, but not a guarantee. For what the
> wallet actually moves, cap on `segment_effects`; use `contracts` to decide **whether to
> deal with this counterparty at all** (an address allow-list, an entry-point allow-list),
> not as a second opinion on the amounts.

```python
#!/usr/bin/env python3
import sys, json
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
called = {c["address"] for c in extra.get("contracts", []) if c["kind"] == "call"}
unknown = called - {"9f3c…"}
print(json.dumps({"allow": not unknown,
                  "reason": f"unapproved contracts: {sorted(unknown)}"}))
```

## Why the design consumes an executable policy rather than a built-in rule

An earlier iteration added a built-in `MovementLimits` rule to the core policy set. That
was **dropped**: baking a movement cap into the engine forces every consumer to accept one
fixed notion of "movement", and Midnight effects are richer than a single scalar
(per-domain, per-token, signed). Leaving the consumer as an **executable** policy keeps the
engine agnostic — a deployment expresses whatever cap, per-token limit, or allow-list it
wants as a program, and the engine's only job is to supply the effects and honor the
verdict.

## How this differs from other chains

Every chain can attach declarative rules and executable policies. The Midnight-specific
part is the **second pass**: only Midnight derives wallet-relative effects *after* planning
and re-runs the executable policies over them. On other chains, a transaction's effect is
knowable at the first pass, so there is nothing to re-evaluate.

## Validation

- **Cases C1–C2** (`e2e/policy-second-pass.md`, `e2e/results-2026-07-16.md` Suite C): the
  cap program above denies a 5,000,000 movement at the second pass
  (`policy denied: summed movement 5000000 (cap 1000000)`) and allows a 500,000 movement
  (which then fails later in authorize — proving the gate let it through).
- **Unit:** `effect_policy_pass_gates_via_executable_policy` (`ows-lib/src/key_ops.rs`)
  drives `enforce_effect_policies` over a constructed `chain_extra` the way the executable
  programs consume `transaction.chain_extra.segment_effects`; `plan_segment_effects` cases in
  `ows-midnight/src/balance_tx.rs` cover the per-segment effect derivation, and
  `contract_interactions` cases in `ows-midnight/src/contracts.rs` cover the per-segment
  `contracts` derivation.
- **Real chain bytes:** `a_real_preprod_contract_call_is_read_from_the_chain_bytes`
  (`ows-midnight/src/contracts.rs`) extracts `contracts` from a settled preprod
  `addUnshieldedLiquidity` call and cross-checks the address and entry point against what the
  indexer independently reports for that transaction.
</content>
