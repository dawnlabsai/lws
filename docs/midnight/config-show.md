# `ows config show` — Midnight endpoints

**Milestones:** Midnight 1 (indexer endpoints for balances) and Midnight 2 (node endpoints
for broadcast).
**Purpose:** show the vault path and the configured RPC endpoints, including Midnight's.

```sh
ows config show
# …
# RPC endpoints:
#   midnight:mainnet         https://indexer.mainnet.midnight.network/api/v4/graphql  (default)
#   midnight:mainnet:node    https://rpc.mainnet.midnight.network/                    (default)
#   midnight:preview         https://indexer.preview.midnight.network/api/v4/graphql  (default)
#   midnight:preview:node    https://rpc.preview.midnight.network/                    (default)
#   midnight:preprod         https://indexer.preprod.midnight.network/api/v4/graphql  (default)
#   midnight:preprod:node    https://rpc.preprod.midnight.network/                    (default)
```

`config show` is generic, but Midnight is the one chain family that registers **two
endpoints per network**, and understanding why is central to how Midnight commands reach
the network.

## Two endpoints per network: indexer vs node

Midnight splits its read and write paths across different services:

- **`midnight:<net>` → the GraphQL indexer.** Used by [`fund balance`](./fund-balance.md)
  to read unshielded UTXOs, replay the shielded (`zswapLedgerEvents`) and dust ledgers, and
  read the current block height for the snapshot fast-path. `resolve_indexer_url` looks up
  this key.
- **`midnight:<net>:node` → the Substrate node.** Used by
  [`sign send-tx`](./sign-send-tx.md) to broadcast a sealed transaction
  (`Midnight::send_mn_transaction`). `resolve_midnight_node_rpc_url` looks up the
  `{chain_id}:node` key.

The two are resolved by **separate** functions on purpose. Both are exact lookups on their
key — `resolve_indexer_url` on `midnight:<net>`, `resolve_midnight_node_rpc_url` on
`midnight:<net>:node` — and node resolution deliberately has **no namespace fallback**: a
missing `:node` entry errors with a clear message rather than silently sending a broadcast
to the indexer URL. An explicit `--rpc-url` overrides the node lookup. Each resolver's
error names the exact config key to set, so a missing endpoint is self-explaining.

## Overriding endpoints

`config show` annotates each endpoint `(default)` or `(custom)`. A custom
`~/.ows/config.json` can point any of these keys at a private indexer or node (e.g. for a
feature testnet whose reference isn't a shipped default). Because a Midnight network is
identified by its **verbatim CAIP-2 reference**, an ad-hoc `midnight:feature-x` network
addresses and signs correctly out of the box — you only need to add `midnight:feature-x`
and `midnight:feature-x:node` entries so its indexer and node can be reached.

## How this differs from other chains

Other chain families register one RPC endpoint per network. Midnight registers two — a
read endpoint (indexer) and a write endpoint (node) — reflecting its split read/write
architecture. The commands resolve them through different code paths so the two are never
confused.

## Validation

Endpoint resolution is covered by unit tests in `ows-core/src/config.rs`
(`rpc_url("midnight:preview")` → the indexer URL; `rpc_url("midnight:preview:node")` → the
node URL). The end-to-end suites exercise both live: the indexer via `fund balance`
(cases M1–M9) and the node via `sign send-tx` broadcasts (Suite B txhashes) in
`e2e/results-2026-07-16.md`.
</content>
