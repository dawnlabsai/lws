# `ows fund balance` — Midnight balances (unshielded, shielded, dust)

**Purpose:** read a Midnight wallet's balances from the indexer — the public unshielded
(Night) UTXOs, the private shielded (Zswap) coins, and the DUST fee ledger — for any
`midnight:<network>`.

```sh
OWS_PASSPHRASE="…" ows fund balance --wallet demo --chain midnight:preview
```

A `midnight:*` chain routes to the Midnight indexer instead of the MoonPay path the other
chains use. The unshielded balance needs only the stored address, so it's always shown; the
**shielded** and **dust** balances need the wallet's key material (from `OWS_PASSPHRASE`), so
without a passphrase those two sections are skipped and the command prints:

```
note: set OWS_PASSPHRASE to read Midnight shielded/dust balances
```

## What it prints

Amounts print to **stdout** as `{amount:>24} {token_type}`; status, addresses, and headers go
to **stderr**, so balances pipe out cleanly. A Preview run (values illustrative):

```
[ows-midnight] syncing balances from indexer (may take a while on first run)…
Addresses:
  Unshielded: mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
  Shielded:   mn_shield-addr_preview1…
  Dust:       mn_dust_preview1…

Unshielded balances:
     1000000000000000000 0100…            ← NIGHT wire token type (0x… hex)

Shielded balances:
      500000000000000000 0100…

Dust status (fees):
  NIGHT UTXOs: total=3 registered=2 unregistered=1
  Fee mode: generationless DUST (can be derived from unregistered NIGHT inputs)
  DUST seed: available
  DUST UTXOs: 4
  DUST balance: 12.34567890 (best-effort, wall-clock time)
```

The `Addresses` block re-encodes the stored address to the target network's HRP and adds
shielded/dust when a key is available (else `(unavailable)`). Token types are the indexer's wire
form (`0x…` hex; NIGHT is native). An empty section says so — `none — no unshielded tokens found
for <address> on <chain_id>` / `none — no unspent shielded coins found after full sync`.

## The credential

`OWS_PASSPHRASE` carries one of two things, resolved before syncing:

- **An owner envelope passphrase** — decrypts the packed `MNK1` role seeds and builds the
  `MidnightCryptoProvider` that derives the shielded/dust keys.
- **An api-key token** (prefix `ows_lib::key_store::TOKEN_PREFIX`) — routes through the same
  policy-enforcing channel as `sign-message` / `sign-transaction`, so a scoped token reads
  shielded/dust balances without the raw passphrase.
- **Neither** — unshielded only, with the `note:` above.

A **raw imported** private-key wallet has no packed Midnight roles (see [wallet.md](./wallet.md)),
so the provider build fails and the command degrades to unshielded-only rather than erroring.

## The three balance streams

### Unshielded (Night)

From the indexer's UTXO set for the address, summed per token type. Needs no key, fetched fresh
every call (it doesn't consume the snapshot fast-path), and drives the DUST-registration summary
below.

### Shielded (Zswap)

OWS subscribes to the full, unfiltered `zswapLedgerEvents` stream and replays it **locally**
through the crypto provider (`fold_shielded`) into a full spendable wallet state
(`ShieldedWalletState` / `ZswapLocalState`, keyed by nullifier); balances sum its coins. The
viewing key never leaves the process, and the number is **authoritative and spendable** — the
same synced wallet builds Zswap spends, and spend-with-change nets correctly. First sync is slow
(full replay); the snapshot cache (below) makes later runs fast.

### Dust (fees)

The dust-fee section shows only when the **network's dust ledger is live** — decided at run time,
not by network name. OWS probes the indexer's `dustLedgerEvents` tip cursor: a positive `maxId`
means an active ledger (shown); a missing, empty, or unreachable stream hides it. So dust appears
wherever the ledger is active — Preview/Preprod today, **mainnet automatically once its ledger
goes live**, no OWS change. The probe needs no wallet key (the tip is chain-global) and fails safe.

The ledger is replayed through the provider (`fold_dust`) and the balance is computed **at read
time** with the current wall clock, since DUST decays — hence `best-effort, wall-clock time`. The
NIGHT-registration summary (`total`/`registered`/`unregistered`) comes from the public UTXOs, so
it shows even without a key, and picks the fee mode: *generationless DUST* when unregistered NIGHT
inputs exist, *DUST spend proofs* otherwise.

## Concurrency

The three streams are independent subscriptions with independent caches, so they sync
concurrently (`tokio::join!`); wall-clock cost is the **slowest** stream, not the sum. A block-height read plus a per-stream live-tip probe gate the shielded/dust fast-paths and
the stale-snapshot check; the unshielded stream is always fresh.

## Snapshot cache

Each stream persists its **source state** (UTXO set / Zswap wallet state / dust ledger — never a
derived balance) to disk, so a warm run resumes instead of replaying from genesis:

```
{vault}/chains/midnight/cache/{unshielded|shielded|dust}/{wallet_id}/<hash>.json
```

The `<hash>` fingerprints `(indexer_url, chain_id, key)`, so a snapshot is never reused across a
different indexer, network, or key. On resume the shielded/dust streams **validate the snapshot
against the live stream tip** (`tip_verify`) by probing the indexer's current `maxId`:

- **discard** it and replay from genesis when the saved cursor sits *past* the live tip — the sign
  of an indexer reset that rewound the event ledger, where resuming would otherwise report the old
  chain's stale balances;
- **skip the WebSocket catch-up** and return the on-disk state when the cursor already sits *at* the
  live tip (an unchanged block height is also accepted as a cheaper at-tip signal);
- otherwise replay forward from the saved cursor to catch up.

`OWS_MIDNIGHT_SYNC_CACHE=0` disables disk caching.

## Configuration

The GraphQL indexer URL comes from `~/.ows/config.json` under `rpc["midnight:<network>"]` (the
WebSocket URL is derived from it); defaults ship for mainnet/preview/preprod. Sync timeouts
(HTTP 30s, WS connect 30s, WS idle 90s, stall 120s) are fixed, not environment-configurable.

## Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; unlocks shielded/dust. Unset → unshielded only. |
| `OWS_WALLET` | Default for `--wallet`. |
| `OWS_MIDNIGHT_SYNC_CACHE` | `0`/`false` → disable the disk snapshot cache (always re-sync). |

## The code path

- CLI: `commands/fund.rs::balance` detects a `midnight:*` chain, resolves the credential, builds
  the optional `MidnightCryptoProvider`, and calls `ows_midnight::print_fund_balance`.
- Display + concurrency: `ows-midnight/src/fund_balance.rs`.
- Streams (`wallet_sync/`): `unshielded.rs`, `shielded/` → `shielded/vk_hidden/` (VK-free
  replay), `dust/`.
- Cache + gating: `cache_io.rs`, each stream's `*sync_cache.rs`/`cache.rs`, `tip_verify.rs`.
- Env flags: `midnight_env.rs`.
