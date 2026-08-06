#!/usr/bin/env bash
#
# Interactive smoke test for `ows fund balance` on Midnight (the midnight-1 balance work).
#
# Builds `ows` from THIS checkout first (so it works right after `git checkout midnight-1` —
# it never looks for a prebuilt binary), then walks a wallet through every balance path that is
# exercisable against a live indexer: unshielded + shielded + dust in OWNER-PASSPHRASE mode, the
# same via an API TOKEN, and the no-credential (unshielded-only) path. Each step prints the exact
# command and waits for Enter before running it.
#
# The wallet can be one already in your vault (give its name) or a fresh import from a mnemonic
# (give a new name + the words). It also serves as a live check of the runtime dust gating: on a
# network whose dust ledger is active (Preview/Preprod), the "Dust status" section must appear.
#
# Usage:  ./midnight-fund-balance.sh [network]   # network defaults to midnight:preprod
# Env:    CHAIN=midnight:preview   PROFILE=debug (faster build, slower sync)   FRESH=1 (no cache)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
CHAIN="${1:-${CHAIN:-midnight:preprod}}"

# Colours — bold-blue headings, cyan commands, dim asides, green/red pass-fail. Suppressed when
# stdout is not a terminal, so a piped/headless run stays free of escape codes.
if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'
  CYAN=$'\e[36m'; YELLOW=$'\e[33m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'
else
  BOLD=; DIM=; RESET=; CYAN=; YELLOW=; GREEN=; RED=; BLUE=
fi

say()  { printf '%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }

# Print a step header (▶ label) and the command about to run ($ cmd), then wait for Enter.
pause() {
  echo
  printf '%s▶ %s%s\n' "$BOLD$BLUE" "$1" "$RESET"
  printf '%s$ %s%s\n' "$CYAN" "$2" "$RESET"
  printf '%s   … press Enter to run%s' "$DIM" "$RESET"; read -r _
}

# pause(), then run the command and report its exit code.
run() {
  local label="$1" shown="$2"; shift 2
  pause "$label" "$shown"
  "$@"
  local rc=$?
  if [ "$rc" -eq 0 ]; then printf '%s✓ exit 0%s\n' "$GREEN" "$RESET"
  else printf '%s✗ exit %d%s\n' "$RED" "$rc" "$RESET"; fi
  return "$rc"
}

# Release by default — the shielded/dust replay is crypto-heavy, so a debug build is painfully
# slow to sync. PROFILE=debug builds faster but syncs slower.
PROFILE="${PROFILE:-release}"
if [ "$PROFILE" = release ]; then BIN_DIR=release; else BIN_DIR=debug; fi
OWS="$WORKSPACE/target/$BIN_DIR/ows"

say "ows Midnight fund-balance smoke test"
note "workspace: $WORKSPACE"
note "profile:   $PROFILE"
note "network:   $CHAIN"

# ── 1. Build ows from this checkout (first run may take a while) ─────────────────────────
if [ "$PROFILE" = release ]; then
  run "build ows (release) from this checkout" \
    "(cd $WORKSPACE && cargo build --release -p ows-cli)" \
    cargo build --release -p ows-cli --manifest-path "$WORKSPACE/Cargo.toml"
else
  run "build ows (debug) from this checkout" \
    "(cd $WORKSPACE && cargo build -p ows-cli)" \
    cargo build -p ows-cli --manifest-path "$WORKSPACE/Cargo.toml"
fi
[ -x "$OWS" ] || { printf '%s✗ build did not produce %s%s\n' "$RED" "$OWS" "$RESET"; exit 1; }

# ── Collect inputs ──────────────────────────────────────────────────────────────────────
echo
say "Wallets currently in your vault:"
NAMES="$("$OWS" wallet list 2>/dev/null | sed -n 's/^[[:space:]]*Name:[[:space:]]*//p')"
if [ -n "$NAMES" ]; then
  printf '%s\n' "$NAMES" | sed 's/^/  • /'
else
  note "(none yet — enter a new name to import one)"
fi
echo
read -rp "Wallet name (existing above, or a NEW name to import): " WALLET
[ -n "$WALLET" ] || { printf '%s✗ wallet name required%s\n' "$RED" "$RESET"; exit 1; }

# Reuse the wallet if it already exists; otherwise import it from a mnemonic.
if printf '%s\n' "$NAMES" | grep -Fxq "$WALLET"; then
  WALLET_EXISTS=1
  note "found existing wallet '$WALLET' — reusing it (no import)"
  # An existing wallet may carry a real owner passphrase — ask for it (Enter for empty).
  read -rsp "Owner passphrase [Enter for empty]: " PASS; echo
else
  WALLET_EXISTS=0
  note "no wallet '$WALLET' yet — will import it from a mnemonic"
  read -rsp "Mnemonic (hidden — paste the 12/24 words): " MNEMONIC; echo
  [ -n "$MNEMONIC" ] || { printf '%s✗ mnemonic required to import a new wallet%s\n' "$RED" "$RESET"; exit 1; }
  # 'ows wallet import' always writes an EMPTY-passphrase envelope, so owner-mode balance below
  # must decrypt with an empty passphrase. Force it rather than prompt for one that would only
  # make step 6 fail.
  PASS=""
  note "imported wallets have an empty owner passphrase — owner mode will use OWS_PASSPHRASE=\"\""
fi

KEYNAME="${WALLET}-smoke-key"

# FRESH=1 forces a full indexer re-sync (bypasses the on-disk snapshot cache).
[ "${FRESH:-0}" = "1" ] && export OWS_MIDNIGHT_SYNC_CACHE=0

# ── 2. Sanity: config (vault path + indexer endpoints) ──────────────────────────────────
run "config: vault path + indexer endpoints" "ows config show" "$OWS" config show

# ── 3. Import the wallet (only when it doesn't already exist) ────────────────────────────
if [ "$WALLET_EXISTS" -eq 0 ]; then
  run "import wallet '$WALLET' from the mnemonic" \
    "OWS_MNEMONIC=<hidden> ows wallet import --name $WALLET --mnemonic" \
    env OWS_MNEMONIC="$MNEMONIC" "$OWS" wallet import --name "$WALLET" --mnemonic
fi

# ── 4. Confirm it's in the vault ────────────────────────────────────────────────────────
run "list wallets (confirm '$WALLET' + its Midnight address)" "ows wallet list" "$OWS" wallet list

# ── 5. Derive the Midnight address from the mnemonic (new imports only) ──────────────────
if [ "$WALLET_EXISTS" -eq 0 ]; then
  run "derive the Midnight address from the mnemonic" \
    "OWS_MNEMONIC=<hidden> ows mnemonic derive --chain $CHAIN" \
    env OWS_MNEMONIC="$MNEMONIC" "$OWS" mnemonic derive --chain "$CHAIN"
fi

# ── 6. OWNER MODE: full balance (unshielded + shielded + dust) via the owner passphrase ──
run "OWNER-mode balance on $CHAIN (unshielded + shielded + dust)" \
  "OWS_PASSPHRASE=<hidden> ows fund balance --wallet $WALLET --chain $CHAIN" \
  env OWS_PASSPHRASE="$PASS" "$OWS" fund balance --wallet "$WALLET" --chain "$CHAIN"

# ── 7. Mint an API token (owner passphrase decrypts the wallet; token re-encrypts it) ────
pause "mint an API token for $WALLET (owner passphrase → scoped token)" \
      "OWS_PASSPHRASE=<hidden> ows key create --name $KEYNAME --wallet $WALLET"
KEY_OUT="$(OWS_PASSPHRASE="$PASS" "$OWS" key create --name "$KEYNAME" --wallet "$WALLET" 2>&1 | tee /dev/tty)"
TOKEN="$(printf '%s\n' "$KEY_OUT" | grep -oE 'ows_key_[A-Za-z0-9_.-]+' | head -1)"

# ── 8. TOKEN MODE: same balance, authenticated by the API token ─────────────────────────
if [ -n "$TOKEN" ]; then
  run "TOKEN-mode balance on $CHAIN (same balance, api-token auth)" \
    "OWS_PASSPHRASE=ows_key_<hidden> ows fund balance --wallet $WALLET --chain $CHAIN" \
    env OWS_PASSPHRASE="$TOKEN" "$OWS" fund balance --wallet "$WALLET" --chain "$CHAIN"
else
  printf '\n%s✗ no ows_key_ token captured — skipping token-mode balance%s\n' "$RED" "$RESET"
fi

# ── 9. NO-CREDENTIAL: unshielded only; shielded/dust degrade to (unavailable) ────────────
run "no-passphrase balance on $CHAIN (unshielded only; shielded/dust unavailable)" \
  "ows fund balance --wallet $WALLET --chain $CHAIN   ${DIM}# OWS_PASSPHRASE unset${CYAN}" \
  env -u OWS_PASSPHRASE "$OWS" fund balance --wallet "$WALLET" --chain "$CHAIN"

echo
say "Done. What to check:"
note "• owner + token modes printed matching unshielded/shielded balances;"
note "• the Dust status section appeared on $CHAIN — the runtime dust probe found a live ledger;"
note "• the no-passphrase run showed unshielded only, with the 'set OWS_PASSPHRASE' note."
echo
note "Revoke the smoke-test token when finished:  ${CYAN}ows key list${DIM}  then  ${CYAN}ows key revoke --id <id> --confirm"
