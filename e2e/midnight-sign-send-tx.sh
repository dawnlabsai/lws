#!/usr/bin/env bash
#
# Interactive smoke test for `ows sign send-tx` on Midnight — the balanceUnsealed connector method
# (the [Midnight 2] balance & submit unsealed transactions work).
#
# Builds `ows` from THIS checkout first (so it works right after `git checkout midnight-balance-unsealed`
# — it never looks for a prebuilt binary), then walks the balanceUnsealed path: it confirms the
# command is wired and rejects a malformed connector request with a PRECISE error (offline-safe, needs
# no funded wallet or prover), then — if you have one — balances, signs, proves, seals, and submits a
# real balanceUnsealed connector JSON against the live node.
#
# A live submission needs a funded wallet and a proven (proof,embedded-fr) balanceUnsealed input,
# which a DApp normally supplies. This checkout bundles one built on preprod
# (shielded-movement-cap/tx-proven-preprod.hex), so on preprod the live submit runs out of the box;
# point TX_JSON at your own connector-request file to override it. Proving runs in-process (circuit
# keys are fetched on first use) — no separate prover service. The offline reject check runs regardless.
#
# Usage:  ./midnight-sign-send-tx.sh [network]   # network defaults to midnight:preprod
# Env:    CHAIN=midnight:preview   PROFILE=debug (faster build, slower prove)   TX_JSON=<path-to-json>

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

# Release by default — proving is crypto-heavy, so a debug build is painfully slow. PROFILE=debug
# builds faster but proves slower.
PROFILE="${PROFILE:-release}"
if [ "$PROFILE" = release ]; then BIN_DIR=release; else BIN_DIR=debug; fi
OWS="$WORKSPACE/target/$BIN_DIR/ows"

say "ows Midnight sign send-tx smoke test (balanceUnsealed)"
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
  note "(none yet)"
fi
echo
read -rp "Wallet name (existing above): " WALLET
[ -n "$WALLET" ] || { printf '%s✗ wallet name required%s\n' "$RED" "$RESET"; exit 1; }
# 'ows wallet import/create' always writes an EMPTY-passphrase envelope, so owner-mode signing below
# decrypts with an empty passphrase — press Enter unless this wallet carries a real owner passphrase.
read -rsp "Owner passphrase [Enter for empty — 'ows wallet import/create' wallets have an EMPTY passphrase]: " PASS; echo

# ── 2. Command is wired (help) ──────────────────────────────────────────────────────────
run "sign send-tx --help (confirm the command is wired)" "ows sign send-tx --help" "$OWS" sign send-tx --help

# ── 3. Offline-safe: a malformed connector request is rejected with a PRECISE error ──────
# Not routed through run(): we pipe the output to grep for a rejection message, so we keep the
# ▶/command header via pause() but score it ourselves rather than on the exit code.
pause "offline reject check: a malformed connector JSON must fail with a precise error" \
      "OWS_PASSPHRASE=<hidden> ows sign send-tx --wallet $WALLET --chain $CHAIN --json --tx '{\"method\":\"balanceUnsealedTransaction\"}'"
if OWS_PASSPHRASE="$PASS" "$OWS" sign send-tx --wallet "$WALLET" --chain "$CHAIN" --json \
     --tx '{"method":"balanceUnsealedTransaction"}' 2>&1 | tee /dev/tty | grep -qiE 'error|invalid|unsupported|expected'; then
  printf '%s✓ rejected with a message (expected — the payload is intentionally malformed)%s\n' "$GREEN" "$RESET"
else
  printf '%s✗ no rejection message — the command may not be wired correctly%s\n' "$RED" "$RESET"
fi

# ── 4. Live run: seal (sign tx, no broadcast) then submit (sign send-tx) a balanceUnsealed request ─
# TX_JSON, if set, points at your own connector-request file. Otherwise, on preprod, fall back to the
# bundled proven maker (shielded-movement-cap/tx-proven-preprod.hex) so the live run works by default.
# Each step's pause() lets you Ctrl-C before it runs — the seal step never broadcasts, only send-tx does.
ARTIFACT="$SCRIPT_DIR/shielded-movement-cap/tx-proven-preprod.hex"
REQ=""; SRC=""; SHOWN=""
if [ -n "${TX_JSON:-}" ] && [ -f "$TX_JSON" ]; then
  REQ="$(cat "$TX_JSON")"; SRC="$TX_JSON"; SHOWN="@$TX_JSON"
elif [ -f "$ARTIFACT" ] && [ "${CHAIN##*:}" = preprod ]; then
  REQ="{\"tx\":\"$(tr -d ' \n' < "$ARTIFACT")\",\"options\":{\"payFees\":true}}"
  SRC="the bundled preprod maker"; SHOWN="@shielded-movement-cap/tx-proven-preprod.hex"
fi
if [ -n "$REQ" ]; then
  # Seal without broadcasting first (prints the sealed tx), then submit the same request.
  run "balanceUnsealed ($SRC) — seal only, no broadcast (prints the sealed tx)" \
    "OWS_PASSPHRASE=<hidden> ows sign tx --wallet $WALLET --chain $CHAIN --json --tx $SHOWN" \
    env OWS_PASSPHRASE="$PASS" "$OWS" sign tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$REQ"
  run "balanceUnsealed ($SRC) — SUBMIT to $CHAIN (broadcasts, prints the tx hash)" \
    "OWS_PASSPHRASE=<hidden> ows sign send-tx --wallet $WALLET --chain $CHAIN --json --tx $SHOWN" \
    env OWS_PASSPHRASE="$PASS" "$OWS" sign send-tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$REQ"
else
  echo
  note "No TX_JSON set and no preprod maker artifact for $CHAIN — skipping the live run."
  note "Set TX_JSON=<path> to a balanceUnsealed connector request (a funded wallet + a proof,embedded-fr tx)."
fi

echo
say "Done. What to check:"
note "• sign send-tx --help listed the command;"
note "• the malformed payload was rejected with a precise error (not a panic, not a generic 'unsupported');"
note "• the seal step (sign tx) printed the sealed tx; the submit step (sign send-tx) balanced, proved, sealed, and the node returned a tx hash."
