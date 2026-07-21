#!/usr/bin/env bash
#
# Interactive coverage smoke test for the Midnight dapp-connector methods + message signing
# (the [Midnight 2.5] work). Every transaction is built from THIS wallet's live balances, so it
# works for any funded wallet — each flow self-skips when the wallet can't satisfy it, and each
# live flow asks whether to SUBMIT (broadcast) or just seal it (no broadcast).
#
# Flows (offline first, then a live menu):
#   1. sign message                           — unshielded-key signing (offline, no network)
#   2. makeTransfer, unshielded NIGHT -> self  — wallet funds, balances, proves, seals
#   3. makeTransfer, a shielded token -> self  — token + amount picked from your shielded balances
#   4. makeIntent -> sealed maker offer        — builds an imbalanced maker offer and seals it (no submit)
#   5a. balanceSealed <- your sealed offer     — the taker MERGES its complement (+ dust) and completes it
#   5b. balanceSealed <- proven maker artifact — taker balances + seals a proven-unsealed maker offer
#
# makeIntent is a maker EXPORT (an imbalanced, sealed offer handed to a taker) — it never self-submits.
# A taker completes a *sealed* maker (4's output) by MERGING in its complementary half plus a dust fee
# (5a), or balances a *proven-unsealed* maker (5b, from e2e/shielded-movement-cap/tx-proven.hex).
#
# Proving runs in-process (circuit keys fetched on first use) — no separate prover service.
#
# Usage:  ./midnight-connector-siblings.sh [network]   # network defaults to midnight:preprod
# Env:    CHAIN=midnight:preview   PROFILE=debug (faster build, slower prove)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
CHAIN="${1:-${CHAIN:-midnight:preprod}}"
# Flow 5b's maker artifact, picked for THIS network (tx-proven-<network>.hex, e.g. preprod), falling
# back to the default preview artifact — so 5b runs on whatever network has a matching proven maker.
ARTIFACT="$SCRIPT_DIR/shielded-movement-cap/tx-proven-${CHAIN##*:}.hex"
[ -f "$ARTIFACT" ] || ARTIFACT="$SCRIPT_DIR/shielded-movement-cap/tx-proven.hex"

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

# Yes/no prompt, default no.
ask() { local a; read -rp "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }

# Build + send a connector tx. Asks whether to submit: yes -> `sign send-tx` (broadcasts),
# no -> `sign tx` (builds, balances, proves, seals, prints hex — no broadcast). Usage: send_tx <label> <json>
send_tx() {
  local label="$1" json="$2" verb
  if ask "   Submit '$label' to the network (else just seal it)?"; then verb="send-tx"; else verb="tx"; fi
  pause "$label (sign $verb)" \
        "OWS_PASSPHRASE=<hidden> ows sign $verb --wallet $WALLET --chain $CHAIN --json --tx '$json'"
  env OWS_PASSPHRASE="$PASS" "$OWS" sign "$verb" --wallet "$WALLET" --chain "$CHAIN" --json --tx "$json"
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

say "ows Midnight dapp-connector coverage smoke test"
note "workspace: $WORKSPACE"
note "profile:   $PROFILE"
note "network:   $CHAIN"

# ── 1. Build ows from this checkout ──────────────────────────────────────────────────────
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

# ── 2. Message signing with the unshielded key (offline-safe: no network, no prover) ─────
run "sign a message with the unshielded key on $CHAIN" \
  "OWS_PASSPHRASE=<hidden> ows sign message --wallet $WALLET --chain $CHAIN --message 'hello midnight'" \
  env OWS_PASSPHRASE="$PASS" "$OWS" sign message --wallet "$WALLET" --chain "$CHAIN" --message "hello midnight"

# ── 3. Confirm the connector command is wired ────────────────────────────────────────────
run "sign send-tx --help (confirm the connector command is wired)" "ows sign send-tx --help" "$OWS" sign send-tx --help

# ── Read the wallet's live balances ONCE, then build every flow from them ─────────────────
echo
say "Reading ${WALLET}'s balances on $CHAIN (one sync; every flow below is built from this)…"
BAL="$(mktemp)"; trap 'rm -f "$BAL"' EXIT
env OWS_PASSPHRASE="$PASS" "$OWS" fund balance --wallet "$WALLET" --chain "$CHAIN" >"$BAL" 2>&1 || true

UNSH_ADDR="$(sed -n 's/^[[:space:]]*Unshielded:[[:space:]]*//p' "$BAL" | head -1)"
SH_ADDR="$(sed -n 's/^[[:space:]]*Shielded:[[:space:]]*//p' "$BAL" | head -1)"
# native NIGHT = the all-zero 32-byte token under "Unshielded balances:"
UNSH_NIGHT="$(awk '/^Unshielded balances:/{f=1;next} /^Shielded balances:/{f=0} f&&$2~/^0+$/&&length($2)==64{print $1; exit}' "$BAL")"
# each shielded holding as "value token-hex"
SH_LIST="$(awk '/^Shielded balances:/{f=1;next} /^Dust status/{f=0} f&&NF>=2{print $1" "$2}' "$BAL")"

printf '  unshielded addr:  %s%s%s\n' "$CYAN" "${UNSH_ADDR:-<none>}" "$RESET"
printf '  shielded addr:    %s%s%s\n' "$CYAN" "${SH_ADDR:-<none>}" "$RESET"
printf '  unshielded NIGHT: %s%s%s\n' "$CYAN" "${UNSH_NIGHT:-0}" "$RESET"
if [ -n "$SH_LIST" ]; then echo "  shielded tokens:"; printf '%s\n' "$SH_LIST" | nl -w4 -s'  ' | sed 's/^/    /'
else note "  shielded tokens: (none)"; fi

echo
say "Live flows — each asks before running, and (where it can submit) whether to broadcast or just seal."

# ── Flow 2: makeTransfer, unshielded NIGHT -> self ───────────────────────────────────────
if [ -n "$UNSH_NIGHT" ] && [ "$UNSH_NIGHT" != 0 ]; then
  if ask "Flow 2 — makeTransfer unshielded NIGHT to self (you hold $UNSH_NIGHT)?"; then
    read -rp "  Amount (NIGHT base units) [default 1000000]: " A; A="${A:-1000000}"
    J="{\"method\":\"makeTransfer\",\"desiredOutputs\":[{\"kind\":\"unshielded\",\"type\":\"night\",\"value\":\"$A\",\"recipient\":\"$UNSH_ADDR\"}]}"
    send_tx "makeTransfer unshielded NIGHT -> self" "$J"
  fi
else
  note "Flow 2 skipped: wallet holds no unshielded NIGHT."
fi

# ── Flow 3: makeTransfer, a shielded token -> self ───────────────────────────────────────
if [ -n "$SH_LIST" ] && [ -n "$SH_ADDR" ]; then
  if ask "Flow 3 — makeTransfer a shielded token to self?"; then
    echo "  Shielded tokens you hold:"; printf '%s\n' "$SH_LIST" | nl -w2 -s') ' | sed 's/^/    /'
    read -rp "  Pick a token by number [1]: " N; N="${N:-1}"
    LINE="$(printf '%s\n' "$SH_LIST" | sed -n "${N}p")"
    SVAL="${LINE%% *}"; STOK="${LINE##* }"
    if [ -n "$STOK" ] && [ "$STOK" != "$LINE" ]; then
      read -rp "  Amount (you hold $SVAL) [default 1]: " A; A="${A:-1}"
      J="{\"method\":\"makeTransfer\",\"desiredOutputs\":[{\"kind\":\"shielded\",\"type\":\"$STOK\",\"value\":\"$A\",\"recipient\":\"$SH_ADDR\"}]}"
      send_tx "makeTransfer shielded token -> self" "$J"
    else
      printf '  %sno token at line %s%s\n' "$RED" "$N" "$RESET"
    fi
  fi
else
  note "Flow 3 skipped: wallet holds no shielded tokens."
fi

# ── Flow 4: makeIntent -> sealed maker offer (give a held shielded token, want NIGHT) ─────
# A self-completable swap: the maker gives a shielded token it holds and wants NIGHT; in flow 5a the
# same wallet, as taker, receives that token back and supplies the NIGHT — so both legs are covered by
# this wallet's own holdings. (Giving NIGHT and wanting shielded NIGHT would need shielded NIGHT the
# wallet may not hold, which the taker couldn't then supply.)
MAKER_HEX=""
if [ -n "$SH_LIST" ] && [ -n "$UNSH_ADDR" ] && [ -n "$UNSH_NIGHT" ] && [ "$UNSH_NIGHT" != 0 ]; then
  if ask "Flow 4 — makeIntent: give a held shielded token, want NIGHT (build+seal a maker offer)?"; then
    echo "  Shielded tokens you hold:"; printf '%s\n' "$SH_LIST" | nl -w2 -s') ' | sed 's/^/    /'
    read -rp "  Token to give (number) [1]: " N; N="${N:-1}"
    LINE="$(printf '%s\n' "$SH_LIST" | sed -n "${N}p")"
    SVAL="${LINE%% *}"; STOK="${LINE##* }"
    if [ -z "$STOK" ] || [ "$STOK" = "$LINE" ]; then
      printf '  %sno token at line %s%s\n' "$RED" "$N" "$RESET"
    else
      read -rp "  Amount to give (you hold $SVAL) [1]: " GA; GA="${GA:-1}"
      read -rp "  NIGHT to want in return [500000]: " WA; WA="${WA:-500000}"
      J="{\"method\":\"makeIntent\",\"desiredInputs\":[{\"kind\":\"shielded\",\"type\":\"$STOK\",\"value\":\"$GA\"}],\"desiredOutputs\":[{\"kind\":\"unshielded\",\"type\":\"night\",\"value\":\"$WA\",\"recipient\":\"$UNSH_ADDR\"}]}"
      pause "makeIntent -> sealed maker offer (sign tx, no broadcast)" \
            "OWS_PASSPHRASE=<hidden> ows sign tx --wallet $WALLET --chain $CHAIN --json --tx '$J'"
      OUT="$(env OWS_PASSPHRASE="$PASS" "$OWS" sign tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$J" 2>/dev/null)"
      if [ $? -eq 0 ]; then
        MAKER_HEX="$(printf '%s' "$OUT" | tr -d ' \n' | sed -n 's/.*"transaction":"\([^"]*\)".*/\1/p')"
        MAKER_HEX="${MAKER_HEX#0x}"
        if [ -n "$MAKER_HEX" ]; then printf '%s✓ sealed maker offer built (%s hex chars)%s\n' "$GREEN" "${#MAKER_HEX}" "$RESET"
        else printf '%s✗ could not read the sealed offer from the JSON%s\n' "$RED" "$RESET"; fi
      else
        printf '%s✗ makeIntent failed%s\n' "$RED" "$RESET"
      fi
    fi
  fi
else
  note "Flow 4 skipped: needs a held shielded token + unshielded NIGHT + an unshielded address."
fi

# ── Flow 5a: balanceSealed <- your sealed maker offer (the taker MERGES its complement) ──
# The sealed maker from flow 4 can't be balanced in place, so the taker completes it by MERGING: it
# builds the per-token complement of the maker's imbalance, funds the merged tx's dust fee, seals, and
# `Transaction::merge`s the two. Same-wallet maker+taker here, so this is a self-completed swap.
if [ -n "$MAKER_HEX" ]; then
  if ask "Flow 5a — complete that sealed offer via balanceSealed (the taker merges its complement + dust)?"; then
    J="{\"method\":\"balanceSealedTransaction\",\"makerTx\":\"$MAKER_HEX\"}"
    send_tx "balanceSealed <- your sealed maker offer (merge)" "$J"
  fi
fi

# ── Flow 5b: balanceSealed <- a proven-unsealed maker artifact (the taker completes it) ──
# The artifact is a proven-unsealed (proof,embedded-fr) maker bound to one network; the CLI can't
# produce one (makeIntent seals), so it's checked in per-network and selected above. The guard below
# still skips if the selected artifact's network doesn't match this chain (e.g. an unshipped network).
if [ -f "$ARTIFACT" ]; then
  ART_NET="$(tr -d ' \n' < "$ARTIFACT" | xxd -r -p 2>/dev/null | strings 2>/dev/null | grep -ioE 'preview|preprod|mainnet|devnet' | head -1)"
  CHAIN_NET="${CHAIN##*:}"
  if [ -n "$ART_NET" ] && [ "$ART_NET" != "$CHAIN_NET" ]; then
    note "Flow 5b skipped: the maker artifact is for '$ART_NET' but this run is on '$CHAIN_NET' — re-run with CHAIN=midnight:$ART_NET to exercise it."
  elif ask "Flow 5b — balanceSealed a checked-in proven-unsealed maker (taker balances + seals)?"; then
    HEX="$(tr -d ' \n' < "$ARTIFACT")"; HEX="${HEX#0x}"
    J="{\"method\":\"balanceSealedTransaction\",\"makerTx\":\"$HEX\"}"
    send_tx "balanceSealed <- proven maker artifact" "$J"
  fi
else
  note "Flow 5b skipped: no maker artifact at $ARTIFACT."
fi

echo
say "Done. What to check:"
note "• sign message returned a signature; sign send-tx --help listed the connector command;"
note "• each makeTransfer you ran balanced, proved, sealed (and, if submitted, returned a tx hash);"
note "• makeIntent produced a sealed maker offer; balanceSealed completed it by MERGING the taker's"
note "  complement + dust (5a); the proven-unsealed taker path (5b) runs when the artifact matches the network."
echo
note "For the maker→taker background and MIP offers, see the runbook:  e2e/dapp-connector-siblings.md"
