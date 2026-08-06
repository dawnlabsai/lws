#!/usr/bin/env bash
#
# Interactive smoke test for the commands milestone-0 makes functional on Midnight —
# address derivation and universal-wallet enrollment (NO balance/sync; that is midnight-1).
#
# Builds `ows` from THIS checkout first (so it works right after `git checkout midnight-0` —
# it never looks for a prebuilt binary), then walks every path the signer milestone unlocks:
#
#   • `ows mnemonic derive --chain midnight:<network>` — the unshielded Night address, checked
#     BYTE-FOR-BYTE against the pinned abandon-phrase vectors across mainnet / preview / preprod,
#     the `midnight` alias, an ad-hoc `feature-x`, a fully custom network, and --index 1;
#   • arbitrary / custom networks — any `midnight:<network>` is carried verbatim into the HRP;
#   • malformed-network REJECTION — uppercase, bad charset, leading/trailing hyphen, empty are
#     rejected (non-zero exit) rather than coerced to mainnet;
#   • `ows wallet import` / `list` / `info` — Midnight as a first-class account in a mnemonic
#     wallet, run against a THROWAWAY vault so your real ~/.ows is never touched.
#
# Every derivation is pure (no network, no vault), so the whole run is deterministic: it pins the
# BIP-39 test phrase `abandon abandon … about` and matches the same vectors the unit tests lock.
# Each step prints the exact command and waits for Enter before running it.
#
# Usage:  ./midnight-mnemonic-derive.sh
# Env:    PROFILE=debug (faster build)   CUSTOM_NET=my-testnet (override the custom-network demo)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
CUSTOM_NET="${CUSTOM_NET:-my-feature-testnet}"

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

PASS=0; FAIL=0

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

# pause(), run the command, show its (indented) output, and assert it CONTAINS $want — the exact
# address (or address prefix) the derivation must produce. Counts a pass/fail.
expect() {
  local label="$1" shown="$2" want="$3"; shift 3
  pause "$label" "$shown"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if printf '%s' "$out" | grep -qF -- "$want"; then
    printf '%s✓ matched %s%s\n' "$GREEN" "$want" "$RESET"; PASS=$((PASS+1))
  else
    printf '%s✗ expected output to contain %s (exit %d)%s\n' "$RED" "$want" "$rc" "$RESET"; FAIL=$((FAIL+1))
  fi
}

# pause(), run the command, show its (indented) output, and assert it was REJECTED (non-zero exit)
# — a malformed network reference must error, never be coerced to mainnet. Counts a pass/fail.
reject() {
  local label="$1" shown="$2"; shift 2
  pause "$label" "$shown"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if [ "$rc" -ne 0 ]; then
    printf '%s✓ rejected (exit %d)%s\n' "$GREEN" "$rc" "$RESET"; PASS=$((PASS+1))
  else
    printf '%s✗ expected a non-zero exit (rejection) but got exit 0%s\n' "$RED" "$RESET"; FAIL=$((FAIL+1))
  fi
}

# Release by default; PROFILE=debug builds faster. Derivation is light either way (no sync).
PROFILE="${PROFILE:-release}"
if [ "$PROFILE" = release ]; then BIN_DIR=release; else BIN_DIR=debug; fi
OWS="$WORKSPACE/target/$BIN_DIR/ows"

# The pinned BIP-39 test vector every output below is matched against — the same phrase the unit
# tests use, so these run verbatim and match byte-for-byte.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Expected unshielded (Night) addresses for index 0 of that wallet. Note the Bech32m *data* part
# (dwv2rta…g35q) is identical across networks — only the HRP and its checksum change, because it is
# one key and one hash tagged by the human-readable prefix.
DATA_PREFIX="dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q"
MAINNET_ADDR="mn_addr1${DATA_PREFIX}w3dyt6"
PREVIEW_ADDR="mn_addr_preview1${DATA_PREFIX}4y8xms"
PREPROD_ADDR="mn_addr_preprod1${DATA_PREFIX}49ekgd"
FEATUREX_ADDR="mn_addr_feature-x1${DATA_PREFIX}gl8r2t"
PREVIEW_IDX1_ADDR="mn_addr_preview14vxp6lccnpxc2zecz5a7fls8cc63kme540jwgajrakhmvc9xkxmqpmzrx8"
# For a fully custom network there is no pinned checksum, but the HRP tag + shared data part are —
# same key, network-tagged prefix — so assert everything up to (not including) the 6-char checksum.
CUSTOM_ADDR_PREFIX="mn_addr_${CUSTOM_NET}1${DATA_PREFIX}"

say "ows Midnight milestone-0 smoke test — address derivation & wallet enrollment"
note "workspace: $WORKSPACE"
note "profile:   $PROFILE"
note "vector:    abandon abandon … about  (index 0)"
note "custom:    midnight:$CUSTOM_NET"

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

# derive.rs reads the mnemonic from OWS_MNEMONIC and prints ONLY the address; export it once.
export OWS_MNEMONIC="$MNEMONIC"

# ── 2. Sanity: config (real vault path + endpoints; read-only) ────────────────────────────
run "config: vault path + endpoints (read-only sanity)" "ows config show" "$OWS" config show

# ── 3. Derive the unshielded Night address across the known networks (byte-for-byte) ──────
say ""
say "Address derivation — pinned vectors (mainnet / preview / preprod / alias / index)"

expect "derive midnight:mainnet" \
  "ows mnemonic derive --chain midnight:mainnet" \
  "$MAINNET_ADDR" \
  "$OWS" mnemonic derive --chain midnight:mainnet

expect "derive midnight (bare alias resolves to mainnet)" \
  "ows mnemonic derive --chain midnight" \
  "$MAINNET_ADDR" \
  "$OWS" mnemonic derive --chain midnight

expect "derive midnight:preview (HRP suffix _preview, same data part)" \
  "ows mnemonic derive --chain midnight:preview" \
  "$PREVIEW_ADDR" \
  "$OWS" mnemonic derive --chain midnight:preview

expect "derive midnight:preprod (HRP suffix _preprod, same data part)" \
  "ows mnemonic derive --chain midnight:preprod" \
  "$PREPROD_ADDR" \
  "$OWS" mnemonic derive --chain midnight:preprod

expect "derive midnight:feature-x (ad-hoc reference kept verbatim)" \
  "ows mnemonic derive --chain midnight:feature-x" \
  "$FEATUREX_ADDR" \
  "$OWS" mnemonic derive --chain midnight:feature-x

expect "derive midnight:preview --index 1 (a different address index)" \
  "ows mnemonic derive --chain midnight:preview --index 1" \
  "$PREVIEW_IDX1_ADDR" \
  "$OWS" mnemonic derive --chain midnight:preview --index 1

# ── 4. Arbitrary / custom networks — the milestone-0 headline ─────────────────────────────
say ""
say "Custom networks — any midnight:<network> is addressable (HRP-tagged, never coerced)"

expect "derive a fully custom network midnight:$CUSTOM_NET" \
  "ows mnemonic derive --chain midnight:$CUSTOM_NET" \
  "$CUSTOM_ADDR_PREFIX" \
  "$OWS" mnemonic derive --chain "midnight:$CUSTOM_NET"

# ── 5. Malformed network references are REJECTED, not coerced ─────────────────────────────
say ""
say "Malformed networks — rejected with a non-zero exit (never silently cast to mainnet)"

reject "reject uppercase midnight:Preview (charset)" \
  "ows mnemonic derive --chain midnight:Preview" \
  "$OWS" mnemonic derive --chain midnight:Preview

reject "reject underscore midnight:my_feature (charset)" \
  "ows mnemonic derive --chain midnight:my_feature" \
  "$OWS" mnemonic derive --chain midnight:my_feature

reject "reject leading hyphen midnight:-bad" \
  "ows mnemonic derive --chain midnight:-bad" \
  "$OWS" mnemonic derive --chain midnight:-bad

reject "reject trailing hyphen midnight:bad-" \
  "ows mnemonic derive --chain midnight:bad-" \
  "$OWS" mnemonic derive --chain midnight:bad-

reject "reject empty reference midnight:" \
  "ows mnemonic derive --chain midnight:" \
  "$OWS" mnemonic derive --chain "midnight:"

# ── 6. Enumerate all chains (no --chain) — Midnight is in the default account set ─────────
say ""
say "Universal wallet — Midnight is a first-class account (no --chain enumerates every chain)"

expect "derive with no --chain — the midnight:mainnet line appears" \
  "ows mnemonic derive   ${DIM}# enumerates ALL_CHAIN_TYPES${CYAN}" \
  "$MAINNET_ADDR" \
  "$OWS" mnemonic derive

# ── 7. Wallet enrollment against a THROWAWAY vault (your real ~/.ows is untouched) ────────
SMOKE_HOME="$(mktemp -d)"
trap 'rm -rf "$SMOKE_HOME"' EXIT
note "isolated vault: $SMOKE_HOME/.ows  (throwaway HOME → your real ~/.ows is never touched)"

run "config in the throwaway vault (confirms the isolated path)" \
  "HOME=$SMOKE_HOME ows config show" \
  env HOME="$SMOKE_HOME" "$OWS" config show

expect "import the abandon-phrase wallet — its midnight:mainnet account surfaces" \
  "OWS_MNEMONIC=<pinned> HOME=$SMOKE_HOME ows wallet import --name m0-smoke --mnemonic" \
  "$MAINNET_ADDR" \
  env HOME="$SMOKE_HOME" OWS_PASSPHRASE="" OWS_MNEMONIC="$MNEMONIC" "$OWS" wallet import --name m0-smoke --mnemonic

expect "list wallets — the Midnight account shows the mainnet Night address" \
  "HOME=$SMOKE_HOME ows wallet list" \
  "$MAINNET_ADDR" \
  env HOME="$SMOKE_HOME" "$OWS" wallet list

run "wallet info — Midnight listed among the supported chains" \
  "HOME=$SMOKE_HOME ows wallet info" \
  env HOME="$SMOKE_HOME" "$OWS" wallet info

# ── Summary ───────────────────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" -eq 0 ]; then
  say "All checks passed: $PASS/$((PASS+FAIL))."
else
  printf '%s✗ %d of %d checks FAILED.%s\n' "$RED" "$FAIL" "$((PASS+FAIL))" "$RESET"
fi
note "What this proved:"
note "• every network derives the same key, HRP-tagged (data part $DATA_PREFIX shared);"
note "• a custom midnight:$CUSTOM_NET network is addressable, not coerced to mainnet;"
note "• malformed references (uppercase / charset / hyphen / empty) are rejected;"
note "• Midnight is a first-class account in mnemonic wallets (import / list / info)."
echo
note "The throwaway vault at $SMOKE_HOME/.ows is removed on exit — nothing to clean up."
[ "$FAIL" -eq 0 ]
