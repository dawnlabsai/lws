#!/usr/bin/env bash
#
# Interactive smoke test for the Midnight effect-aware SECOND POLICY PASS (the midnight-3 work).
# Builds `ows` from THIS checkout first (so it works right after `git checkout`), then drives an
# executable movement-cap policy through `ows sign tx` on the agent path to show BOTH halves of the
# feature:
#
#   A. Policy ENFORCEMENT (network-free) — a `makeIntent` request whose declared movement is
#      OVER the cap is DENIED at the plan→authorize seam, BEFORE any proving (the key drops
#      unused); one UNDER the cap PASSES the gate. makeIntent effects are request-derived, so this
#      needs no indexer sync and no prover. It closes with the request options the wallet refuses
#      outright — payFees:true, segment 0, an expired ttl — none of which reach the gate at all.
#
#   B. Effect CALCULATION across tx input types — the same second pass computes the wallet-relative
#      effects for every connector method. A cap-0 "reporter" policy denies each and prints the
#      computed movement, so you can see the effect the seam gated on for:
#        • makeIntent            — request-derived (declared inputs/outputs)
#        • makeTransfer unshielded — plan-derived, INCLUDING the DUST fee (sized by mock-proving)
#        • makeTransfer shielded   — same, in the shielded domain
#        • balanceSealed merge     — the taker's complement PLUS the merged DUST fee
#      The plan-derived flows sync the wallet + mock-prove, so they need a funded wallet on a live
#      indexer; each self-skips when the wallet can't satisfy it. No REAL proving happens — every
#      flow is denied at the seam (cap 0), before authorize.
#
# Each step prints the exact command and waits for Enter before running it.
#
# Usage:  ./midnight-sign-and-policy.sh [network]   # network defaults to midnight:preprod
# Env:    CHAIN=midnight:preview   PROFILE=debug (faster build, slower sync/mock-prove)
#         RECIPIENT_WALLET=<name>  external wallet the makeTransfer steps send TO, so the effect shows a
#                                  real outflow rather than a self-transfer that nets to just the dust fee
#                                  (default: the first vault wallet that isn't the one under test).
#                                  RECIPIENT_PASS is that wallet's owner passphrase (default empty).
#         AUTO=1                   non-interactive: skip the Enter-pauses and answer the y/N prompts from
#                                  the environment. Feed WALLET, PASS (owner passphrase), AUTO_ASK=y|n
#                                  (default y, drives B2/B3), B2_AMOUNT, and AUTO_B4=y to also run B4
#                                  (which does REAL proving and needs a prover). For smoking the script.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
CHAIN="${1:-${CHAIN:-midnight:preprod}}"
AUTO="${AUTO:-}"   # non-empty → non-interactive (see the Env block above)

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
pass() { printf '%s✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
fail() { printf '%s✗ %s%s\n' "$RED" "$1" "$RESET"; }

# Print a step header (▶ label) and the command about to run ($ cmd), then wait for Enter (skipped under AUTO).
pause() {
  echo
  printf '%s▶ %s%s\n' "$BOLD$BLUE" "$1" "$RESET"
  printf '%s$ %s%s\n' "$CYAN" "$2" "$RESET"
  if [ -n "$AUTO" ]; then printf '%s   … auto-run%s\n' "$DIM" "$RESET"
  else printf '%s   … press Enter to run%s' "$DIM" "$RESET"; read -r _; fi
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

# Yes/no prompt, default no. Under AUTO it answers from AUTO_ASK (default yes) without reading a tty.
ask() {
  if [ -n "$AUTO" ]; then case "${AUTO_ASK:-y}" in y|Y) echo "$1 [auto: y]" >&2; return 0;; *) echo "$1 [auto: n]" >&2; return 1;; esac; fi
  local a; read -rp "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]
}
# Like ask, but AUTO defaults to NO unless AUTO_B4=y — B4 does REAL proving and needs a running prover.
ask_b4() { if [ -n "$AUTO" ]; then [ "${AUTO_B4:-}" = y ]; else ask "$1"; fi; }

# pause(), then run the command capturing combined output into LAST_OUT (the policy steps assert on
# WHAT was printed, not just the exit code), echoing it indented.
LAST_OUT=
run_capture() {
  local label="$1" shown="$2"; shift 2
  pause "$label" "$shown"
  LAST_OUT="$("$@" 2>&1)"; local rc=$?
  printf '%s\n' "$LAST_OUT" | sed 's/^/   /'
  return "$rc"
}

# Revoke EVERY api key whose exact name matches — interrupted runs can leave duplicates, and a stale key
# bound to a since-deleted policy program would deny spuriously. Used at start (fresh slate) and at end.
revoke_keys_named() {
  local name="$1" ids id
  ids="$("$OWS" key list 2>/dev/null | awk -v n="$name" '/^ID:/{id=$2} /^Name:/{ if ($2==n) print id }')"
  for id in $ids; do "$OWS" key revoke --id "$id" --confirm >/dev/null 2>&1 || true; done
}

# Release by default — the plan-derived flows sync + mock-prove, which a debug build runs painfully
# slowly. PROFILE=debug builds faster but syncs/mock-proves slower.
PROFILE="${PROFILE:-release}"
if [ "$PROFILE" = release ]; then BIN_DIR=release; else BIN_DIR=debug; fi
OWS="$WORKSPACE/target/$BIN_DIR/ows"

say "ows Midnight second-policy-pass smoke test"
note "workspace: $WORKSPACE"
note "profile:   $PROFILE"
note "network:   $CHAIN"

# ── 1. Build ows from this checkout (first run may take a while) ──────────────────────────
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

# ── Collect inputs ────────────────────────────────────────────────────────────────────────
echo
say "Wallets currently in your vault:"
NAMES="$("$OWS" wallet list 2>/dev/null | sed -n 's/^[[:space:]]*Name:[[:space:]]*//p')"
if [ -n "$NAMES" ]; then printf '%s\n' "$NAMES" | sed 's/^/  • /'; else note "(none yet — enter a new name to import one)"; fi
echo
if [ -z "${WALLET:-}" ]; then
  [ -z "$AUTO" ] || { printf '%s✗ AUTO mode needs WALLET set in the environment%s\n' "$RED" "$RESET"; exit 1; }
  read -rp "Wallet name (existing above, or a NEW name to import): " WALLET
fi
[ -n "$WALLET" ] || { printf '%s✗ wallet name required%s\n' "$RED" "$RESET"; exit 1; }

if printf '%s\n' "$NAMES" | grep -Fxq "$WALLET"; then
  note "found existing wallet '$WALLET' — reusing it (no import)"
else
  note "no wallet '$WALLET' yet — will import it from a mnemonic"
  read -rsp "Mnemonic (hidden — paste the 12/24 words): " MNEMONIC; echo
  [ -n "$MNEMONIC" ] || { printf '%s✗ mnemonic required to import a new wallet%s\n' "$RED" "$RESET"; exit 1; }
  run "import wallet '$WALLET' from the mnemonic" \
    "OWS_MNEMONIC=<hidden> ows wallet import --name $WALLET --mnemonic" \
    env OWS_MNEMONIC="$MNEMONIC" "$OWS" wallet import --name "$WALLET" --mnemonic
fi
# 'ows wallet import/create' writes an EMPTY-passphrase envelope — press Enter unless this wallet
# carries a real owner passphrase.
if [ -n "$AUTO" ]; then PASS="${PASS:-}"
else read -rsp "Owner passphrase [Enter for empty — 'ows wallet import/create' wallets have an EMPTY passphrase]: " PASS; echo; fi

# Temp workspace for the two cap programs + policy JSON; cleaned up on exit.
TMP="$(mktemp -d)"
CAP_PY="$TMP/cap.py"          # cap 1,000,000 — for the enforcement half
REPORT_PY="$TMP/report.py"    # cap 0 — denies everything, printing the computed movement
CAP_JSON="$TMP/cap.json"; REPORT_JSON="$TMP/report.json"
CAP_ID="mn3-move-cap-smoke"; REPORT_ID="mn3-effect-report-smoke"
CAP_KEY="${WALLET}-cap-key"; REPORT_KEY="${WALLET}-report-key"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# ── 2. Endpoints ──────────────────────────────────────────────────────────────────────────
run "config: indexer + node endpoints" "ows config show" "$OWS" config show

# ── 3. OWNER-mode message signing — BIP-340 Schnorr with the unshielded key ────────────────
run "OWNER-mode sign message on $CHAIN (signature = x-only pubkey ‖ sig)" \
  "OWS_PASSPHRASE=<hidden> ows sign message --chain $CHAIN --wallet $WALLET --message 'hello midnight' --json" \
  env OWS_PASSPHRASE="$PASS" "$OWS" sign message --chain "$CHAIN" --wallet "$WALLET" --message "hello midnight" --json

# ── 4. Register the two executable policies + mint a token bound to each ────────────────────
# The cap policy denies when the summed absolute wallet-relative movement exceeds 1,000,000. The
# connector's SECOND pass hands the program the real, key-derived per-segment effects under
# `transaction.chain_extra.segment_effects` (the generic `effects` field stays empty for Midnight), so
# this is a rule only enforceable after planning. `chain_extra.contracts` sits alongside it, carrying
# who the transaction talks to; every flow below is a plain token movement, so it reports an empty
# list — that exercises the extraction path, not its content. Seeing a populated list needs a real
# dapp transaction that calls a contract.
cat > "$CAP_PY" <<'PY'
#!/usr/bin/env python3
import sys, json
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
segs = extra.get("segment_effects", [])
total = sum(abs(d) for s in segs for e in s.get("effects", []) for _, d in e.get("diff", []))
print(json.dumps({"allow": total <= 1_000_000, "reason": f"summed movement {total} (cap 1000000)"}))
PY
# The reporter denies ANY non-zero movement (cap 0), so its reason always prints what the seam computed —
# an allow verdict would be silent. Used to read both chain_extra keys for each tx input type: the
# per-segment effects (what the wallet moves) and the sibling `contracts` list (who it talks to).
#
# It MUST allow when the effects are empty. The FIRST, keyless policy pass runs this same program with no
# `chain_extra` at all; an unconditional deny would fire there and abort before the second pass ever
# produces anything, which reads as "the seam computed nothing".
cat > "$REPORT_PY" <<'PY'
#!/usr/bin/env python3
import sys, json
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
segs = extra.get("segment_effects", [])
total = sum(abs(d) for s in segs for e in s.get("effects", []) for _, d in e.get("diff", []))
per = "; ".join(f"seg{s.get('segment')} {addr[:10]}…:{d}" for s in segs for e in s.get("effects", []) for addr in [e.get("address","")] for _, d in e.get("diff", []))
# Reported, never gated on: the allow-when-empty property above must depend on the effects alone.
cons = "; ".join(f"seg{c.get('segment')} {c.get('kind')} {c.get('address','')[:10]}…{'.' + c['entry_point'] if c.get('entry_point') else ''}" for c in extra.get("contracts", []))
print(json.dumps({"allow": total == 0, "reason": f"effect movement {total} [{per}] contracts[{cons}]"}))
PY
chmod +x "$CAP_PY" "$REPORT_PY"
cat > "$CAP_JSON" <<JSON
{ "id": "$CAP_ID", "name": "Midnight movement cap (smoke)", "version": 1,
  "created_at": "2026-07-22T00:00:00Z", "rules": [], "executable": "$CAP_PY", "action": "deny" }
JSON
cat > "$REPORT_JSON" <<JSON
{ "id": "$REPORT_ID", "name": "Midnight effect reporter (smoke)", "version": 1,
  "created_at": "2026-07-22T00:00:00Z", "rules": [], "executable": "$REPORT_PY", "action": "deny" }
JSON

# Start from a clean slate: an interrupted previous run can leave these keys/policies behind (the policy
# then points at a since-deleted temp program). `policy create` overwrites the program path, but stale
# keys would accumulate — revoke them first so each run mints exactly one token per policy.
note "clearing any leftovers from a previous run…"
revoke_keys_named "$CAP_KEY"; revoke_keys_named "$REPORT_KEY"
"$OWS" policy delete --id "$CAP_ID" --confirm >/dev/null 2>&1 || true
"$OWS" policy delete --id "$REPORT_ID" --confirm >/dev/null 2>&1 || true

run "register the cap policy (cap 1,000,000)"      "ows policy create --file $CAP_JSON"    "$OWS" policy create --file "$CAP_JSON"
run "register the reporter policy (cap 0)"         "ows policy create --file $REPORT_JSON" "$OWS" policy create --file "$REPORT_JSON"

mint_token() {  # mint_token <keyname> <policy-id> -> echoes ONLY the ows_key_ token on stdout
  local kn="$1" pid="$2" out
  # The banner and the key-create output must go to stderr, not stdout: this function is captured with
  # $(...), so anything on stdout other than the token ends up glued into $CAP_TOKEN. A polluted token
  # doesn't start with ows_key_, so `ows sign` silently takes the owner path (no policy pass) instead of
  # the agent path — the whole point of the test.
  pause "mint a scoped token for $WALLET bound to '$pid'" \
        "OWS_PASSPHRASE=<hidden> ows key create --name $kn --wallet $WALLET --policy $pid" >&2
  out="$(OWS_PASSPHRASE="$PASS" "$OWS" key create --name "$kn" --wallet "$WALLET" --policy "$pid" 2>&1)"
  printf '%s\n' "$out" >&2
  printf '%s\n' "$out" | grep -oE 'ows_key_[A-Za-z0-9_.-]+' | head -1
}
CAP_TOKEN="$(mint_token "$CAP_KEY" "$CAP_ID")"
REPORT_TOKEN="$(mint_token "$REPORT_KEY" "$REPORT_ID")"
[ -n "$CAP_TOKEN" ] && [ -n "$REPORT_TOKEN" ] || { printf '%s✗ could not capture both tokens — aborting%s\n' "$RED" "$RESET"; exit 1; }

# ── 5. TOKEN-mode message signing — the FIRST (shape) pass runs; a message has no effects ──
run "TOKEN-mode sign message (first policy pass; a message seals no tx, so no second pass)" \
  "OWS_PASSPHRASE=ows_key_<hidden> ows sign message --chain $CHAIN --wallet $WALLET --message 'hello agent' --json" \
  env OWS_PASSPHRASE="$CAP_TOKEN" "$OWS" sign message --chain "$CHAIN" --wallet "$WALLET" --message "hello agent" --json

# ═══ PART A — Policy ENFORCEMENT (network-free, via the cap-1,000,000 policy) ═══════════════
echo; say "Part A — policy enforcement over the cap (makeIntent effects are request-derived: no sync, no prover)"
OVER_TX='{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"5000000"}],"desiredOutputs":[],"options":{"intentId":1}}'
UNDER_TX='{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"500000"}],"desiredOutputs":[],"options":{"intentId":1}}'

run_capture "OVER the cap (makeIntent contributes 5,000,000 > 1,000,000) — must DENY at the second pass" \
  "OWS_PASSPHRASE=ows_key_<hidden> ows sign tx --chain $CHAIN --wallet $WALLET --json --tx '{makeIntent input 5000000}'" \
  env OWS_PASSPHRASE="$CAP_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$OVER_TX"
if printf '%s' "$LAST_OUT" | grep -qi 'policy denied'; then
  pass "denied at the second pass — the key dropped unused, nothing was proved"
  printf '%s' "$LAST_OUT" | grep -qi 'summed movement 5000000' \
    && pass "reason shows the REAL effect (5000000) — known only after planning, not at the first pass" \
    || fail "expected the reason to report the summed movement of 5000000"
else
  fail "expected a 'policy denied' from the second pass"
fi

run_capture "UNDER the cap (makeIntent contributes 500,000) — must PASS the gate, then fail later in authorize" \
  "OWS_PASSPHRASE=ows_key_<hidden> ows sign tx --chain $CHAIN --wallet $WALLET --json --tx '{makeIntent input 500000}'" \
  env OWS_PASSPHRASE="$CAP_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$UNDER_TX"
if printf '%s' "$LAST_OUT" | grep -qi 'policy denied'; then
  fail "was DENIED — the gate should ALLOW an under-cap movement"
else
  pass "passed the gate — the error is authorize-stage (build/prove), NOT a policy denial"
fi

# ── The makeIntent request options, refused while parsing — before any planning, sync or proving ──
echo; say "Part A (cont.) — the makeIntent options the wallet validates before it plans anything"
refuse_option() {  # refuse_option <label> <json> <needle>
  run_capture "$1 — must be refused at parse" \
    "OWS_PASSPHRASE=ows_key_<hidden> ows sign tx --chain $CHAIN --wallet $WALLET --json --tx '$2'" \
    env OWS_PASSPHRASE="$CAP_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$2"
  if printf '%s' "$LAST_OUT" | grep -qi "$3"; then
    pass "refused, and the error names $3"
  else
    fail "expected a refusal naming $3"
  fi
}

IN_700K='{"kind":"unshielded","type":"night","value":"700000"}'
refuse_option "payFees: true — a maker offer is fee-free; the taker funds the DUST on completion" \
  "{\"method\":\"makeIntent\",\"desiredInputs\":[$IN_700K],\"options\":{\"intentId\":1,\"payFees\":true}}" \
  'payFees'
refuse_option "intentId: 0 — segment 0 is the guaranteed section, where the ledger rejects an intent" \
  "{\"method\":\"makeIntent\",\"desiredInputs\":[$IN_700K],\"options\":{\"intentId\":0}}" \
  'intentId'
refuse_option "ttl in the past — the offer would be sealed already expired" \
  "{\"method\":\"makeIntent\",\"desiredInputs\":[$IN_700K],\"options\":{\"intentId\":1,\"ttl\":1}}" \
  'ttl'

# A wallet-drawn segment and a 60-second quote are both well formed, so this one must get past the
# options and be judged on its movement (500,000, under the cap) like any other request.
FRESH_TTL=$(( $(date +%s) + 60 ))
FRESH_TX="{\"method\":\"makeIntent\",\"desiredInputs\":[{\"kind\":\"unshielded\",\"type\":\"night\",\"value\":\"500000\"}],\"options\":{\"intentId\":\"random\",\"ttl\":$FRESH_TTL}}"
run_capture "intentId \"random\" + a 60-second ttl, under the cap — must reach the gate" \
  "OWS_PASSPHRASE=ows_key_<hidden> ows sign tx --chain $CHAIN --wallet $WALLET --json --tx '{makeIntent 500000, random segment, ttl now+60}'" \
  env OWS_PASSPHRASE="$CAP_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$FRESH_TX"
if printf '%s' "$LAST_OUT" | grep -qiE 'options\.ttl|options\.intentId|payFees'; then
  fail "the options were refused — a drawn segment and a fresh ttl are both valid"
else
  pass "options accepted — the request was planned and gated on its movement, not its shape"
fi

# ═══ PART B — Effect CALCULATION across tx input types (via the cap-0 reporter) ════════════
# Every flow below is DENIED at the seam by the reporter (cap 0), which prints the computed movement
# — so we read the effect the second pass gated on WITHOUT any real proving. report_effect drives one
# tx through the reporter token and echoes the movement it computed.
report_effect() {  # report_effect <label> <json>
  run_capture "$1 — reporter prints the computed effect (denied at cap 0, no proving)" \
    "OWS_PASSPHRASE=ows_key_<hidden> ows sign tx --chain $CHAIN --wallet $WALLET --json --tx '$2'" \
    env OWS_PASSPHRASE="$REPORT_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$2"
  local mv
  mv="$(printf '%s' "$LAST_OUT" | grep -oiE 'effect movement [0-9]+' | head -1)"
  if [ -n "$mv" ]; then pass "computed → $mv"; else fail "no computed effect printed (did the flow error before the gate?)"; fi
}

echo; say "Part B — effect calculation across tx input types (plan-derived flows sync + mock-prove; funded wallet needed)"

# B1. makeIntent — request-derived, network-free.
report_effect "makeIntent (request-derived: declared 700,000 NIGHT input)" \
  '{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"700000"}],"desiredOutputs":[],"options":{"intentId":1}}'

# Read the wallet's live balances ONCE; the plan-derived flows build from them.
echo; say "Reading ${WALLET}'s balances on $CHAIN (one sync; the plan-derived flows build from this)…"
BAL="$(mktemp)"; trap 'rm -rf "$TMP"; rm -f "$BAL"' EXIT
env OWS_PASSPHRASE="$PASS" "$OWS" fund balance --wallet "$WALLET" --chain "$CHAIN" >"$BAL" 2>&1 || true
UNSH_ADDR="$(sed -n 's/^[[:space:]]*Unshielded:[[:space:]]*//p' "$BAL" | head -1)"
SH_ADDR="$(sed -n 's/^[[:space:]]*Shielded:[[:space:]]*//p' "$BAL" | head -1)"
UNSH_NIGHT="$(awk '/^Unshielded balances:/{f=1;next} /^Shielded balances:/{f=0} f&&$2~/^0+$/&&length($2)==64{print $1; exit}' "$BAL")"
SH_LIST="$(awk '/^Shielded balances:/{f=1;next} /^Dust status/{f=0} f&&NF>=2{print $1" "$2}' "$BAL")"
printf '  unshielded NIGHT: %s%s%s   shielded tokens: %s%s%s\n' \
  "$CYAN" "${UNSH_NIGHT:-0}" "$RESET" "$CYAN" "$([ -n "$SH_LIST" ] && echo yes || echo none)" "$RESET"

# External recipient for the makeTransfer steps. Sending to SELF nets the value straight back and leaves
# only the DUST fee as the movement — so B2/B3 send to ANOTHER wallet instead, and the effect then shows
# the real outflow (value + dust). Derived lazily (one sync) from the first vault wallet that isn't the one
# under test, overridable via RECIPIENT_WALLET; falls back to self if the vault has only one wallet.
RECIP_UNSH=; RECIP_SH=; RECIP_DONE=
ensure_recipient() {
  [ -n "$RECIP_DONE" ] && return 0
  RECIP_DONE=1
  local rw rbal
  rw="${RECIPIENT_WALLET:-$(printf '%s\n' "$NAMES" | grep -Fxv "$WALLET" | head -1)}"
  if [ -z "$rw" ]; then
    note "no second wallet to use as an external recipient (set RECIPIENT_WALLET) — falling back to self."
    RECIP_UNSH="$UNSH_ADDR"; RECIP_SH="$SH_ADDR"; return 0
  fi
  note "deriving external recipient addresses from wallet '$rw' on $CHAIN (one sync)…"
  rbal="$(mktemp)"
  env OWS_PASSPHRASE="${RECIPIENT_PASS:-}" "$OWS" fund balance --wallet "$rw" --chain "$CHAIN" >"$rbal" 2>&1 || true
  RECIP_UNSH="$(sed -n 's/^[[:space:]]*Unshielded:[[:space:]]*//p' "$rbal" | head -1)"
  RECIP_SH="$(sed -n 's/^[[:space:]]*Shielded:[[:space:]]*//p' "$rbal" | head -1)"
  rm -f "$rbal"
  [ -n "$RECIP_UNSH" ] && note "  external unshielded recipient: $RECIP_UNSH"
  [ -n "$RECIP_SH" ]   && note "  external shielded recipient:   $RECIP_SH"
}

# B2. makeTransfer, unshielded NIGHT -> an EXTERNAL wallet — PLAN-derived: the effect is the value that
# LEAVES the wallet PLUS the DUST fee (a self-transfer would net the value back, leaving only the fee).
# This is the path that used to break before the unsealed mock-prove fix; here it must compute a value.
if [ -n "$UNSH_NIGHT" ] && [ "$UNSH_NIGHT" != 0 ]; then
  if ask "B2 — makeTransfer unshielded NIGHT to an EXTERNAL wallet (you hold $UNSH_NIGHT; plan-derived, value + dust)?"; then
    ensure_recipient
    if [ -n "$RECIP_UNSH" ]; then
      if [ -n "$AUTO" ]; then A="${B2_AMOUNT:-5}"
      else read -rp "  Amount (NIGHT base units, small so it funds) [5]: " A; A="${A:-5}"; fi
      report_effect "makeTransfer unshielded NIGHT $A -> external (plan-derived: value outflow + DUST fee)" \
        "{\"method\":\"makeTransfer\",\"desiredOutputs\":[{\"kind\":\"unshielded\",\"type\":\"night\",\"value\":\"$A\",\"recipient\":\"$RECIP_UNSH\"}]}"
    else
      note "B2 skipped: no external unshielded recipient available."
    fi
  fi
else
  note "B2 skipped: wallet holds no unshielded NIGHT (plan-derived makeTransfer needs funding)."
fi

# B3. makeTransfer, a shielded token -> an EXTERNAL wallet — PLAN-derived in the shielded domain: the
# effect is the shielded value that leaves plus the DUST fee.
if [ -n "$SH_LIST" ]; then
  if ask "B3 — makeTransfer a shielded token to an EXTERNAL wallet (plan-derived, shielded domain)?"; then
    ensure_recipient
    LINE="$(printf '%s\n' "$SH_LIST" | head -1)"; SVAL="${LINE%% *}"; STOK="${LINE##* }"
    if [ -z "$RECIP_SH" ]; then note "B3 skipped: no external shielded recipient available."
    elif [ -n "$STOK" ] && [ "$STOK" != "$LINE" ]; then
      report_effect "makeTransfer shielded token 1 -> external (you hold $SVAL of ${STOK:0:10}…; value outflow + DUST fee)" \
        "{\"method\":\"makeTransfer\",\"desiredOutputs\":[{\"kind\":\"shielded\",\"type\":\"$STOK\",\"value\":\"1\",\"recipient\":\"$RECIP_SH\"}]}"
    else note "B3 skipped: could not read a shielded token."; fi
  fi
else
  note "B3 skipped: wallet holds no shielded tokens."
fi

# B4. balanceSealed merge — build a sealed maker (give a held shielded token, want NIGHT), then read
# the taker's effect: its complement PLUS the merged DUST fee (the merge-dust work).
if [ -n "$SH_LIST" ] && [ -n "$UNSH_ADDR" ] && [ -n "$UNSH_NIGHT" ] && [ "$UNSH_NIGHT" != 0 ]; then
  if ask_b4 "B4 — build a sealed maker offer (owner mode, real proving) then read the merge effect?"; then
    LINE="$(printf '%s\n' "$SH_LIST" | head -1)"; STOK="${LINE##* }"
    MK='{"method":"makeIntent","desiredInputs":[{"kind":"shielded","type":"'"$STOK"'","value":"1"}],"desiredOutputs":[{"kind":"unshielded","type":"night","value":"500000","recipient":"'"$UNSH_ADDR"'"}]}'
    pause "makeIntent -> sealed maker offer (owner mode; sign tx, no broadcast)" \
          "OWS_PASSPHRASE=<hidden> ows sign tx --wallet $WALLET --chain $CHAIN --json --tx '<maker>'"
    MK_OUT="$(env OWS_PASSPHRASE="$PASS" "$OWS" sign tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$MK" 2>/dev/null)"
    MAKER_HEX="$(printf '%s' "$MK_OUT" | tr -d ' \n' | sed -n 's/.*"transaction":"\([^"]*\)".*/\1/p')"; MAKER_HEX="${MAKER_HEX#0x}"
    if [ -n "$MAKER_HEX" ]; then
      pass "sealed maker offer built (${#MAKER_HEX} hex chars)"
      report_effect "balanceSealed merge (taker complement + merged DUST fee)" \
        "{\"method\":\"balanceSealedTransaction\",\"makerTx\":\"$MAKER_HEX\"}"
    else
      fail "could not build a sealed maker offer — skipping the merge effect"
    fi
  fi
else
  note "B4 skipped: needs a held shielded token + unshielded NIGHT + an unshielded address."
fi

# ── 6. Cleanup the smoke-test keys + policies (revoke ALL matching keys, in case a run left dups) ──
for kn in "$CAP_KEY" "$REPORT_KEY"; do
  run "revoke smoke-test key(s) named $kn" "ows key revoke (every key named $kn)" revoke_keys_named "$kn"
done
run "delete the cap policy"      "ows policy delete --id $CAP_ID --confirm"    "$OWS" policy delete --id "$CAP_ID" --confirm
run "delete the reporter policy" "ows policy delete --id $REPORT_ID --confirm" "$OWS" policy delete --id "$REPORT_ID" --confirm

echo
say "Done. What to check:"
note "Part A (enforcement, network-free):"
note "  • OVER the cap (makeIntent) was DENIED at the second pass with 'summed movement 5000000 (cap 1000000)';"
note "  • UNDER the cap PASSED the gate (its error was authorize-stage, not a policy denial)."
note "Part B (effect calculation, reporter cap 0 — each denied at the seam, no real proving):"
note "  • makeIntent printed a request-derived movement;"
note "  • makeTransfer unshielded/shielded to an EXTERNAL wallet printed a PLAN-derived movement — the"
note "    value that LEFT the wallet PLUS the dust fee (the path the unsealed mock-prove fix repaired);"
note "  • balanceSealed merge printed the taker's complement PLUS the merged dust fee."
echo
note "Revoke anything left over with:  ${CYAN}ows key list${DIM}  then  ${CYAN}ows key revoke --id <id> --confirm"
