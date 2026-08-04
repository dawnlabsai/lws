#!/usr/bin/env bash
# Generates llms-full.txt by concatenating all documentation.
# Usage: scripts/build-llms-full.sh <docs-dir> <output-file>
set -euo pipefail

DOCS_DIR="${1:?Usage: build-llms-full.sh <docs-dir> <output-file>}"
OUT="${2:?Usage: build-llms-full.sh <docs-dir> <output-file>}"

# Ordered list of doc files to include
SPEC_FILES=(
  01-storage-format.md
  02-signing-interface.md
  03-policy-engine.md
  04-agent-access-layer.md
  05-key-isolation.md
  06-wallet-lifecycle.md
  07-supported-chains.md
  policy-engine-implementation.md
  cardano.md
)

SDK_FILES=(
  sdk-cli.md
  sdk-node.md
  sdk-python.md
)

cat > "$OUT" <<'HEADER'
# Open Wallet Standard (OWS)

OWS is an open specification for agent-native wallets — encrypted key storage, a pluggable signing interface, and a declarative policy engine that lets AI agents hold and move value safely.

> Source: https://openwallet.sh | Docs: https://docs.openwallet.sh | GitHub: https://github.com/open-wallet-standard/core

<!--
Sitemap:
- [Overview](https://docs.openwallet.sh/): Documentation overview and navigation
- [01 — Storage Format](https://docs.openwallet.sh/doc.html?slug=01-storage-format): How wallets are encrypted, structured, and stored on the local filesystem
- [02 — Signing Interface](https://docs.openwallet.sh/doc.html?slug=02-signing-interface): How wallets expose a chain-agnostic signing API
- [03 — Policy Engine](https://docs.openwallet.sh/doc.html?slug=03-policy-engine): Declarative rules that govern what agents are allowed to do
- [04 — Agent Access Layer](https://docs.openwallet.sh/doc.html?slug=04-agent-access-layer): How AI agents authenticate and interact with wallets
- [05 — Key Isolation](https://docs.openwallet.sh/doc.html?slug=05-key-isolation): How private keys are protected in memory and at rest
- [06 — Wallet Lifecycle](https://docs.openwallet.sh/doc.html?slug=06-wallet-lifecycle): Creation, backup, recovery, rotation, and deletion
- [07 — Supported Chains](https://docs.openwallet.sh/doc.html?slug=07-supported-chains): Blockchain networks supported by OWS and how to add new ones
- [Policy Engine Implementation](https://docs.openwallet.sh/doc.html?slug=policy-engine-implementation): Detailed implementation guide for the policy engine
- [Cardano Support](https://docs.openwallet.sh/doc.html?slug=cardano): Cardano integration — CIP-34 addressing, Ed25519-BIP32 derivation, CIP-8 signing, and policy context
- [CLI Reference](https://docs.openwallet.sh/doc.html?slug=sdk-cli): Command-line interface for managing wallets, signing, and key operations
- [Node.js SDK](https://docs.openwallet.sh/doc.html?slug=sdk-node): Node.js / TypeScript SDK for programmatic wallet access
- [Python SDK](https://docs.openwallet.sh/doc.html?slug=sdk-python): Python SDK for programmatic wallet access
-->

HEADER

# Append each spec doc
for f in "${SPEC_FILES[@]}"; do
  src="$DOCS_DIR/$f"
  if [ -f "$src" ]; then
    cat "$src" >> "$OUT"
    printf '\n\n---\n\n' >> "$OUT"
  fi
done

# Append each SDK doc
for f in "${SDK_FILES[@]}"; do
  src="$DOCS_DIR/$f"
  if [ -f "$src" ]; then
    cat "$src" >> "$OUT"
    printf '\n\n---\n\n' >> "$OUT"
  fi
done

echo "Generated $OUT ($(wc -c < "$OUT") bytes)"
