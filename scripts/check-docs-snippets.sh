#!/usr/bin/env bash
# Execute the documented product flows against a built binary and assert the
# contracts the docs and README promise. This is the gate the 2026-07 audits
# asked for: a green docs build proves MDX compiles; this proves the commands
# users copy actually run and return the documented verdicts.
#
# Usage: scripts/check-docs-snippets.sh [path-to-treeship-binary]
# Requires: jq. Runs fully offline in a throwaway store (never touches
# ~/.treeship; trust pins go to a scratch TREESHIP_TRUST_ROOTS).

set -euo pipefail

BIN="${1:-target/debug/treeship}"
command -v jq >/dev/null || { echo "jq is required"; exit 2; }
[ -x "$BIN" ] || { echo "binary not found: $BIN (cargo build -p treeship-cli)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

TMP="$(mktemp -d -t treeship-snippets.XXXX)"
trap 'rm -rf "$TMP"' EXIT
export TREESHIP_CONFIG="$TMP/.treeship/config.json"
export TREESHIP_TRUST_ROOTS="$TMP/trust_roots.json"
cd "$TMP"

PASS=0
step() { echo "── $1"; }
ok() { PASS=$((PASS + 1)); echo "   ✓ $1"; }
fail() { echo "   ✗ $1"; exit 1; }

step "README: install-free local loop (init → wrap → verify last)"
"$BIN" init --name snippets >/dev/null
"$BIN" wrap --action test.run -- sh -c 'echo ok' >/dev/null
OUT="$("$BIN" verify last 2>&1)"
grep -q "actor proof:   asserted" <<<"$OUT" || fail "verify last must grade the wrap actor 'asserted', got: $OUT"
ok "wrap verifies with actor proof: asserted"

step "README: scoped approval flow (nonce field, scope required, binding verified)"
if "$BIN" attest approval --approver human://alice --description "x" \
    --expires 2030-01-01T00:00:00Z --format json 2>/dev/null | grep -q '"nonce"'; then
  fail "scopeless approval must be rejected (docs promise scoped-by-default)"
fi
ok "scopeless approval rejected"
NONCE="$("$BIN" attest approval --approver human://alice --description "deploy v2.1" \
  --allowed-actor agent://deployer --allowed-action deploy.production --max-uses 1 \
  --expires 2030-01-01T00:00:00Z --format json | jq -re .nonce)"
[ -n "$NONCE" ] || fail "approval JSON must carry .nonce"
ok "approval JSON exposes .nonce"
GATED="$("$BIN" attest action --actor agent://deployer --action deploy.production \
  --approval-nonce "$NONCE" --format json | jq -re 'first(.id // .artifact_id // empty)')"
OUT="$("$BIN" verify "$GATED" 2>&1)"
grep -q "approved:" <<<"$OUT" || fail "verify must surface the approval binding; id=$GATED got: $OUT"
ok "approval binding verified"

step "README: identity onboarding upgrades actor proof to proven (key-bound)"
"$BIN" onboard deployer --tools 'deploy.*,git.push' >/dev/null 2>&1
BOUND="$("$BIN" attest action --actor agent://deployer --action deploy.production --format json | jq -re 'first(.id // .artifact_id // empty)')"
OUT="$("$BIN" verify "$BOUND" 2>&1)"
grep -q "proven (key-bound)" <<<"$OUT" || fail "onboarded agent's action must verify proven (key-bound); id=$BOUND got: $OUT"
ok "onboard → proven (key-bound)"

step "README: selective-disclosure presentation verifies offline"
"$BIN" present agent://deployer --disclose 'deploy.*' --out p.json >/dev/null
OUT="$("$BIN" verify-presentation p.json 2>&1)"
grep -q "revealed 1 of 2 capabilities" <<<"$OUT" || fail "presentation must reveal 1 of 2, got: $OUT"
grep -q "key-bound:   yes" <<<"$OUT" || fail "presentation must be key-bound"
ok "present --disclose / verify-presentation round-trips"

step "docs(cli/verify): fetched receipts earn structural-pass, never pass"
"$BIN" session start --name snippets >/dev/null 2>&1
"$BIN" wrap --action snippets.write -- sh -c 'echo hello > a.txt' >/dev/null
"$BIN" session close --summary "snippets run" >/dev/null 2>&1
PKG="$(find "$TMP/.treeship/sessions" -name 'ssn_*.treeship' -print -quit)"
[ -n "$PKG" ] || fail "session close must produce a .treeship package"
V="$("$BIN" verify "$PKG" --format json)"
[ "$(jq -r .outcome <<<"$V")" = "structural-pass" ] || fail "package verify outcome must be structural-pass, got $(jq -r .outcome <<<"$V")"
[ "$(jq -r .signatures_verified <<<"$V")" = "false" ] || fail "signatures_verified must be false on this surface"
ok "external verify: structural-pass with signatures_verified:false"

step "docs(guides/dogfood): session report takes a session ID, not a package path"
SSN="$(basename "$PKG" .treeship)"
"$BIN" session report --no-upload "$SSN" >/dev/null 2>&1 || fail "session report <session-id> must work"
ok "session report <session-id> works"

step "docs(cli/receipt): exported triple verifies via JSON contract"
ART="$("$BIN" attest action --actor agent://deployer --action triple.test --format json | jq -re '.id // .artifact_id')"
T="$("$BIN" receipt export "$ART" --format json)"
[ "$(jq -r .algorithm <<<"$T")" = "ed25519" ] || fail "receipt export algorithm must be ed25519"
jq -re .message_b64 <<<"$T" >/dev/null && jq -re .signature_b64 <<<"$T" >/dev/null \
  && jq -re .public_key_b64 <<<"$T" >/dev/null || fail "receipt export must emit the full triple"
ok "receipt export emits the message/signature/key triple"

step "docs(cli/trust): deprecated 'ship' kind is rejected"
if "$BIN" trust add key_test ed25519:AAAA --kind ship --yes >/dev/null 2>&1; then
  fail "trust add --kind ship must be rejected"
fi
ok "trust add --kind ship rejected"

echo
echo "✓ all $PASS documented contracts hold"
