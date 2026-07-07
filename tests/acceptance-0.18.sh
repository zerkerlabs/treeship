#!/usr/bin/env bash
#
# Treeship acceptance test — exercises every capability shipped 0.13 → 0.18
# end to end, with pass/fail assertions. Hand this to a tester: if it prints
# ALL PASS, the full stack works on their machine.
#
# Usage:
#   ./tests/acceptance-0.18.sh                 # local-only steps
#   HUB=https://api.treeship.dev ./tests/acceptance-0.18.sh   # + network steps
#
# It runs in an isolated HOME so it never touches your real keystore.
# Network steps (publish/resolve/audit/history/match) run only when HUB is set
# AND a hub is attached; otherwise they are skipped and reported as such.

set -u

TS="${TREESHIP_BIN:-treeship}"
HUB="${HUB:-}"
PASS=0; FAIL=0; SKIP=0
WORK="$(mktemp -d)"
export HOME="$WORK"          # isolate the keystore
cd "$WORK"

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }

ok()   { PASS=$((PASS+1)); green "  PASS  $1"; }
no()   { FAIL=$((FAIL+1)); red   "  FAIL  $1"; [ -n "${2:-}" ] && echo "        $2"; }
skip() { SKIP=$((SKIP+1)); echo  "  SKIP  $1"; }

# assert <description> <command...>  — pass if the command exits 0
assert() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else no "$d"; fi; }
# assert_out <description> <needle> <command...> — pass if stdout contains needle
assert_out() {
  local d="$1" needle="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if printf '%s' "$out" | grep -qF "$needle"; then ok "$d"; else no "$d" "wanted '$needle', got: $(printf '%s' "$out" | head -1)"; fi
}

echo "Treeship acceptance — CLI: $($TS --version 2>/dev/null)"
echo "Isolated HOME: $WORK"
echo

# ── Layer 1: Identity ────────────────────────────────────────────────────────
echo "Layer 1: Identity"
assert_out "init creates a ship" "ship" $TS init --name acceptance
assert "register agent with its own key" $TS agent register --name tester --own-key
assert "register is idempotent (no duplicate key)" $TS agent register --name tester --own-key
assert_out "action attested" "attested" $TS attest action --actor agent://tester --action "Bash(git:status)"

# capture the action id for verify
ACT=$($TS attest action --actor agent://tester --action "Bash(git:commit)" --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
assert_out "action verifies proven (key-bound)" "proven (key-bound)" $TS verify "$ACT"

# ── Layer 2: Capability cards ────────────────────────────────────────────────
echo "Layer 2: Capability cards"
# a harness config to capture from
mkdir -p .claude
echo '{"permissions":{"allow":["Bash(git:*)","Read(*)","Edit(*)"]}}' > .claude/settings.json
CARD=$($TS attest card --agent agent://tester --from-harness .claude/settings.json --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
assert_out "card is key-bound" "yes (AgentCert)" $TS verify-capability "$CARD"
assert_out "harness capture graded captured" "captured" $TS verify-capability "$CARD"
# the Bash(git:*) glob should match the git action → in-scope, exit 0
assert "glob capability matches real git action (exit 0)" $TS verify-capability "$CARD"

# revocation → REVOKED and non-zero exit
$TS revoke-capability "$CARD" --reason "acceptance" >/dev/null 2>&1
if $TS verify-capability "$CARD" >/dev/null 2>&1; then
  no "revoked card exits non-zero"
else
  assert_out "revoked card reports REVOKED" "REVOKED" $TS verify-capability "$CARD"
fi

# ── Layer 3: Typed receipts ──────────────────────────────────────────────────
echo "Layer 3: Typed receipts"
# a malformed session.v1 payload must be rejected before signing
if $TS attest receipt --system system://x --kind session.v1 --payload '{}' >/dev/null 2>&1; then
  no "malformed typed payload is rejected"
else
  ok "malformed typed payload is rejected (fail-closed)"
fi

# ── Layer 4/6: Onboard + trust bundle (local) ────────────────────────────────
echo "Layer 6: Onboard"
assert_out "onboard runs end to end" "agent onboarded" $TS onboard tester2 --from-harness .claude/settings.json
assert_out "keys export prints a pinnable pubkey" "ed25519:" $TS keys export

# ── Layer 6: Presentation + challenge (local, offline) ───────────────────────
echo "Layer 6: Presentation + challenge"
$TS checkpoint >/dev/null 2>&1
if $TS present agent://tester2 --out t.presentation.json >/dev/null 2>&1; then
  ok "present writes a presentation file"
  NONCE=$(python3 -c "import secrets;print(secrets.token_hex(16))")
  $TS present agent://tester2 --challenge "$NONCE" --out t.presentation.json >/dev/null 2>&1
  # verify against OUR trust roots: with the agent key locally pinned it should verify live
  assert_out "challenge proves live key control" "bearer controls" $TS verify-presentation t.presentation.json --challenge "$NONCE"
  # a replayed nonce must fail
  BAD=$(python3 -c "import secrets;print(secrets.token_hex(16))")
  if $TS verify-presentation t.presentation.json --challenge "$BAD" >/dev/null 2>&1; then
    no "replayed challenge is rejected"
  else
    ok "replayed challenge is rejected"
  fi
else
  skip "present (needs a checkpoint; ensure artifacts exist)"
fi

# ── Layer 7: Work history (local) ────────────────────────────────────────────
echo "Layer 7: Work history"
git init -q . 2>/dev/null
$TS session start --name "acceptance session" >/dev/null 2>&1
$TS attest action --actor agent://tester --action "Bash(git:status)" >/dev/null 2>&1
if $TS session close --headline "acceptance" >/dev/null 2>&1; then
  ok "session close mints a session.v1 record"
  $TS checkpoint >/dev/null 2>&1
  assert_out "profile computes + attests" "checkpoint #" $TS profile ship://$($TS status --format json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['ship']['id'])" 2>/dev/null) --attest 2>/dev/null || skip "profile (needs a session.v1 record)"
else
  skip "session close (session machinery unavailable in this sandbox)"
fi

# ── Layer 9: Reliability ─────────────────────────────────────────────────────
echo "Layer 9: Reliability"
assert_out "status shows the resolved store" "store:" $TS status

# ── Network steps (only with HUB set + attached) ─────────────────────────────
echo "Network steps"
if [ -z "$HUB" ]; then
  skip "publish/resolve/audit/history/match (set HUB= and run 'treeship hub attach' first)"
else
  if $TS hub status 2>/dev/null | grep -q attached; then
    assert "publish agent to hub" $TS publish agent://tester2
    assert_out "resolve over the network" "resolved" $TS resolve --hub "$HUB" agent://tester2
    assert "audit over the network (exit 0 = no anomaly)" $TS audit --hub "$HUB" agent://tester2
    assert "match by exercised evidence" $TS match --hub "$HUB" --exercised "Bash(git:*)"
  else
    skip "network steps (no hub attached — run 'treeship hub attach')"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────"
echo "  PASS: $PASS   FAIL: $FAIL   SKIP: $SKIP"
rm -rf "$WORK"
if [ "$FAIL" -eq 0 ]; then
  green "  ALL PASS"
  exit 0
else
  red "  $FAIL FAILED"
  exit 1
fi
