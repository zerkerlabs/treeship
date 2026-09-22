#!/usr/bin/env bash
# The Claude Code gate, end to end, with the real CLI and the real hook
# scripts. The parity suite runs the hooks against a mock treeship and
# fixture cards; it passed while the gate never fired in a real install
# (film findings 2026-09-22, gate report). This test is the real path:
#
#   register a card with rules -> the bridge's start-up re-register must
#   keep them -> session-start.sh must start the session as the agent ->
#   pre-tool-use.sh must deny a forbidden Bash with a signed blocked.v1 ->
#   an allowed Read must pass silently -> the sealed package must verify
#   under --strict, refusal included.
#
# Usage: integrations/tests/gate-e2e.sh [path-to-treeship]
set -euo pipefail

TREESHIP="${1:-${TREESHIP_CLI:-treeship}}"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
BIN=$(command -v "$TREESHIP" 2>/dev/null || true)
[ -n "$BIN" ] || BIN="$TREESHIP"
[ -x "$BIN" ] || { echo "treeship not found: $TREESHIP" >&2; exit 2; }

PLUGIN=$(cd "$(dirname "$0")/../claude-code-plugin" && pwd)
ROOT=$(mktemp -d -t gate-e2e.XXXXXX)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/home" "$ROOT/proj" "$ROOT/bin"
ln -sf "$BIN" "$ROOT/bin/treeship"
export PATH="$ROOT/bin:$PATH"
export HOME="$ROOT/home"
export TREESHIP_ALLOW_INSECURE_KEY_PERMS=1
export TREESHIP_TRUST_ROOTS="$ROOT/home/trust_roots.json"
unset TREESHIP_ACTOR TREESHIP_GATE TREESHIP_PROJECT_ROOT TREESHIP_CONFIG

ok()   { printf '   ok   %s\n' "$*"; }
fail() { printf '   FAIL %s\n' "$*" >&2; exit 1; }
jsonget() { python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:]) if i>=0 else {}
v=d
for k in sys.argv[1].split("."):
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else v)' "$1"; }

cd "$ROOT/proj"
treeship init --config .treeship/config.json >/dev/null

echo "== card with rules survives the bridge's start-up register"
treeship agent register --name claude-code --tools file.read,file.write --forbidden shell.exec,net.fetch --quiet >/dev/null
treeship agent register --own-key --quiet --name claude-code >/dev/null
python3 - <<'PY' || fail "re-registering without rule flags wiped the card's rules"
import json,glob,sys
cards=[json.load(open(f)) for f in glob.glob(".treeship/agents/*.json")]
c=[c for c in cards if c.get("agent_name")=="claude-code"]
assert c, "no card"
caps=c[0].get("capabilities") or {}
assert "shell.exec" in caps.get("forbidden",[]), caps
assert "file.read" in caps.get("bounded_tools",[]), caps
assert c[0].get("key_id"), "own key not recorded"
PY
ok "forbidden and bounded rules kept, own key recorded"

echo "== session-start.sh starts the session as the agent"
echo '{}' | sh "$PLUGIN/scripts/session-start.sh" >/dev/null
ACTOR=$(treeship session status --format json | jsonget actor)
[ "$ACTOR" = "agent://claude-code" ] || fail "session actor is '$ACTOR', not agent://claude-code"
ok "actor $ACTOR"

echo "== a forbidden Bash is denied with a signed blocked.v1"
OUT=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pytest"},"tool_use_id":"t1"}' | sh "$PLUGIN/scripts/pre-tool-use.sh")
printf '%s' "$OUT" | grep -q '"permissionDecision":"deny"' || fail "gate did not deny: $OUT"
BLOCKED=$(python3 - <<'PY'
import json,base64,glob
found=[]
for f in glob.glob(".treeship/artifacts/*.json"):
    if f.endswith("index.json"): continue
    try: rec=json.load(open(f))
    except Exception: continue
    env=rec.get("envelope") or {}
    pl=env.get("payload","")
    try:
        stmt=json.loads(base64.urlsafe_b64decode(pl+"="*(-len(pl)%4)))
    except Exception: continue
    if stmt.get("kind")=="blocked.v1":
        found.append((rec["artifact_id"], stmt.get("payload",{}).get("description",""), "parentId" in stmt))
print(json.dumps(found))
PY
)
python3 -c 'import json,sys; f=json.loads(sys.argv[1]); assert f, "no blocked.v1 receipt in the store"; assert any("shell.exec" in d for _,d,_ in f), f; assert all(p for _,_,p in f), "refusal is not chained (no signed parentId): %r" % f' "$BLOCKED" || fail "blocked.v1 receipt missing or unchained"
ok "blocked.v1 sealed, chained onto the session"

echo "== an allowed Read passes silently"
OUT=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"},"tool_use_id":"t2"}' | sh "$PLUGIN/scripts/pre-tool-use.sh")
[ -z "$OUT" ] || fail "allowed call produced output: $OUT"
ok "no decision emitted"

echo "== the sealed package verifies under --strict, refusal included"
CLOSE=$(treeship session close --summary "gate e2e" --format json)
PKG=$(printf '%s' "$CLOSE" | jsonget package)
V=$(treeship package verify "$PKG" --strict --format json || true)
VERDICT=$(printf '%s' "$V" | jsonget verdict)
[ "$VERDICT" = "verified" ] || { printf '%s' "$V" | python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:]) if i>=0 else {}
for c in d.get("checks",[]):
    if c.get("status")!="pass": print("   ",c.get("status"),c.get("name"),":",c.get("detail","")[:160])' >&2; fail "package is $VERDICT under --strict"; }
ok "verified"

printf '\ngate e2e: every check holds\n'
