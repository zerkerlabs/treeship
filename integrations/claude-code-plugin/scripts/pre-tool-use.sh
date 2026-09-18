#!/bin/sh
# Treeship Claude Code plugin -- PreToolUse hook: the gate.
#
# Turns the session actor's registered agent card into a runtime boundary.
# The card (`treeship agent register --name <actor> --tools ... --forbidden
# ... --escalation ...`) lives at .treeship/agents/<id>.json. This hook maps
# the Claude Code tool about to run onto a capability name, then:
#
#   forbidden          -> deny, and sign a blocked.v1 receipt (always)
#   network declared and a WebFetch host is outside it
#                      -> deny, and sign a blocked.v1 receipt (always)
#   network declared and the host is inside it -> allow
#   escalation_required-> ask the operator (always)
#   not in bounded_tools:
#       TREESHIP_GATE=enforce -> deny, and sign a blocked.v1 receipt
#       otherwise              -> allow, and leave an agent.note in the
#                                 timeline saying the call was off-card
#   in bounded_tools   -> allow, silently
#
# No registered card for the session actor means no policy, so the hook
# allows everything and says nothing. It fails open on every error path:
# a broken Treeship never blocks a tool call by accident.
#
# A deny is a signed refusal, not a log line: `blocked.v1` with
# reason_class=scope_violation, refused_kind=action, the actor, and the
# tool, sealed into the session like any other artifact.

set -e

# Resolve our own directory before any cd so the shared helper is found
# whether the hook is invoked by absolute path (Claude Code) or relative.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v treeship >/dev/null 2>&1 || exit 0

if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ ! -d "./.treeship" ] && [ ! -d "${HOME}/.treeship" ]; then
  exit 0
fi
STATUS=$(treeship session status --format json 2>/dev/null) || exit 0
[ -z "$STATUS" ] && exit 0

# shellcheck source=./agent-instance.sh
. "$SCRIPT_DIR/agent-instance.sh"

TOOL_NAME=$(json_field "$INPUT" tool_name)
[ -z "$TOOL_NAME" ] || [ "$TOOL_NAME" = "null" ] && exit 0
ACTOR=$(json_field "$STATUS" actor)
[ -z "$ACTOR" ] && exit 0
AGENT_NAME=${ACTOR#agent://}
AGENT_NAME=${AGENT_NAME#human://}

# Map the Claude Code tool onto the capability vocabulary cards use.
case "$TOOL_NAME" in
  Read|Grep|Glob)                       CAP="file.read" ;;
  Write|Edit|MultiEdit|NotebookEdit)    CAP="file.write" ;;
  Bash)                                 CAP="shell.exec" ;;
  WebFetch|WebSearch)                   CAP="net.fetch" ;;
  Agent|Task)                           CAP="agent.spawn" ;;
  mcp__*)
    # mcp__server__tool -> server.tool
    CAP=$(printf '%s' "$TOOL_NAME" | sed -e 's/^mcp__//' -e 's/__/./') ;;
  *)                                    CAP=$(printf '%s' "$TOOL_NAME" | tr 'A-Z' 'a-z') ;;
esac

# The host a WebFetch is about to reach, for the card's network scope.
# Scheme and path stripped with sed only; empty for tools without a URL.
HOST=""
if [ "$TOOL_NAME" = "WebFetch" ]; then
  # json_field reads top-level keys only; the URL is nested under tool_input.
  URL=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin); ti = d.get("tool_input") or {}
    u = ti.get("url") if isinstance(ti, dict) else None
    print(u if isinstance(u, str) else "")
except Exception:
    print("")' 2>/dev/null || true)
  [ -n "$URL" ] && HOST=$(printf '%s' "$URL" | sed -E 's|^[a-zA-Z]+://||' | cut -d/ -f1 | cut -d@ -f2- | cut -d: -f1 | tr 'A-Z' 'a-z')
fi

# Find the card for this actor in the agents dir beside the active config.
CARD_DIR=""
for d in "./.treeship/agents" "${HOME}/.treeship/agents"; do
  [ -d "$d" ] && CARD_DIR="$d" && break
done
[ -z "$CARD_DIR" ] && exit 0

# Returns: allow | deny-forbidden | deny-network | deny-scope | ask | nocard
decide() {
  python3 - "$CARD_DIR" "$AGENT_NAME" "$CAP" "$TOOL_NAME" "$HOST" <<'PY' 2>/dev/null
import json, os, sys
card_dir, agent, cap, tool, host = sys.argv[1:6]
def matches(declared, actual):
    if '*' in declared:
        pre, suf = declared.split('*', 1)
        return len(actual) >= len(pre)+len(suf) and actual.startswith(pre) and actual.endswith(suf)
    return declared == actual
def host_in_scope(h, scope):
    # Same rule as treeship_core::session::receipt::host_in_scope: exact
    # host, `*.suffix` (which also matches the suffix itself), or `*`.
    h = h.strip().rstrip('.').lower()
    if not h: return False
    for pat in scope:
        p = pat.strip().lower()
        if p == '*': return True
        if p.startswith('*.'):
            suf = p[2:]
            if h == suf or h.endswith('.' + suf): return True
        elif h == p: return True
    return False
card = None
for f in sorted(os.listdir(card_dir)):
    if not f.endswith('.json'): continue
    try: c = json.load(open(os.path.join(card_dir, f)))
    except Exception: continue
    if c.get('agent_name') == agent: card = c; break
if card is None:
    print('nocard'); sys.exit(0)
caps = card.get('capabilities') or {}
names = (cap, tool)
if any(matches(d, n) for d in caps.get('forbidden', []) for n in names):
    print('deny-forbidden'); sys.exit(0)
network = caps.get('network') or []
if network and host:
    # A declared network scope is an explicit grant for those hosts and an
    # explicit refusal of every other one, whatever mode the gate runs in.
    print('allow' if host_in_scope(host, network) else 'deny-network'); sys.exit(0)
if any(matches(d, n) for d in caps.get('escalation_required', []) for n in names):
    print('ask'); sys.exit(0)
if any(matches(d, n) for d in caps.get('bounded_tools', []) for n in names):
    print('allow'); sys.exit(0)
print('deny-scope')
PY
}
DECISION=$(decide)
[ -z "$DECISION" ] && exit 0

emit_deny() {
  reason="$1"
  DESC=$(printf 'gate refused %s (%s) for %s: %s' "$TOOL_NAME" "$CAP" "$ACTOR" "$reason" | cut -c1-300)
  PAYLOAD=$(python3 -c '
import json, sys
print(json.dumps({"reason_class": "scope_violation", "refused_kind": "action", "actor": sys.argv[1], "description": sys.argv[2]}))
' "$ACTOR" "$DESC" 2>/dev/null)
  [ -n "$PAYLOAD" ] && treeship attest receipt \
    --system "system://treeship-gate" \
    --kind "blocked.v1" \
    --payload "$PAYLOAD" \
    >/dev/null 2>&1 || true
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Treeship gate: %s is %s for %s. The refusal is a signed blocked.v1 receipt in this session."}}\n' "$CAP" "$reason" "$ACTOR"
}

case "$DECISION" in
  nocard|allow) exit 0 ;;
  deny-forbidden) emit_deny "forbidden by the agent card"; exit 0 ;;
  deny-network) emit_deny "host $HOST is outside the agent card's network scope"; exit 0 ;;
  ask)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Treeship gate: %s requires escalation on the agent card for %s."}}\n' "$CAP" "$ACTOR"
    exit 0 ;;
  deny-scope)
    if [ "${TREESHIP_GATE:-}" = "enforce" ]; then
      emit_deny "not in the agent card's bounded tools"; exit 0
    fi
    # Observe mode: allow, but the timeline says the call was off-card.
    NOTE=$(python3 -c 'import json,sys; print(json.dumps({"text": "off-card: %s (%s) not in bounded tools for %s" % (sys.argv[1], sys.argv[2], sys.argv[3])}))' "$TOOL_NAME" "$CAP" "$ACTOR" 2>/dev/null)
    [ -n "$NOTE" ] && treeship session event --type agent.note --agent-name "$(agent_instance "$INPUT")" --meta "$NOTE" >/dev/null 2>&1 || true
    exit 0 ;;
esac
exit 0
