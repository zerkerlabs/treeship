#!/bin/sh
# Treeship Kimi Code CLI plugin -- PreToolUse hook
# Records intent. Emits agent.called_tool with meta.phase=intent BEFORE the
# tool runs. Paired with PostToolUse, which emits the typed result event.

set -e

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0

if ! command -v treeship >/dev/null 2>&1; then exit 0; fi

if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ ! -d "./.treeship" ] && [ ! -d "${HOME}/.treeship" ]; then
  exit 0
fi

if ! treeship session status --check >/dev/null 2>&1; then exit 0; fi

extract() {
  field="$1"
  out=""
  if command -v jq >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | jq -r --arg f "$field" '
      ($f | split(".")) as $path
      | reduce $path[] as $k (.; if type == "object" then .[$k] else empty end)
      | if (. == null or . == false) then "" else (if type == "string" then . else tojson end) end
    ' 2>/dev/null)
  fi
  if [ -z "$out" ] && command -v python3 >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | python3 -c "
import json, sys
field = sys.argv[1]
try:
    d = json.load(sys.stdin)
    for p in field.split('.'):
        if isinstance(d, dict): d = d.get(p)
        else: d = None; break
    if d is None: print('')
    elif isinstance(d, str): print(d)
    else: print(json.dumps(d))
except Exception:
    pass
" "$field" 2>/dev/null)
  fi
  printf '%s' "$out"
}

TOOL_NAME=""
for path in toolName tool_name tool.name name params.tool_name; do
  TOOL_NAME=$(extract "$path")
  [ -n "$TOOL_NAME" ] && [ "$TOOL_NAME" != "null" ] && break
  TOOL_NAME=""
done
[ -z "$TOOL_NAME" ] && TOOL_NAME="unknown"

treeship session event \
  --type "agent.called_tool" \
  --tool "$TOOL_NAME" \
  --meta '{"phase":"intent"}' \
  --agent-name "kimi-code" \
  >/dev/null 2>&1 || true

exit 0
