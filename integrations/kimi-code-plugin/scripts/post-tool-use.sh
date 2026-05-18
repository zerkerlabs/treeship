#!/bin/sh
# Treeship Kimi Code CLI plugin -- PostToolUse hook
# Dispatches on tool_name to emit the right typed Treeship event.

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

pick() {
  for path in "$@"; do
    v=$(extract "$path")
    if [ -n "$v" ] && [ "$v" != "null" ]; then
      printf '%s' "$v"
      return 0
    fi
  done
  printf ''
}

TOOL_NAME=$(pick toolName tool_name tool.name name params.tool_name)
[ -z "$TOOL_NAME" ] && TOOL_NAME="unknown"

emit_called_tool() {
  treeship session event \
    --type "agent.called_tool" \
    --tool "$TOOL_NAME" \
    --agent-name "kimi-code" \
    >/dev/null 2>&1 || true
}

TOOL_LOWER=$(printf '%s' "$TOOL_NAME" | tr 'A-Z' 'a-z')

case "$TOOL_LOWER" in
  read)
    FILE=$(pick params.file_path params.path params.file tool_input.file_path input.file_path file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.read_file" \
        --file "$FILE" \
        --agent-name "kimi-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  write|edit|multiedit)
    FILE=$(pick params.file_path params.path params.file tool_input.file_path input.file_path file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "kimi-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  notebookedit)
    FILE=$(pick params.notebook_path tool_input.notebook_path notebook_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "kimi-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  bash|exec|shell|run|run_command|terminal)
    CMD=$(pick params.command params.cmd params.shell tool_input.command input.command)
    PROC_NAME=$(printf '%s' "${CMD:-bash}" | cut -c1-120)
    EXIT_CODE=$(pick params.exit_code result.exit_code tool_response.exit_code exit_code)
    if [ -z "$EXIT_CODE" ]; then
      IS_ERROR=$(pick params.is_error result.is_error tool_response.is_error error)
      if [ "$IS_ERROR" = "true" ]; then EXIT_CODE=1; else EXIT_CODE=0; fi
    fi
    treeship session event \
      --type "agent.completed_process" \
      --tool "$PROC_NAME" \
      --exit-code "$EXIT_CODE" \
      --agent-name "kimi-code" \
      >/dev/null 2>&1 || emit_called_tool
    ;;
  fetch|webfetch|http|http_get|http_post)
    URL=$(pick params.url params.href params.endpoint tool_input.url url)
    if [ -n "$URL" ]; then
      HOST=$(printf '%s' "$URL" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
      if [ -n "$HOST" ]; then
        treeship session event \
          --type "agent.connected_network" \
          --destination "$HOST" \
          --agent-name "kimi-code" \
          >/dev/null 2>&1 || emit_called_tool
      else
        emit_called_tool
      fi
    else
      emit_called_tool
    fi
    ;;
  *)
    emit_called_tool
    ;;
esac

exit 0
