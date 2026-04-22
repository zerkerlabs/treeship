#!/bin/sh
# Treeship Claude Code plugin -- PostToolUse hook
#
# Dispatches on tool_name to emit the correct Treeship session event so the
# receipt's side-effects buckets populate properly:
#
#   Claude Code tool   ->  Emitted Treeship event
#   ---------------------  --------------------------------------
#   Read               ->  agent.read_file --file <path>
#   Write              ->  agent.wrote_file --file <path>
#   Edit               ->  agent.wrote_file --file <path>
#   MultiEdit          ->  agent.wrote_file --file <path>
#   NotebookEdit       ->  agent.wrote_file --file <path>
#   Bash               ->  agent.completed_process --tool <cmd> --exit-code <N>
#   WebFetch           ->  agent.connected_network --destination <host>
#   *                  ->  agent.called_tool --tool <name>
#
# Without the dispatch, every tool was emitted as agent.called_tool only, so
# the receipt's files_read[], files_written[], and processes[] lists stayed
# at length 0 even when Claude was reading and writing files all session.
#
# The Treeship MCP server captures every MCP-routed tool call automatically
# via @treeship/mcp; this hook covers Claude Code's BUILT-IN tools (Read,
# Write, Edit, Bash, Grep, Glob, etc.) which bypass MCP entirely.

set -e

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0

if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

if [ ! -d "./.treeship" ]; then
  exit 0
fi

# No active session means no place to record this event.
if ! treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

# ----------------------------------------------------------------------------
# JSON field extractor: jq -> python3 -> node fallback chain.
#
# Takes a dotted path (e.g. "tool_input.file_path") and prints the matching
# string value from $INPUT, or empty if absent. Field name is passed via
# argv to each interpreter so the shell never tries to interpolate it into
# script source -- that prevents quoting bugs and avoids injection if a
# later refactor ever passes user-controlled field paths.
# ----------------------------------------------------------------------------

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
  if [ -z "$out" ] && command -v node >/dev/null 2>&1; then
    out=$(printf '%s' "$INPUT" | node -e '
      let buf = "";
      process.stdin.on("data", c => buf += c);
      process.stdin.on("end", () => {
        try {
          let v = JSON.parse(buf);
          for (const k of process.argv[1].split(".")) {
            if (v == null || typeof v !== "object") { v = null; break; }
            v = v[k];
          }
          if (v == null) console.log("");
          else if (typeof v === "string") console.log(v);
          else console.log(JSON.stringify(v));
        } catch { console.log(""); }
      });
    ' "$field" 2>/dev/null)
  fi
  printf '%s' "$out"
}

TOOL_NAME=$(extract tool_name)
[ -z "$TOOL_NAME" ] || [ "$TOOL_NAME" = "null" ] && TOOL_NAME="unknown"

# ----------------------------------------------------------------------------
# Helper: emit a generic agent.called_tool event. Used as the fall-through
# for tools we don't have a specialized event type for, AND as the safety
# net when a specialized emit can't extract its required field.
# ----------------------------------------------------------------------------
emit_called_tool() {
  treeship session event \
    --type "agent.called_tool" \
    --tool "$TOOL_NAME" \
    --agent-name "claude-code" \
    >/dev/null 2>&1 || true
}

# ----------------------------------------------------------------------------
# Dispatch on tool name.
# ----------------------------------------------------------------------------
case "$TOOL_NAME" in
  Read)
    FILE=$(extract tool_input.file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.read_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  Write|Edit|MultiEdit)
    FILE=$(extract tool_input.file_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  NotebookEdit)
    FILE=$(extract tool_input.notebook_path)
    if [ -n "$FILE" ]; then
      treeship session event \
        --type "agent.wrote_file" \
        --file "$FILE" \
        --agent-name "claude-code" \
        >/dev/null 2>&1 || emit_called_tool
    else
      emit_called_tool
    fi
    ;;
  Bash)
    CMD=$(extract tool_input.command)
    # Trim long commands to a sensible process_name. The full command is
    # available in the meta if a downstream consumer wants it.
    PROC_NAME=$(printf '%s' "${CMD:-bash}" | cut -c1-120)
    # PostToolUse fires AFTER the command exits. The exit code is in the
    # tool_response payload (Claude Code uses tool_response.exit_code OR
    # the tool_response.is_error boolean depending on Bash variant).
    EXIT_CODE=$(extract tool_response.exit_code)
    if [ -z "$EXIT_CODE" ]; then
      IS_ERROR=$(extract tool_response.is_error)
      if [ "$IS_ERROR" = "true" ]; then EXIT_CODE=1; else EXIT_CODE=0; fi
    fi
    treeship session event \
      --type "agent.completed_process" \
      --tool "$PROC_NAME" \
      --exit-code "$EXIT_CODE" \
      --agent-name "claude-code" \
      >/dev/null 2>&1 || emit_called_tool
    ;;
  WebFetch)
    URL=$(extract tool_input.url)
    if [ -n "$URL" ]; then
      # Strip scheme + path -> just the host. Sed-only so no extra deps.
      HOST=$(printf '%s' "$URL" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
      if [ -n "$HOST" ]; then
        treeship session event \
          --type "agent.connected_network" \
          --destination "$HOST" \
          --agent-name "claude-code" \
          >/dev/null 2>&1 || emit_called_tool
      else
        emit_called_tool
      fi
    else
      emit_called_tool
    fi
    ;;
  *)
    # Glob, Grep, Task, TodoWrite, ScheduleWakeup, etc. -- generic call.
    emit_called_tool
    ;;
esac

exit 0
