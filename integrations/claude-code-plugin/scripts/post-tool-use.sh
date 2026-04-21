#!/bin/sh
# Treeship Claude Code plugin -- PostToolUse hook
#
# The Treeship MCP server captures every MCP tool call. This hook captures
# Claude Code's BUILT-IN tools (Read, Write, Edit, Bash, Grep, Glob, etc.)
# which do not flow through MCP and would otherwise be missing from the
# receipt timeline.
#
# Reads the PostToolUse JSON payload from stdin, extracts the tool name,
# and forwards a structured event to `treeship session event` with the
# full payload as JSON metadata.

set -e

INPUT=$(cat 2>/dev/null || true)

if [ -z "$INPUT" ]; then
  exit 0
fi

if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

if [ ! -d "./.treeship" ]; then
  exit 0
fi

# No active session means no place to record this event.
# `treeship session status --check` exits 0 when active, 1 when not.
if ! treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

# Pull tool_name out of the payload using a real JSON parser. The payload
# can contain user-controlled strings that look like JSON keys (e.g. a Bash
# command whose argument literally contains `"tool_name":"foo"`), so a
# regex would extract the wrong value. Try jq, then python3, then node --
# any of the three is fine. Only fall back to "unknown" if none are
# present, which is rare on modern dev machines.
TOOL_NAME=""
if command -v jq >/dev/null 2>&1; then
  TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
fi
if [ -z "$TOOL_NAME" ] && command -v python3 >/dev/null 2>&1; then
  TOOL_NAME=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("tool_name",""))
except Exception: pass' 2>/dev/null)
fi
if [ -z "$TOOL_NAME" ] && command -v node >/dev/null 2>&1; then
  TOOL_NAME=$(printf '%s' "$INPUT" | node -e 'let d=""; process.stdin.on("data",c=>d+=c); process.stdin.on("end",()=>{ try { console.log(JSON.parse(d).tool_name||""); } catch { console.log(""); } })' 2>/dev/null)
fi
if [ -z "$TOOL_NAME" ] || [ "$TOOL_NAME" = "null" ]; then
  TOOL_NAME="unknown"
fi

# Fire-and-forget: a failure to record an individual tool call must never
# break Claude Code. The CLI's `session event` is best-effort.
treeship session event \
  --type "agent.called_tool" \
  --tool "$TOOL_NAME" \
  --agent-name "claude-code" \
  --meta "$INPUT" \
  >/dev/null 2>&1 || true

exit 0
