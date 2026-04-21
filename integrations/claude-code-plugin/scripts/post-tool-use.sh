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

# No active session means no place to record this event
if ! treeship session status >/dev/null 2>&1; then
  exit 0
fi

# Pull tool_name out of the payload without requiring jq. The PostToolUse
# JSON schema includes a top-level "tool_name" string field.
TOOL_NAME=$(printf '%s' "$INPUT" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$TOOL_NAME" ]; then
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
