#!/bin/sh
# Treeship Claude Code plugin -- SubagentStart hook
#
# Records the spawn in the session timeline as an `agent.spawned` event so
# the sealed receipt's agent graph carries a parent_child edge from the
# main Claude Code instance to the subagent, and `spawned_subagents` counts
# it. The subagent's own tool calls are tagged with the same instance name
# by post-tool-use.sh, so a reader can see which instance did what.
#
# Fails open: any error exits 0 so a broken Treeship never blocks a spawn.

set -e

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v treeship >/dev/null 2>&1 || exit 0

if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ ! -d "./.treeship" ] && [ ! -d "${HOME}/.treeship" ]; then
  exit 0
fi
treeship session status --check >/dev/null 2>&1 || exit 0

# shellcheck source=./agent-instance.sh
. "$(dirname "$0")/agent-instance.sh"
INSTANCE=$(agent_instance "$INPUT")
[ -z "$INSTANCE" ] && exit 0
AGENT_TYPE=$(json_field "$INPUT" agent_type)
AGENT_ID=$(json_field "$INPUT" agent_id)

META=$(printf '{"spawned_by":"claude-code","agent_type":"%s","agent_id":"%s","hook":"SubagentStart"}' \
  "$(printf '%s' "$AGENT_TYPE" | sed 's/["\\]//g')" "$(printf '%s' "$AGENT_ID" | sed 's/["\\]//g')")

treeship session event \
  --type "agent.spawned" \
  --agent-name "$INSTANCE" \
  --meta "$META" \
  >/dev/null 2>&1 || true

exit 0
