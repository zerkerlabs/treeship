#!/bin/sh
# Treeship Claude Code plugin -- SubagentStop hook
#
# Records the subagent handing control back as an `agent.returned` event, the
# closing half of the parent_child edge subagent-start.sh opened.
#
# Fails open: any error exits 0.

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

treeship session event \
  --type "agent.returned" \
  --agent-name "$INSTANCE" \
  --meta '{"returned_to":"claude-code","hook":"SubagentStop"}' \
  >/dev/null 2>&1 || true

exit 0
