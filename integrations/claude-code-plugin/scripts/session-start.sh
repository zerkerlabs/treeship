#!/bin/sh
# Treeship Claude Code plugin -- SessionStart hook
#
# Auto-starts a Treeship session if (a) the treeship CLI is on PATH and
# (b) the cwd is a Treeship-initialized project (.treeship/ exists).
#
# Fails open: any error path silently exits 0 so a missing or broken
# Treeship install never prevents Claude Code from starting.

set -e

# Drain the SessionStart event payload from stdin (we don't currently use it)
cat >/dev/null 2>&1 || true

# Fail open if treeship CLI not installed
if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

# Only act inside a Treeship-initialized project
if [ ! -d "./.treeship" ]; then
  exit 0
fi

# If a session is already active in this project, don't start a duplicate.
# `treeship session status` exits non-zero when no active session.
if treeship session status >/dev/null 2>&1; then
  exit 0
fi

# Derive a session name from the project directory + timestamp
PROJECT=$(basename "$(pwd)")
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SESSION_NAME="${PROJECT}-claude-code-${TIMESTAMP}"

if treeship session start --name "$SESSION_NAME" >/dev/null 2>&1; then
  # Surface a quiet status line back into Claude's context via structured hook output
  cat <<EOF
{
  "additionalContext": "Treeship session started: $SESSION_NAME. Every tool call below will be recorded into a portable, signed receipt. The receipt is yours -- it stays in .treeship/sessions/ and only leaves this machine when you run \`treeship session report\`."
}
EOF
fi

exit 0
