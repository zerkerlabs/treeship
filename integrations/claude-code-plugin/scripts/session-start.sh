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
# `treeship session status --check` exits 0 when active, 1 when not.
if treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

# Derive a session name from the project directory + timestamp
PROJECT=$(basename "$(pwd)")
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SESSION_NAME="${PROJECT}-claude-code-${TIMESTAMP}"

# Capture stderr so we can surface a meaningful diagnostic if session start
# fails. The most common failure is a legacy keystore that can't decrypt
# under the current machine-key derivation; v0.9.4+ emits an actionable
# recovery message on stderr that we want Claude to see rather than swallow.
SESSION_START_ERR=$(treeship session start --name "$SESSION_NAME" 2>&1 >/dev/null) || SESSION_START_FAILED=1

if [ -z "${SESSION_START_FAILED:-}" ]; then
  cat <<EOF
{
  "additionalContext": "Treeship session started: $SESSION_NAME. Every tool call below will be recorded into a portable, signed receipt. The receipt is yours -- it stays in .treeship/sessions/ and only leaves this machine when you run \`treeship session report\`."
}
EOF
else
  # Session start failed. Build the entire additionalContext JSON envelope
  # via python so newlines and quotes in the diagnostic message are escaped
  # correctly. Fall back to a no-frills plain-text message if python isn't
  # available (unlikely on a dev machine, but don't want the hook to crash).
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$SESSION_START_ERR" | python3 -c '
import json, sys
err = sys.stdin.read()
out = {
    "additionalContext":
        "Treeship session did NOT start. The plugin'"'"'s SessionStart hook ran, "
        "but the CLI reported an error. Tool calls in this session will not be "
        "recorded until the underlying issue is fixed.\n\nDiagnostic:\n\n" + err
}
print(json.dumps(out))
' 2>/dev/null || true
  fi
fi

exit 0
