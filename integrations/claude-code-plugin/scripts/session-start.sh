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
  # Emit one agent.decision event so the receipt records WHICH model
  # Claude Code was running on. Without this, AgentNode.model stays
  # null and the receipt page can't show "claude-opus-4-7" beside
  # the agent name -- the central claim of a multi-model session
  # receipt.
  #
  # Detection priority (best-effort, fail-open):
  #   1. TREESHIP_MODEL env var      (most explicit)
  #   2. ~/.claude/settings.json     (where the user picks /model)
  #   3. fall back to "claude" generic
  MODEL="${TREESHIP_MODEL:-}"
  if [ -z "$MODEL" ] && [ -f "$HOME/.claude/settings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
      MODEL=$(jq -r '.model // empty' "$HOME/.claude/settings.json" 2>/dev/null)
    elif command -v python3 >/dev/null 2>&1; then
      MODEL=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("model", "") or "")
except Exception:
    pass
' "$HOME/.claude/settings.json" 2>/dev/null)
    fi
  fi
  MODEL="${MODEL:-claude}"

  # Provider for claude-code is always anthropic. For multi-vendor
  # deployments (codex/kimi/etc) each integration has its own
  # session-start hook with the right provider hardcoded.
  treeship session event \
    --type agent.decision \
    --model "$MODEL" \
    --provider anthropic \
    --agent-name claude-code \
    >/dev/null 2>&1 || true

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
