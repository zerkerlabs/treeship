#!/bin/sh
# Treeship Kimi Code CLI plugin -- SessionStart hook
set -e
cat >/dev/null 2>&1 || true

if ! command -v treeship >/dev/null 2>&1; then exit 0; fi

if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ -d "${HOME}/.treeship" ]; then
  :
elif [ ! -d "./.treeship" ]; then
  exit 0
fi

if treeship session status --check >/dev/null 2>&1; then exit 0; fi

PROJECT=$(basename "$(pwd)")
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SESSION_NAME="${PROJECT}-kimi-code-${TIMESTAMP}"

SESSION_START_ERR=$(treeship session start --name "$SESSION_NAME" 2>&1 >/dev/null) || SESSION_START_FAILED=1

if [ -z "${SESSION_START_FAILED:-}" ]; then
  MODEL="${TREESHIP_MODEL:-}"
  if [ -z "$MODEL" ] && [ -f "$HOME/.kimi/config.toml" ]; then
    MODEL=$(grep -E '^[[:space:]]*model[[:space:]]*=' "$HOME/.kimi/config.toml" 2>/dev/null \
            | head -1 \
            | sed -E 's/^[[:space:]]*model[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/' \
            | head -c 64)
  fi
  MODEL="${MODEL:-kimi-k2}"

  treeship session event \
    --type agent.decision \
    --model "$MODEL" \
    --provider moonshot \
    --agent-name kimi-code \
    >/dev/null 2>&1 || true

  cat <<EOF
{
  "additionalContext": "Treeship session started: $SESSION_NAME. Every tool call below will be captured into a portable, signed receipt."
}
EOF
fi
exit 0
