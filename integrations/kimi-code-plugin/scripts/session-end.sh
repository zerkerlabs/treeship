#!/bin/sh
# Treeship Kimi Code CLI plugin -- SessionEnd hook
set -e
cat >/dev/null 2>&1 || true

if ! command -v treeship >/dev/null 2>&1; then exit 0; fi

if [ -n "${TREESHIP_PROJECT_ROOT:-}" ] && [ -d "${TREESHIP_PROJECT_ROOT}/.treeship" ]; then
  cd "${TREESHIP_PROJECT_ROOT}"
elif [ ! -d "./.treeship" ] && [ ! -d "${HOME}/.treeship" ]; then
  exit 0
fi

if ! treeship session status --check >/dev/null 2>&1; then exit 0; fi

HEADLINE="Kimi Code session"
if treeship session close --headline "$HEADLINE" >/dev/null 2>&1; then
  REPORT_OUT=$(treeship session report 2>/dev/null || true)
  REPORT_URL=$(printf '%s\n' "$REPORT_OUT" | grep -oE 'https?://[^[:space:]]+' | head -1)
  if [ -n "$REPORT_URL" ]; then
    cat <<EOF
{"additionalContext": "Treeship session sealed. Receipt: .treeship/sessions/. Report: $REPORT_URL"}
EOF
  else
    cat <<'EOF'
{"additionalContext": "Treeship session sealed. Receipt stored locally at .treeship/sessions/."}
EOF
  fi
fi
exit 0
