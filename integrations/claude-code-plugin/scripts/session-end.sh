#!/bin/sh
# Treeship Claude Code plugin -- SessionEnd hook
#
# Closes the active Treeship session and surfaces the session report URL
# back into the Claude Code context. Fails open: a broken Treeship install
# never blocks the session from ending.

set -e

cat >/dev/null 2>&1 || true

if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

if [ ! -d "./.treeship" ]; then
  exit 0
fi

# No active session means nothing to close
if ! treeship session status >/dev/null 2>&1; then
  exit 0
fi

# Generic auto-headline. If the user invoked the treeship-session skill earlier
# and closed with a real headline, `session status` returns non-zero above and
# we never get here.
HEADLINE="Claude Code session"

if treeship session close --headline "$HEADLINE" >/dev/null 2>&1; then
  # `treeship session report` prints the report URL on stdout by default.
  # Capture it; fall back to a local-only message if reporting fails (no hub
  # configured, offline, etc.).
  REPORT_OUT=$(treeship session report 2>/dev/null || true)
  REPORT_URL=$(printf '%s\n' "$REPORT_OUT" | grep -oE 'https?://[^[:space:]]+' | head -1)

  if [ -n "$REPORT_URL" ]; then
    cat <<EOF
{
  "additionalContext": "Treeship session sealed. Receipt is yours -- it lives at .treeship/sessions/ and you can verify it offline with \`treeship verify last\`. Shareable session report: $REPORT_URL"
}
EOF
  else
    cat <<'EOF'
{
  "additionalContext": "Treeship session sealed. Receipt is yours -- stored locally at .treeship/sessions/. Verify offline: `treeship verify last`. Publish a shareable session report: `treeship session report`."
}
EOF
  fi
fi

exit 0
