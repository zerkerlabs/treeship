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

# No active session means nothing to close.
# `treeship session status --check` exits 0 when active, 1 when not.
if ! treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

# Generic auto-headline. If the user invoked the treeship-session skill earlier
# and closed with a real headline, `session status --check` returns 1 above and
# we never get here.
HEADLINE="Claude Code session"

if treeship session close --headline "$HEADLINE" >/dev/null 2>&1; then
  # Publishing is opt-in.
  #
  # This used to run unconditionally, so ending a session uploaded its receipt
  # to the configured Hub with no operator in the loop. A receipt is immutable
  # and the upload is not undoable, so anything the capture path got wrong
  # became public before anyone could look at it. The OpenClaw plugin was
  # gated behind this same variable when that was found; this path and the
  # Kimi one were missed, which is why they are being fixed now rather than
  # then.
  #
  # The local receipt is written either way. `treeship session report`
  # publishes it whenever the operator chooses to.
  REPORT_URL=""
  case "${TREESHIP_AUTO_PUBLISH:-}" in
    1|true)
      # `treeship session report` prints the report URL on stdout by default.
      REPORT_OUT=$(treeship session report 2>/dev/null || true)
      REPORT_URL=$(printf '%s\n' "$REPORT_OUT" | grep -oE 'https?://[^[:space:]]+' | head -1)
      ;;
  esac

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
