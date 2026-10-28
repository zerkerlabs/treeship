#!/bin/sh
# Treeship Claude Code plugin -- SessionEnd hook
#
# Closes the active Treeship session and tells the PERSON where their receipt
# is. Fails open: a broken Treeship install never blocks the session ending.
#
# Why both output fields. `additionalContext` is injected into the model's
# prompt and is never shown to the user, so for a long time the only pointer
# to a sealed receipt went to Claude rather than to the human who owns it, and
# people reasonably concluded nothing had been produced. `systemMessage` is
# the documented user-facing field, but the hooks reference does not state
# whether it renders for SessionEnd specifically. So this emits both: the
# user-facing field carries the path, and the model-facing field instructs
# Claude to say it out loud if the first one does not render. One of the two
# always reaches the person.

set -e

cat >/dev/null 2>&1 || true

if ! command -v treeship >/dev/null 2>&1; then
  exit 0
fi

if [ ! -d "./.treeship" ]; then
  exit 0
fi

if ! treeship session status --check >/dev/null 2>&1; then
  exit 0
fi

HEADLINE="Claude Code session"

# JSON, so the real report path comes from the close itself rather than being
# reconstructed here and drifting from whatever the CLI actually wrote.
CLOSE_OUT=$(treeship session close --headline "$HEADLINE" --format json 2>/dev/null || true)

if [ -z "$CLOSE_OUT" ]; then
  exit 0
fi

json_field() {
  printf '%s\n' "$CLOSE_OUT" \
    | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -1
}

# Backslashes first, then quotes: a path is attacker-adjacent input only in
# the sense that a directory name can contain either, and an unescaped one
# would produce JSON the harness cannot parse.
json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

REPORT=$(json_field report)
PACKAGE=$(json_field package)
SESSION_ID=$(json_field session_id)

REPORT_URL=""
case "${TREESHIP_AUTO_PUBLISH:-}" in
  1|true)
    REPORT_OUT=$(treeship session report 2>/dev/null || true)
    REPORT_URL=$(printf '%s\n' "$REPORT_OUT" | grep -oE 'https?://[^[:space:]]+' | head -1)
    ;;
esac

if [ -n "$REPORT_URL" ]; then
  USER_MSG="Treeship sealed this session. Shareable report: ${REPORT_URL} -- run 'treeship dashboard' to read it locally, or 'treeship verify last' to check it offline."
  MODEL_MSG="The Treeship session was sealed and published. Tell the user plainly, in your closing message, that their signed receipt is published at ${REPORT_URL}, that a local copy is in .treeship/sessions/, and that 'treeship dashboard' opens the human-readable report. Do not omit this: it is the only notice the user gets."
elif [ -n "$REPORT" ]; then
  USER_MSG="Treeship sealed this session. Human-readable report: ${REPORT} -- or run 'treeship dashboard' to browse it. Verify offline with 'treeship verify last'. Nothing was published."
  MODEL_MSG="The Treeship session was sealed locally and nothing left the machine. Tell the user plainly, in your closing message, that their signed receipt and a human-readable report are at ${REPORT}, that 'treeship dashboard' opens it in a browser, and that 'treeship session report' would publish a shareable URL. Do not omit this: it is the only notice the user gets."
else
  USER_MSG="Treeship sealed this session into .treeship/sessions/. Run 'treeship dashboard' to read the report, or 'treeship verify last' to check it offline."
  MODEL_MSG="The Treeship session was sealed into .treeship/sessions/. Tell the user plainly, in your closing message, where it is and that 'treeship dashboard' opens the human-readable report. Do not omit this: it is the only notice the user gets."
fi

if [ -n "$SESSION_ID" ]; then
  USER_MSG="${USER_MSG} (${SESSION_ID})"
fi

printf '{"systemMessage":"%s","additionalContext":"%s","hookSpecificOutput":{"hookEventName":"SessionEnd"}}\n' \
  "$(json_escape "$USER_MSG")" \
  "$(json_escape "$MODEL_MSG")"

exit 0
