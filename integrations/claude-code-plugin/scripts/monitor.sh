#!/bin/sh
# Treeship Claude Code plugin -- session monitor
#
# Reports STATE TRANSITIONS, not activity. A session opening, sealing, or
# getting wedged is worth interrupting for. A counter going up is not.
#
# The previous version emitted a line every time `receipts` or `events`
# changed. Events tick on essentially every tool call, so a normal working
# session produced well over a hundred notifications -- one per event --
# none of which told the developer anything they needed. That is how a trust
# tool earns an uninstall: not by being wrong, by being noisy.
#
# The rule this now follows: notify when the answer to "is my work being
# recorded?" changes. It changes when a session opens, when it closes, and
# when it breaks. It does not change because a counter moved.
#
# Silent when there's no active session or no Treeship install; never
# crashes the session.

set -e

if ! command -v treeship >/dev/null 2>&1; then
  # Sleep instead of exit so the monitor framework doesn't keep respawning us.
  exec sleep 86400
fi

# 30s, not 5s. Nothing here is time-critical, and the old interval meant two
# CLI invocations every five seconds for the life of the session -- a real
# background cost for information nobody was reading.
INTERVAL=30

# Session id we last reported on. Empty means nothing reported yet.
REPORTED=""
# Whether the wedged-session warning has already fired, so a stuck session
# warns once instead of every interval.
WARNED=""

session_id() {
  treeship session status 2>/dev/null |
    sed -n 's/.*\(ssn_[0-9a-f][0-9a-f]*\).*/\1/p' | head -1
}

receipt_count() {
  treeship session status 2>/dev/null |
    sed -n 's/.*receipts:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1
}

while :; do
  if [ -d "./.treeship" ] && treeship session status --check >/dev/null 2>&1; then
    SID=$(session_id)

    if [ -n "$SID" ] && [ "$SID" != "$REPORTED" ]; then
      # A session opened, or we switched to a different one. This single
      # line answers "is Treeship actually on?" -- the reason the monitor
      # exists at all.
      echo "treeship: recording $SID"
      REPORTED="$SID"
      WARNED=""
    fi
  else
    # No active session. If we were reporting on one, it closed: say so once,
    # with the receipt count -- the number that actually mattered.
    if [ -n "$REPORTED" ]; then
      N=$(receipt_count)
      echo "treeship: sealed $REPORTED (${N:-0} receipts)"
      REPORTED=""
      WARNED=""
    fi

    # A session.json with no readable status is a wedged session: work is
    # happening and nothing is being recorded. That is the one failure worth
    # pushing at someone, so warn -- once.
    if [ -z "$WARNED" ] && [ -f "./.treeship/session.json" ]; then
      echo "treeship: session.json present but no active session -- run 'treeship session abandon' if wedged"
      WARNED="1"
    fi
  fi

  sleep "$INTERVAL"
done
