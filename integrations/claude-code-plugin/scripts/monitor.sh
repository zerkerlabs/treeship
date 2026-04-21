#!/bin/sh
# Treeship Claude Code plugin -- live monitor
#
# Streams a one-line status update for the active Treeship session every
# few seconds. Each line written to stdout becomes a notification Claude
# sees in real time, so the agent knows the receipt is being built.
#
# Silent when there's no active session or no Treeship install; never
# crashes the session.

set -e

if ! command -v treeship >/dev/null 2>&1; then
  # Sleep instead of exit so the monitor framework doesn't keep respawning us.
  exec sleep 86400
fi

LAST=""

while :; do
  if [ -d "./.treeship" ] && treeship session status --check >/dev/null 2>&1; then
    # Pull the receipts/events counters out of `session status`. The CLI's
    # default output includes lines like "receipts:  3" and "events:    7".
    STATUS=$(treeship session status 2>/dev/null || true)
    RECEIPTS=$(printf '%s\n' "$STATUS" | sed -n 's/.*receipts:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
    EVENTS=$(printf '%s\n' "$STATUS" | sed -n 's/.*events:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)

    if [ -n "$RECEIPTS" ] || [ -n "$EVENTS" ]; then
      LINE="receipts=${RECEIPTS:-0} events=${EVENTS:-0}"
      if [ "$LINE" != "$LAST" ]; then
        echo "treeship: $LINE"
        LAST="$LINE"
      fi
    fi
  fi
  sleep 5
done
