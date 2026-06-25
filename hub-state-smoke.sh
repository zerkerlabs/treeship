#!/usr/bin/env bash
# hub-state-smoke.sh
#
# Verify the v0.12.0+ Hub activation *state* API is live on api.treeship.dev
# WITHOUT browser approval and WITHOUT attaching a real dock.
#
# What it asserts:
#   1. GET /v1/dock/authorized with an unknown (never-issued) code
#      -> new hub: HTTP 404 + {"state":"invalid",...}
#      -> old hub: HTTP 404 + {"error":"not found"}        (FAIL = not redeployed)
#   2. GET /v1/dock/authorized with a malformed code
#      -> new hub: HTTP 400 + {"state":"invalid",...}
#   3. (mutating, but safe) GET /v1/dock/challenge then immediately poll it
#      -> new hub: HTTP 202 + {"state":"pending",...}
#      The challenge carries no keys and no dock, and auto-expires in 5 minutes.
#      Skip it with SKIP_CHALLENGE=1.
#
# Safety: only read calls, plus at most ONE short-lived challenge row with no
# attached dock. Never approves, never sends keys, never creates a ship.
#
# Usage:
#   ./hub-state-smoke.sh                 # against https://api.treeship.dev
#   HUB=http://localhost:8080 ./hub-state-smoke.sh
#   SKIP_CHALLENGE=1 ./hub-state-smoke.sh   # read-only, zero mutation
#
# Exit code: 0 if all checks pass, 1 otherwise.

set -uo pipefail

BASE="${HUB:-https://api.treeship.dev}"
PASS=0
FAIL=0

# call METHOD PATH -> sets CODE and BODY (curl exits 0 on 4xx by default)
CODE=""; BODY=""
call() {
  local raw
  raw=$(curl -sS -X "$1" "$BASE$2" -w $'\n%{http_code}' 2>/dev/null)
  CODE="${raw##*$'\n'}"
  BODY="${raw%$'\n'*}"
}

# has_state BODY EXPECTED -> 0 if body contains "state":"EXPECTED"
has_state() { printf '%s' "$1" | grep -q "\"state\"[[:space:]]*:[[:space:]]*\"$2\""; }

report() { # NAME RESULT(0=pass) DETAIL
  if [ "$2" -eq 0 ]; then
    echo "PASS  $1"
    PASS=$((PASS+1))
  else
    echo "FAIL  $1"
    [ -n "${3:-}" ] && echo "        $3"
    FAIL=$((FAIL+1))
  fi
}

echo "Hub activation-state smoke against: $BASE"
echo "----------------------------------------------------------------"

# --- 1. unknown but well-formed device code ---------------------------------
UNKNOWN=$(printf 'a%.0s' $(seq 1 16))   # 16 hex chars, astronomically never issued
call GET "/v1/dock/authorized?device_code=$UNKNOWN"
if [ "$CODE" = 404 ] && has_state "$BODY" invalid; then
  report "unknown code => 404 + state=invalid" 0
else
  hint="got HTTP $CODE body=$BODY"
  printf '%s' "$BODY" | grep -q '"error":"not found"' && \
    hint="$hint   <-- OLD hub response; redeploy has NOT landed"
  report "unknown code => 404 + state=invalid" 1 "$hint"
fi

# --- 2. malformed device code -----------------------------------------------
call GET "/v1/dock/authorized?device_code=not-hex!"
if [ "$CODE" = 400 ] && has_state "$BODY" invalid; then
  report "malformed code => 400 + state=invalid" 0
else
  report "malformed code => 400 + state=invalid" 1 "got HTTP $CODE body=$BODY"
fi

# --- 3. fresh challenge => pending (safe, short-lived, no dock) --------------
if [ "${SKIP_CHALLENGE:-0}" = 1 ]; then
  echo "SKIP  fresh challenge => 202 + state=pending   (SKIP_CHALLENGE=1)"
else
  call GET "/v1/dock/challenge"
  DC=$(printf '%s' "$BODY" | sed -n 's/.*"device_code":"\([0-9a-f]\{1,\}\)".*/\1/p')
  if [ -z "$DC" ]; then
    report "challenge issued (device_code present)" 1 "got HTTP $CODE body=$BODY"
  else
    report "challenge issued (device_code=$DC, no keys/dock, ~5m TTL)" 0
    call GET "/v1/dock/authorized?device_code=$DC"
    if [ "$CODE" = 202 ] && has_state "$BODY" pending; then
      report "fresh challenge => 202 + state=pending" 0
    else
      report "fresh challenge => 202 + state=pending" 1 "got HTTP $CODE body=$BODY"
    fi
  fi
fi

echo "----------------------------------------------------------------"
echo "Result: $PASS passed, $FAIL failed"
echo
echo "(expired state is not asserted here: forcing it would require a 5-minute"
echo " wait. To check manually, re-poll a challenge's device_code after 5 min:"
echo " expect HTTP 410 + state=expired.)"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
