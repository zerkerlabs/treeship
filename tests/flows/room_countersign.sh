#!/usr/bin/env bash
# CLI-3: the multi-agent session lifecycle from concepts/multi-agent-sessions:
# host invites, a participant joins, the host countersigns, the session closes.
# The two-signature participant envelope verifies on its own and inside the
# sealed package.
# xfail: W1-3 package verify checks DSSE bytes, the participant signed canonical bytes
# xfail-match: signature:art_[0-9a-f]+ -- invalid signature
. "$(dirname "$0")/lib.sh"

ts init --name host >/dev/null 2>&1 || fail "init"
ts session start --name room --actor agent://host >/dev/null 2>&1 || fail "session start"
ts session invite --open --expires 10m >"$FLOW_DIR/inv.txt" 2>/dev/null || fail "invite"

# join tells the joiner which host key to pin; pin it, then join for real.
hostpub=$(ts session join --invite-file "$FLOW_DIR/inv.txt" --actor agent://j 2>&1 \
  | sed -n 's/.*trust add <key_id> \(ed25519:[^ ]*\).*/\1/p' | head -1)
[ -n "$hostpub" ] || fail "join did not name the host key to pin"
ts trust add room_host "$hostpub" --kind session_host --yes >/dev/null 2>&1 || fail "pin host"
PID=$(ts --format json session join --invite-file "$FLOW_DIR/inv.txt" --actor agent://j | json_field participant_id) \
  || fail "join"

MC=$(ts --format json session mint-challenge) || fail "mint-challenge"
N=$(printf '%s' "$MC" | json_field nonce); IAT=$(printf '%s' "$MC" | json_field issued_at)
ts session answer-challenge "$PID" --challenge "$N" --actor agent://j --out "$FLOW_DIR/resp.json" >/dev/null 2>&1 \
  || fail "answer-challenge"
expect_pass ts session countersign "$PID" --challenge "$N" --challenge-issued-at "$IAT" \
  --challenge-response "$FLOW_DIR/resp.json"

expect_pass ts verify "$PID"
ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
expect_pass ts package verify "$(package_in "$FLOW_DIR/r")"
