#!/usr/bin/env bash
# CLI-3 / W1-3b: a room across two machines. The host invites; a joiner on
# another ship (its own HOME, its own keys and journal) joins and sends the
# pending envelope as a file; the host challenges it, countersigns from the
# file, closes, and the package verifies. A second joiner redeeming the same
# single-use invitation is refused by the host.
. "$(dirname "$0")/lib.sh"

ts init --name host >/dev/null 2>&1 || fail "host init"
ts session start --name room --actor agent://host >/dev/null 2>&1 || fail "session start"
ts session invite --open --expires 10m >"$FLOW_DIR/inv.txt" 2>/dev/null || fail "invite"

join_from() { # join_from <ship> <actor> <out-file>: prints the participant id
  local ship="$1" actor="$2" out="$3" hostpub
  as_ship "$ship" init --name "$ship" >/dev/null 2>&1 || fail "$ship init"
  hostpub=$(as_ship "$ship" session join --invite-file "$FLOW_DIR/inv.txt" --actor "$actor" 2>&1 \
    | sed -n 's/.*trust add <key_id> \(ed25519:[^ ]*\).*/\1/p' | head -1)
  [ -n "$hostpub" ] || fail "$ship: join did not name the host key to pin"
  as_ship "$ship" trust add room_host "$hostpub" --kind session_host --yes >/dev/null 2>&1 || fail "$ship: pin host"
  as_ship "$ship" --format json session join --invite-file "$FLOW_DIR/inv.txt" --actor "$actor" --out "$out" \
    | json_field participant_id
}
# countersign_from <ship> <actor> <pid> <pending-file>: challenge, answer, countersign
countersign_from() {
  local ship="$1" actor="$2" pid="$3" pending="$4" mc n iat
  mc=$(ts --format json session mint-challenge) || fail "mint-challenge"
  n=$(printf '%s' "$mc" | json_field nonce); iat=$(printf '%s' "$mc" | json_field issued_at)
  as_ship "$ship" session answer-challenge "$pid" --challenge "$n" --actor "$actor" \
    --out "$FLOW_DIR/$ship.resp.json" >/dev/null 2>&1 || fail "$ship: answer-challenge"
  ts session countersign --pending "$pending" --challenge "$n" --challenge-issued-at "$iat" \
    --challenge-response "$FLOW_DIR/$ship.resp.json"
}

P1=$(join_from joiner agent://j "$FLOW_DIR/pending1.json") || fail "join"
[ -s "$FLOW_DIR/pending1.json" ] || fail "join --out wrote no pending envelope"

# Across machines the challenge is required.
out="$(ts session countersign --pending "$FLOW_DIR/pending1.json" 2>&1)"; rc=$?
[ $rc -eq 4 ] || { printf '%s\n' "$out" >&2; fail "countersign --pending without a challenge must exit 4 (got $rc)"; }

# A stale challenge (minted long ago) is refused, and refusing it burns
# nothing: every check runs before the host reserves the use.
MC=$(ts --format json session mint-challenge) || fail "mint-challenge"
N=$(printf '%s' "$MC" | json_field nonce)
as_ship joiner session answer-challenge "$P1" --challenge "$N" --actor agent://j \
  --out "$FLOW_DIR/stale.resp.json" >/dev/null 2>&1 || fail "answer-challenge"
out="$(ts session countersign --pending "$FLOW_DIR/pending1.json" --challenge "$N" \
  --challenge-issued-at 2020-01-01T00:00:00Z --challenge-response "$FLOW_DIR/stale.resp.json" 2>&1)" \
  && { printf '%s\n' "$out" >&2; fail "a stale challenge must be refused"; }
printf '%s\n' "$out" | grep -q "mint a fresh one" || { printf '%s\n' "$out" >&2; fail "stale refusal must say why"; }
# ... and without --challenge-issued-at the pending path refuses too.
out="$(ts session countersign --pending "$FLOW_DIR/pending1.json" --challenge "$N" \
  --challenge-response "$FLOW_DIR/stale.resp.json" 2>&1)"; rc=$?
[ $rc -eq 4 ] || { printf '%s\n' "$out" >&2; fail "--pending without --challenge-issued-at must exit 4 (got $rc)"; }

expect_pass countersign_from joiner agent://j "$P1" "$FLOW_DIR/pending1.json"

# A second joiner, on a third machine, redeems the same single-use
# invitation. Its own journal lets it join; the host must refuse.
P2=$(join_from joiner2 agent://k "$FLOW_DIR/pending2.json") || fail "second join"
out="$(countersign_from joiner2 agent://k "$P2" "$FLOW_DIR/pending2.json" 2>&1)"; rc=$?
[ $rc -ne 0 ] || { printf '%s\n' "$out" >&2; fail "a second countersign on a single-use invitation must be refused"; }
printf '%s\n' "$out" | grep -q "already been countersigned" || { printf '%s\n' "$out" >&2; fail "refusal must say the invitation was already countersigned"; }

ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
P="$(package_in "$FLOW_DIR/r")"
expect_pass ts package verify "$P"
expect_output "PASS signature:$P1" ts package verify "$P"

# The session is closed: an invitation for it admits no one now.
out="$(countersign_from joiner2 agent://k "$P2" "$FLOW_DIR/pending2.json" 2>&1)" \
  && { printf '%s\n' "$out" >&2; fail "countersign after close must be refused"; }
printf '%s\n' "$out" | grep -q "not open on this ship" || { printf '%s\n' "$out" >&2; fail "refusal must say the session is not open"; }

# A second ship that pinned the host verifies the room under --strict.
if [ -n "${STRICT_STRANGER:-}" ]; then
  hostkeys=$(python3 -c 'import json,sys; [print(k, v) for k, v in json.load(open(sys.argv[1]))["keys"].items()]' "$P/keys.json")
  as_ship stranger init --name stranger >/dev/null 2>&1 || fail "stranger init"
  while read -r k v; do as_ship stranger trust add "$k" "$v" --kind cert_issuer --yes >/dev/null 2>&1; done <<<"$hostkeys"
  expect_pass as_ship stranger package verify --strict "$P"
fi
