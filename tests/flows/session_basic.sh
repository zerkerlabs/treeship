#!/usr/bin/env bash
# The quickstart: start a session, attest two actions, close, verify the
# package -- on this ship, and under --strict once a stranger pins the key.
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
ts session start --name basic --actor agent://a >/dev/null 2>&1 || fail "session start"
A=$(ts --format json attest action --actor agent://a --action read | json_field id) || fail "attest"
ts attest action --actor agent://a --action write --parent "$A" >/dev/null 2>&1 || fail "attest --parent"
expect_pass ts verify "$A"
ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
P="$(package_in "$FLOW_DIR/r")"
expect_pass ts package verify "$P"
expect_pass ts package verify --strict "$P"

# A second ship has never seen this key: default verify passes with a
# signer_trust warning, --strict fails until the key is pinned.
expect_pass as_ship stranger package verify "$P"
expect_fail as_ship stranger package verify --strict "$P"
# The hint names the key and its fingerprint, without --yes: the reader
# confirms it first. The flow stands in for a reader who did.
pin=$(as_ship stranger package verify "$P" 2>&1 | grep -Eo 'treeship trust add [^ ]+ [^ ]+ --kind [a-z_]+' | head -1)
[ -n "$pin" ] || fail "signer_trust warning printed no pin command"
as_ship stranger package verify "$P" 2>&1 | grep -q 'kind cert_issuer --yes' && fail "pin hint must not carry --yes"
eval "as_ship stranger ${pin#treeship } --yes" >/dev/null 2>&1 || fail "pin: $pin"
expect_pass as_ship stranger package verify --strict "$P"
