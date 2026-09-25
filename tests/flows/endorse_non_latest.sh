#!/usr/bin/env bash
# CLI-1: endorse an artifact that is not the most recent one, then chain an
# action onto the endorsement. The endorsement, its child, and the session
# package that seals them all verify.
# xfail: W1-1 the endorsement's parent link is not the one the verifier checks
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
ts session start --name endorse --actor agent://a >/dev/null 2>&1 || fail "session start"
A=$(ts --format json attest action --actor agent://a --action a | json_field id) || fail "attest A"
ts attest action --actor agent://a --action x >/dev/null 2>&1 || fail "attest X"
E=$(ts --format json attest endorsement --endorser human://r --subject "$A" --kind review | json_field id) || fail "endorse A"
B=$(ts --format json attest action --actor agent://a --action b --parent "$E" | json_field id) || fail "attest B"

expect_pass ts verify "$E"
expect_pass ts verify "$B"
ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
expect_pass ts package verify "$(package_in "$FLOW_DIR/r")"
