#!/usr/bin/env bash
# CLI-2: the standard approval-bound action flow (fixed on main by #466).
# A single-use approval, an action that consumes it, and the sealed package
# verifies; the approval and coverage receipts are not read as actions.
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
ts session start --name approval --actor agent://a >/dev/null 2>&1 || fail "session start"
N=$(ts --format json attest approval --approver human://h --allowed-actor agent://a \
      --allowed-action deploy --max-uses 1 | json_field nonce) || fail "attest approval"
ACT=$(ts --format json attest action --actor agent://a --action deploy --approval-nonce "$N" | json_field id) \
  || fail "attest action --approval-nonce"
expect_pass ts verify "$ACT"
ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
P="$(package_in "$FLOW_DIR/r")"
expect_pass ts package verify "$P"
expect_output 'PASS approval-use-action-binding' ts package verify "$P"
