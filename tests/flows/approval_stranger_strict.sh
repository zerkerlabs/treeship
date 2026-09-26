#!/usr/bin/env bash
# CLI-18: the approval-bound package from approval_bound_action, verified by a
# second ship that has pinned the producer's key. --strict passes: a pinned
# stranger is exactly who strict mode is for.
# xfail: W1-13 the approval is never chained, and a stranger has no approval-use journal
# xfail-match: FAIL (chain_completeness|replay-local-journal)
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
ts session start --name approval --actor agent://a >/dev/null 2>&1 || fail "session start"
N=$(ts --format json attest approval --approver human://h --allowed-actor agent://a \
      --allowed-action deploy --max-uses 1 | json_field nonce) || fail "attest approval"
ts attest action --actor agent://a --action deploy --approval-nonce "$N" >/dev/null 2>&1 \
  || fail "attest action --approval-nonce"
ts session close --headline h --summary s --receipt-dir "$FLOW_DIR/r" >/dev/null 2>&1 || fail "session close"
P="$(package_in "$FLOW_DIR/r")"

as_ship stranger init --name stranger >/dev/null 2>&1 || fail "stranger init"
pin=$(as_ship stranger package verify "$P" 2>&1 | grep -Eo 'treeship trust add [^ ]+ [^ ]+ --kind [a-z_]+' | head -1)
[ -n "$pin" ] || fail "signer_trust warning printed no pin command"
eval "as_ship stranger ${pin#treeship } --yes" >/dev/null 2>&1 || fail "pin: $pin"
expect_pass as_ship stranger package verify --strict "$P"
