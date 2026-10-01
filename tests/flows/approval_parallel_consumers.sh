#!/usr/bin/env bash
# Parallel consumers of one multi-use approval queue on the approval-use
# journal lock instead of failing "lock busy". An 8-use approval and 8
# concurrent `attest action` calls: all 8 sign, and a 9th is refused.
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
N=$(ts --format json attest approval --approver human://h --allowed-actor agent://a \
      --allowed-action deploy --max-uses 8 | json_field nonce) || fail "attest approval"

pids=()
for i in 1 2 3 4 5 6 7 8; do
  ts attest action --actor agent://a --action deploy --approval-nonce "$N" \
    >"$FLOW_DIR/c$i.out" 2>&1 &
  pids+=("$!")
done
ok=0
for i in "${!pids[@]}"; do
  if wait "${pids[$i]}"; then ok=$((ok + 1)); else sed 's/^/  /' "$FLOW_DIR/c$((i + 1)).out" >&2; fi
done
[ "$ok" -eq 8 ] || fail "expected 8 of 8 parallel consumers to sign, got $ok"
if grep -l 'lock busy' "$FLOW_DIR"/c*.out >/dev/null 2>&1; then fail "a consumer reported lock busy"; fi

expect_fail ts attest action --actor agent://a --action deploy --approval-nonce "$N"
