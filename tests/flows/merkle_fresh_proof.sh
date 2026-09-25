#!/usr/bin/env bash
# CLI-5: the steps the CLI itself suggests -- checkpoint, merkle proof,
# merkle verify -- on a fresh ship. Before the checkpoint signer is pinned the
# verdict must say "not pinned" with its own exit code, not "invalid"; after
# pinning, the proof verifies.
# xfail: W1-5 merkle verify reports an unpinned checkpoint signer as an invalid signature
# xfail-match: checkpoint signature invalid
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
A=$(ts --format json attest action --actor agent://a --action x | json_field id) || fail "attest"
ts checkpoint >/dev/null 2>&1 || fail "checkpoint"
ts merkle proof "$A" >/dev/null 2>&1 || fail "merkle proof"
[ -f "$A.proof.json" ] || fail "merkle proof wrote no $A.proof.json"

out="$(ts merkle verify "$A.proof.json" 2>&1)"; rc=$?
printf '%s\n' "$out" | grep -qi 'not pinned' || { printf '%s\n' "$out" >&2; fail "unpinned signer not reported as 'not pinned'"; }
printf '%s\n' "$out" | grep -qi 'signature invalid' && fail "unpinned signer reported as an invalid signature"
[ $rc -ne 0 ] && [ $rc -ne 1 ] || fail "not-pinned must have its own exit code (got $rc; 1 means invalid)"

# Pin the command the verdict prints, then the same proof verifies.
pin="$(printf '%s\n' "$out" | grep -Eo 'treeship trust add [^;]*' | head -1)"
[ -n "$pin" ] || fail "verdict printed no 'treeship trust add' command"
eval "ts ${pin#treeship }" >/dev/null 2>&1 || fail "pin: $pin"
expect_pass ts merkle verify "$A.proof.json"
