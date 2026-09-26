#!/usr/bin/env bash
# CLI-5: the steps the CLI itself suggests -- checkpoint, merkle proof,
# merkle verify -- on a fresh ship. Before the checkpoint signer is pinned the
# verdict says "not pinned" and exits 6, not "invalid" (1); after pinning, the
# proof verifies.
. "$(dirname "$0")/lib.sh"

ts init --name flow >/dev/null 2>&1 || fail "init"
A=$(ts --format json attest action --actor agent://a --action x | json_field id) || fail "attest"
ts checkpoint >/dev/null 2>&1 || fail "checkpoint"
ts merkle proof "$A" >/dev/null 2>&1 || fail "merkle proof"
[ -f "$A.proof.json" ] || fail "merkle proof wrote no $A.proof.json"

out="$(ts merkle verify "$A.proof.json" 2>&1)"; rc=$?
printf '%s\n' "$out" | grep -qi 'not pinned' || { printf '%s\n' "$out" >&2; fail "unpinned signer not reported as 'not pinned'"; }
printf '%s\n' "$out" | grep -qi 'signature invalid' && fail "unpinned signer reported as an invalid signature"
[ $rc -eq 6 ] || fail "not-pinned must exit 6 (got $rc; 1 means invalid)"
printf '%s\n' "$out" | grep -q -- '--yes' && fail "the pin line must not carry --yes: the key comes from the checkpoint itself"

# The JSON names the key to confirm out of band. The flow stands in for a
# reader who did, and pins it; then the same proof verifies.
json="$(ts --format json merkle verify "$A.proof.json" 2>/dev/null)"
[ "$(printf '%s' "$json" | json_field outcome)" = "not_pinned" ] || fail "JSON outcome is not not_pinned: $json"
KID=$(printf '%s' "$json" | json_field key_id); PUB=$(printf '%s' "$json" | json_field public_key)
ts trust add "$KID" "ed25519:$PUB" --kind hub_checkpoint --yes >/dev/null 2>&1 || fail "pin $KID"
expect_pass ts merkle verify "$A.proof.json"
