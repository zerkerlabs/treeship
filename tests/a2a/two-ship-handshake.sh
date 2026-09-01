#!/usr/bin/env bash
# Two-ship A2A handshake acceptance.
#
# The unit tests around `gate.ts` mock the CLI, so they prove the gate's
# DECISIONS but not that the underlying handshake refuses anything. This runs
# the real thing: two isolated ships, real keys, real Merkle staples, and the
# three cases that decide whether the gate is worth having.
#
#   1. Receiver has NOT pinned the sender's cert_issuer  -> refuse (exit 1)
#   2. Receiver pinned it, sender answers the live nonce -> accept (exit 0)
#   3. Same presentation replayed against a DIFFERENT nonce -> refuse (exit 1)
#   4. `attest handoff --verified` on the live presentation -> custody: live,
#      and `verify` grades it live from the signed evidence
#   5. `attest handoff --verified` on the replayed presentation -> refuses to
#      mint, writes nothing (the same decision as case 3, one command later)
#   6. `attest handoff` with no verification -> custody: asserted, and
#      `verify` says so rather than staying silent
#
# Isolation needs BOTH `HOME` and `TREESHIP_CONFIG`. `TREESHIP_HOME` does not
# move the ship (it is the rig ledger's variable), and `--config` alone leaves
# the two ships sharing ~/.treeship/merkle/checkpoints, which makes `present`
# fail with a checkpoint that describes the other store.
set -euo pipefail

BIN="${TREESHIP_BIN:-treeship}"
if ! command -v "$BIN" >/dev/null 2>&1 && [ ! -x "$BIN" ]; then
  echo "SKIP: treeship binary not found (set TREESHIP_BIN)" >&2
  exit 0
fi

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/G" "$ROOT/C"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok: $*"; }

# Run the CLI as one ship. Every invocation is explicit about which ship it is;
# there is no ambient "current ship" in this harness on purpose.
as_ship() {
  local ship="$1"; shift
  ( cd "$ROOT/$ship" && HOME="$ROOT/$ship" TREESHIP_CONFIG="$ROOT/$ship/config.json" "$BIN" "$@" )
}

echo "== provision two isolated ships =="
as_ship G init --quiet >/dev/null
as_ship C init --quiet >/dev/null
as_ship G onboard grok --tools "a2a.*" --format json >/dev/null
as_ship G checkpoint --format json >/dev/null
pass "G onboarded agent://grok, checkpoint sealed"

NONCE="$(as_ship C session mint-challenge --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
[ "${#NONCE}" -ge 32 ] || fail "receiver minted a nonce shorter than 32 chars: ${#NONCE}"
pass "C minted a ${#NONCE}-char nonce"

as_ship G present agent://grok --challenge "$NONCE" --format json >/dev/null
PRESENTATION="$(find "$ROOT/G" -name '*.presentation.json' | head -1)"
[ -n "$PRESENTATION" ] || fail "G produced no presentation file"
pass "G presented against C's nonce"

# --- 1. no pin ---------------------------------------------------------------
echo "== 1. unpinned issuer must refuse =="
set +e
as_ship C verify-presentation "$PRESENTATION" --challenge "$NONCE" --format json > "$ROOT/unpinned.json" 2>&1
UNPINNED_EXIT=$?
set -e
[ "$UNPINNED_EXIT" -ne 0 ] || fail "unpinned issuer verified (exit 0). A verifier that returns Ok for the wrong reason is the bug this repo exists to prevent."
python3 - "$ROOT/unpinned.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("ok") is not True, "ok must not be true for an unpinned issuer"
assert d.get("key_bound") is not True, "key_bound must not be true without a pin"
PY
pass "refused, and key_bound is false (the cause), even though the verdict says CHALLENGE FAILED"

# --- 2. pinned + live nonce --------------------------------------------------
echo "== 2. pinned issuer with a live nonce must accept =="
PIN_LINE="$(as_ship G keys export | grep -E 'trust add .* --kind cert_issuer' | head -1)"
# Parse by pattern, not field offset: `keys export` indents its lines, which
# silently shifts every positional field by one.
KEY_ID="$(echo "$PIN_LINE" | grep -oE 'key_[a-f0-9]+' | head -1)"
PUBKEY="$(echo "$PIN_LINE" | grep -oE 'ed25519:[A-Za-z0-9+/=_-]+' | head -1)"
[ -n "$KEY_ID" ] && [ -n "$PUBKEY" ] || fail "could not parse G's trust-add line: $PIN_LINE"
as_ship C trust add "$KEY_ID" "$PUBKEY" --kind cert_issuer --yes >/dev/null
as_ship C trust add "$KEY_ID" "$PUBKEY" --kind hub_checkpoint --yes >/dev/null
as_ship C verify-presentation "$PRESENTATION" --challenge "$NONCE" --format json > "$ROOT/accepted.json"
python3 - "$ROOT/accepted.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("ok") is True, f"expected ok=true, got {d.get('ok')}"
assert d.get("key_bound") is True, "expected key_bound=true once the issuer is pinned"
assert d.get("challenge_ok") is True, "expected the live challenge to verify"
PY
pass "accepted: key-bound, live challenge verified"

# --- 3. replay ---------------------------------------------------------------
echo "== 3. the same presentation against a different nonce must refuse =="
OTHER_NONCE="$(as_ship C session mint-challenge --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["nonce"])')"
[ "$OTHER_NONCE" != "$NONCE" ] || fail "mint-challenge returned the same nonce twice"
set +e
as_ship C verify-presentation "$PRESENTATION" --challenge "$OTHER_NONCE" --format json > "$ROOT/replayed.json" 2>&1
REPLAY_EXIT=$?
set -e
[ "$REPLAY_EXIT" -ne 0 ] || fail "a presentation answering a different challenge was accepted — replay is not guarded"
python3 - "$ROOT/replayed.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("ok") is not True, "replay must not verify"
assert d.get("challenge_ok") is not True, "replay must fail the challenge specifically"
# The pin still holds, so this one IS genuinely a challenge failure rather
# than a trust failure. That distinction is what gate.ts classifies on.
assert d.get("key_bound") is True, "the card is still key-bound; only the nonce is wrong"
PY
pass "refused as a challenge failure, with the card still key-bound"

# --- 4. verified handoff -----------------------------------------------------
echo "== 4. a handoff that records the live verify must grade live =="
INTENT="$(as_ship C attest action --actor agent://claude --action a2a.task.intent --format json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d.get("artifact_id"))')"
[ -n "$INTENT" ] && [ "$INTENT" != "None" ] || fail "C could not attest an intent artifact"
as_ship C attest handoff --from agent://grok --to agent://claude --artifacts "$INTENT" \
  --verified "$PRESENTATION" --challenge "$NONCE" --format json > "$ROOT/handoff-live.json"
HANDOFF="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("id") or d.get("artifact_id"))' "$ROOT/handoff-live.json")"
[ -n "$HANDOFF" ] && [ "$HANDOFF" != "None" ] || fail "attest handoff --verified produced no artifact id"
as_ship C verify "$HANDOFF" --format json > "$ROOT/verify-live.json"
DIGEST="sha256:$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$PRESENTATION")"
python3 - "$ROOT/verify-live.json" "$HANDOFF" "$DIGEST" "$NONCE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); hid, digest, nonce = sys.argv[2:5]
assert d.get("outcome") == "pass", f"handoff chain must verify, got {d.get('outcome')}"
c = next(c for c in d["checks"] if c["id"] == hid)
cu = c["custody"]
assert cu["live"] is True, f"expected the verifier to grade custody live, got {cu}"
assert cu["presentation_digest"] == digest, "the signed digest must be of the exact presentation bytes"
assert cu["challenge"] == nonce, "the signed challenge must be the nonce C minted"
assert cu["verifier"] == "agent://claude", "the receiver is the verifier"
PY
pass "custody: live, bound to the presentation digest and C's nonce"

# --- 5. verified handoff on a replay -----------------------------------------
echo "== 5. a handoff must refuse to record live custody from a replayed presentation =="
set +e
as_ship C attest handoff --from agent://grok --to agent://claude --artifacts "$INTENT" \
  --verified "$PRESENTATION" --challenge "$OTHER_NONCE" --format json > "$ROOT/handoff-replay.json" 2>&1
REPLAY_HANDOFF_EXIT=$?
set -e
[ "$REPLAY_HANDOFF_EXIT" -ne 0 ] || fail "attest handoff recorded custody: live from a presentation that answers a different nonce"
grep -q "custody: live was NOT recorded" "$ROOT/handoff-replay.json" || fail "refusal did not say that live custody was not recorded: $(cat "$ROOT/handoff-replay.json")"
pass "refused; no handoff written"

# --- 6. unverified handoff ---------------------------------------------------
echo "== 6. a handoff with no verification must be graded asserted, out loud =="
PLAIN="$(as_ship C attest handoff --from agent://grok --to agent://claude --artifacts "$INTENT" --format json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d.get("artifact_id"))')"
as_ship C verify "$PLAIN" --format json > "$ROOT/verify-plain.json"
python3 - "$ROOT/verify-plain.json" "$PLAIN" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); hid = sys.argv[2]
c = next(c for c in d["checks"] if c["id"] == hid)
assert c["custody"]["live"] is False
assert c["custody"]["grade"] is None
assert "no verification recorded" in c["custody"]["detail"], c["custody"]
PY
pass "custody: asserted (no verification recorded)"

echo
echo "PASS: two-ship handshake refuses an unpinned issuer and a replayed nonce, accepts a live one, and the handoff records only what verified."
