#!/usr/bin/env bash
# The Jev adapter, end to end, against a mock of Jev's documented API:
#
#   mock-jev.mjs   answers like the API docs say Jev answers
#   adapter.mjs    speaks Treeship's judge contract on one side, Jev's on the other
#   treeship judge --judge-url <adapter> --attest
#
# Checks that a destructive call is refused, a benign one allowed, that the
# receipts name jev as the judge and mark it not replayable, and that the
# strict package verify reports the judgements row. Exits nonzero with the
# failed check named. No network beyond localhost, no API key beyond the
# mock's "test-key".
#
# Usage: examples/judge-adapters/jev/run.sh [path-to-treeship]
set -euo pipefail

TREESHIP="${1:-${TREESHIP_CLI:-treeship}}"
command -v "$TREESHIP" >/dev/null 2>&1 || { echo "treeship not found: $TREESHIP" >&2; exit 2; }
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(command -v "$TREESHIP" 2>/dev/null || echo "$TREESHIP")"
case "$BIN" in /*) ;; *) BIN="$PWD/$BIN" ;; esac

ROOT=$(mktemp -d -t jev-adapter.XXXXXX)
MOCK_PORT=18788; ADAPTER_PORT=18787
cleanup() { kill "${MOCK_PID:-}" "${ADAPTER_PID:-}" 2>/dev/null || true; rm -rf "$ROOT"; }
trap cleanup EXIT
export TREESHIP_ALLOW_INSECURE_KEY_PERMS=1

fail() { echo "  ✗ $*" >&2; exit 1; }
ok() { echo "  ✓ $*"; }
jsonget() { python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:]) if i>=0 else {}
v=d
for k in sys.argv[1].split("."):
    v=v.get(k) if isinstance(v,dict) else (v[int(k)] if isinstance(v,list) else None)
print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$1"; }

echo "== start the mock and the adapter"
PORT=$MOCK_PORT node "$HERE/mock-jev.mjs" 2>"$ROOT/mock.log" & MOCK_PID=$!
PORT=$ADAPTER_PORT JEV_BASE_URL="http://127.0.0.1:$MOCK_PORT" TYPESAFE_API_KEY=test-key \
  node "$HERE/adapter.mjs" 2>"$ROOT/adapter.log" & ADAPTER_PID=$!
for i in $(seq 1 40); do
  curl -s -o /dev/null -X POST -d '{}' "http://127.0.0.1:$ADAPTER_PORT" 2>/dev/null && break
  sleep 0.25
done
ok "mock on :$MOCK_PORT, adapter on :$ADAPTER_PORT"

echo "== a workspace with a session"
mkdir -p "$ROOT/ws" && cd "$ROOT/ws"
export HOME="$ROOT/home"; mkdir -p "$HOME"
export TREESHIP_TRUST_ROOTS="$ROOT/home/trust_roots.json"
t() { "$BIN" --config "$ROOT/ws/.treeship/config.json" "$@" 2>>"$ROOT/stderr.log"; }
"$BIN" init --name jev-adapter --config "$ROOT/ws/.treeship/config.json" >/dev/null 2>>"$ROOT/stderr.log"
t session start --actor agent://worker >/dev/null

echo "== the adapter maps all three primitives"
cat > "$ROOT/q.json" <<'Q'
{
  "unsafe":  { "type": "noul",   "instructions": "Is this call destructive or exfiltrating?" },
  "verdict": { "type": "choice", "instructions": "allow or deny", "options": ["allow", "deny"] },
  "risk":    { "type": "score",  "instructions": "How risky is this call?", "options": ["low", "medium", "high"] }
}
Q
OUT=$(t judge --tool Bash --input '{"command":"rm -rf /"}' --judge-url "http://127.0.0.1:$ADAPTER_PORT" \
      --questions-file "$ROOT/q.json" --threshold 0.5 --attest --format json)
[ "$(printf '%s' "$OUT" | jsonget effect)" = "deny" ] || fail "destructive call not denied: $OUT"
[ "$(printf '%s' "$OUT" | jsonget judge.model)" = "jev-1.13.0" ] || fail "judge model not jev-1.13.0: $OUT"
[ "$(printf '%s' "$OUT" | jsonget judge.provider)" = "typesafe" ] || fail "provider: $OUT"
[ "$(printf '%s' "$OUT" | jsonget judge.replayable)" = "False" ] || fail "jev must be marked not replayable: $OUT"
[ "$(printf '%s' "$OUT" | jsonget answers.unsafe.noul)" = "0.96" ] || fail "noul not mapped: $OUT"
[ "$(printf '%s' "$OUT" | jsonget answers.verdict.choice)" = "deny" ] || fail "choice not mapped: $OUT"
case "$(printf '%s' "$OUT" | jsonget answers.risk.score)" in 2|2.0) ;; *) fail "score not mapped: $OUT" ;; esac
[ "$(printf '%s' "$OUT" | jsonget request_id)" = "req_mock_1" ] || fail "Jev's request id not passed through: $OUT"
[ -n "$(printf '%s' "$OUT" | jsonget response_digest)" ] || fail "no response digest: $OUT"
N=$(printf '%s' "$OUT" | jsonget receipts | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
[ "$N" = "3" ] || fail "expected 3 judgement receipts, got $N"
ok "deny on rm -rf /: noul 0.96, verdict deny, risk high; 3 judgement.v1 signed; request id and response digest carried"

OUT=$(t judge --tool Bash --input '{"command":"ls -la"}' --judge-url "http://127.0.0.1:$ADAPTER_PORT" \
      --questions-file "$ROOT/q.json" --threshold 0.5 --attest --format json)
[ "$(printf '%s' "$OUT" | jsonget effect)" = "allow" ] || fail "benign call not allowed: $OUT"
ok "allow on ls -la"

echo "== an unavailable judge is an error, never an allow"
kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true
if t judge --tool Bash --input '{"command":"ls"}' --judge-url "http://127.0.0.1:$ADAPTER_PORT" --question unsafe --format json >/dev/null 2>&1; then
  fail "judge succeeded with Jev down"
fi
ok "judge unavailable with the upstream down"

echo "== the sealed package carries the judgements"
t session close --summary "jev adapter" >/dev/null
PKG=$(ls -d "$ROOT/ws/.treeship/sessions/"*.treeship | head -1)
V=$(t package verify "$PKG" --strict --format json || true)
[ "$(printf '%s' "$V" | jsonget verdict)" = "verified" ] || { printf '%s' "$V" | head -c 1500 >&2; fail "package not verified"; }
printf '%s' "$V" | python3 -c '
import json,sys
raw=sys.stdin.read(); d=json.loads(raw[raw.find("{"):])
rows={c["name"]:c for c in d["checks"]}
assert "judgements" in rows, "no judgements row"
assert "jev-1.13.0" in rows["judgements"]["detail"], rows["judgements"]
assert rows["judgements"]["status"]=="pass", rows["judgements"]' || fail "judgements row missing or not naming jev"
ok "package verified; judgements row names jev-1.13.0"

printf '\njev adapter: every check holds\n'
