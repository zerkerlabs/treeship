#!/usr/bin/env bash
# Cross-SDK contract orchestrator.
#
#   1. Generate a fresh corpus (gen-vectors.sh).
#   2. Run the TS runner; capture JSON-line output.
#   3. Run the Python runner; capture JSON-line output.
#   4. Diff outcomes per vector. Any mismatch is a contract bug.
#
# Exits 0 only when both runners verified every vector with the
# corpus-declared expected outcome AND both runners agreed with each other
# on every vector.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 1. Always build the debug CLI (incremental; <1s when nothing changed).
# This is what the runners pick up. Skipping the build would let a stale
# binary mask a regression in the very code path the suite exists to
# guard. Set TREESHIP_SKIP_BUILD=1 to opt out (CI release smoke does this
# after building once for the whole job).
if [[ -z "${TREESHIP_SKIP_BUILD:-}" ]]; then
  echo "==> building treeship CLI (debug, incremental)" >&2
  (cd "$REPO_ROOT" && cargo build --bin treeship)
fi

# 2. Build the TypeScript SDK if its dist/ is missing or older than src/.
# The runner imports from packages/sdk-ts/dist/ (real .js, full module
# resolution); building on demand here means a developer who hasn't
# touched the SDK in a while still gets a green run.
SDK_TS_DIR="$REPO_ROOT/packages/sdk-ts"
if [[ ! -f "$SDK_TS_DIR/dist/index.js" ]] || [[ -n "$(find "$SDK_TS_DIR/src" -newer "$SDK_TS_DIR/dist/index.js" -type f 2>/dev/null | head -1)" ]]; then
  echo "==> building TS SDK" >&2
  (cd "$SDK_TS_DIR" && npm install --no-audit --no-fund --silent && npm run build --silent)
fi

# 3. Generate corpus.
echo "==> generating test vectors" >&2
"$SCRIPT_DIR/gen-vectors.sh"

TS_OUT="$SCRIPT_DIR/.ts-output.jsonl"
PY_OUT="$SCRIPT_DIR/.py-output.jsonl"

# 3. Run TS. tsx (or ts-node) ships nothing in this repo by design --
# we rely on the developer having one available, same as the SDK's own
# build pipeline. Fall back to tsc + node if nothing else works.
echo "==> running TS runner" >&2
ts_status=0
if command -v tsx >/dev/null 2>&1; then
  tsx "$SCRIPT_DIR/verify-vectors.ts" > "$TS_OUT" || ts_status=$?
elif command -v node >/dev/null 2>&1 && node --version | grep -qE 'v(2[0-9]|[3-9][0-9])\.'; then
  # Node 22+ can run TS files directly with --experimental-strip-types.
  node --experimental-strip-types --no-warnings "$SCRIPT_DIR/verify-vectors.ts" > "$TS_OUT" || ts_status=$?
else
  echo "no TS runner available (need tsx or Node 22+)" >&2
  exit 2
fi

# 4. Run Python.
echo "==> running Python runner" >&2
py_status=0
python3 "$SCRIPT_DIR/verify_vectors.py" > "$PY_OUT" || py_status=$?

# 5. Print both outputs side-by-side for the human.
echo "" >&2
echo "==> TS output:" >&2
cat "$TS_OUT" >&2 || true
echo "" >&2
echo "==> PY output:" >&2
cat "$PY_OUT" >&2 || true
echo "" >&2

# 6. Diff outcome per vector. Both runners emit one JSON line per vector
# in corpus order, so a per-line key match is sufficient.
echo "==> contract check" >&2
divergence_status=0
divergences="$(
  python3 - "$TS_OUT" "$PY_OUT" <<'PY'
import json, sys
ts = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
py = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
ts_by_name = {r["name"]: r for r in ts}
py_by_name = {r["name"]: r for r in py}
all_names = sorted(set(ts_by_name) | set(py_by_name))
divs = []
for name in all_names:
    t = ts_by_name.get(name)
    p = py_by_name.get(name)
    if t is None:
        divs.append((name, "missing in ts", "", ""))
        continue
    if p is None:
        divs.append((name, "missing in py", "", ""))
        continue
    if t.get("outcome") != p.get("outcome") or t.get("chain") != p.get("chain"):
        divs.append((
            name,
            "diverged",
            f'outcome={t.get("outcome")} chain={t.get("chain")}',
            f'outcome={p.get("outcome")} chain={p.get("chain")}',
        ))
for d in divs:
    print("\t".join(d))
sys.exit(0 if not divs else 1)
PY
)" || divergence_status=$?

if [[ $divergence_status -eq 0 && $ts_status -eq 0 && $py_status -eq 0 ]]; then
  echo "  ok -- TS and Python agree on every vector and both met expectations" >&2
  exit 0
fi

echo "  CONTRACT FAILED" >&2
if [[ -n "$divergences" ]]; then
  echo "$divergences" >&2 | sed 's/^/    /'
fi
if [[ $ts_status -ne 0 ]]; then
  echo "    TS runner exit=$ts_status (some vector did not match expected_outcome)" >&2
fi
if [[ $py_status -ne 0 ]]; then
  echo "    Python runner exit=$py_status (some vector did not match expected_outcome)" >&2
fi
exit 1
