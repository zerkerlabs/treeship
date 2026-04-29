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

# 2. Build the TypeScript SDK against the workspace's @treeship/core-wasm,
# not the npm registry copy. During cutover PRs (e.g. v0.9.7), the SDK's
# package.json declares the *next* core-wasm version which has not yet
# been published; resolving that from npm gives ETARGET. The contract
# suite's job is to verify the workspace, not yesterday's published
# graph, so we build core-wasm locally and install it into the SDK as
# a file: tarball before npm install.
#
# Original package.json + package-lock.json are restored on EXIT so
# local invocations leave the working tree clean.
SDK_TS_DIR="$REPO_ROOT/packages/sdk-ts"
CORE_WASM_DIR="$REPO_ROOT/packages/core-wasm"
CORE_WASM_PKG_DIR="$CORE_WASM_DIR/pkg"
TARBALL_DIR="$REPO_ROOT/target/cross-sdk-npm"

if ! command -v wasm-pack >/dev/null 2>&1; then
  cat >&2 <<'EOF'
::error::wasm-pack not found. Cross-SDK builds @treeship/core-wasm from
source and needs wasm-pack on PATH. Install with:
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
or:
  cargo install wasm-pack --locked
EOF
  exit 3
fi

# Determine the version from the SDK manifest -- this is the version
# pyproject/Cargo/package.json all agree on after `release.sh prepare`,
# which is the version we're testing here. Strip any leading semver
# prefix (^, ~, =, v) so build-npm.sh receives a clean version.
CORE_WASM_VERSION="$(node -p "require('$SDK_TS_DIR/package.json').dependencies['@treeship/core-wasm'].replace(/^[\\^~=v]+/, '')")"

echo "==> building local @treeship/core-wasm@${CORE_WASM_VERSION}" >&2
(cd "$CORE_WASM_DIR" && bash build-npm.sh "$CORE_WASM_VERSION" >&2)

mkdir -p "$TARBALL_DIR"
echo "==> packing local @treeship/core-wasm" >&2
CORE_WASM_TGZ_NAME="$(cd "$CORE_WASM_PKG_DIR" && npm pack --pack-destination "$TARBALL_DIR" --silent)"
CORE_WASM_TGZ="$TARBALL_DIR/$CORE_WASM_TGZ_NAME"
if [[ ! -f "$CORE_WASM_TGZ" ]]; then
  echo "::error::expected tarball at $CORE_WASM_TGZ but it doesn't exist" >&2
  exit 1
fi

# Snapshot package.json + lockfile, restore on any exit. Without this, a
# Ctrl-C halfway through would leave a dev's working tree pointing at a
# file: dependency.
SDK_PKG="$SDK_TS_DIR/package.json"
SDK_LOCK="$SDK_TS_DIR/package-lock.json"
SDK_PKG_BAK="$(mktemp -t cross-sdk-pkg.XXXXXX)"
SDK_LOCK_BAK="$(mktemp -t cross-sdk-lock.XXXXXX)"
cp "$SDK_PKG" "$SDK_PKG_BAK"
if [[ -f "$SDK_LOCK" ]]; then cp "$SDK_LOCK" "$SDK_LOCK_BAK"; else : > "$SDK_LOCK_BAK"; fi
restore_sdk_manifests() {
  if [[ -f "$SDK_PKG_BAK" ]]; then mv "$SDK_PKG_BAK" "$SDK_PKG"; fi
  if [[ -s "$SDK_LOCK_BAK" ]]; then
    mv "$SDK_LOCK_BAK" "$SDK_LOCK"
  else
    rm -f "$SDK_LOCK_BAK" "$SDK_LOCK"
  fi
}
trap restore_sdk_manifests EXIT

# Rewrite the dependency to point at the local tarball, then install +
# build. Lockfile is removed so npm doesn't try to honor a registry
# resolution from a previous run.
node - "$SDK_PKG" "$CORE_WASM_TGZ" <<'NODE'
const fs = require('fs');
const [pkgPath, tgz] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
pkg.dependencies = pkg.dependencies || {};
pkg.dependencies['@treeship/core-wasm'] = `file:${tgz}`;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
NODE

echo "==> building TS SDK against local core-wasm" >&2
(cd "$SDK_TS_DIR" && rm -f package-lock.json && rm -rf node_modules/@treeship/core-wasm && npm install --no-audit --no-fund --silent && npm run build --silent)

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

phase_a_ok=true
if [[ $divergence_status -ne 0 || $ts_status -ne 0 || $py_status -ne 0 ]]; then
  phase_a_ok=false
fi

# 7. Phase B: roundtrip attest+verify across SDKs. Pulls TREESHIP_CONFIG
# from the corpus we just generated. This catches signing/format drift
# that Phase A's verify-only contract can't see -- e.g. TS produces an
# artifact that Python cannot parse.
echo "" >&2
echo "==> Phase B: roundtrip attest+verify" >&2
PHASE_B_OUT="$SCRIPT_DIR/.roundtrip-output.jsonl"
phase_b_status=0
TREESHIP_CONFIG="$(python3 -c 'import json; print(json.load(open("'"$SCRIPT_DIR/corpus.json"'"))["config_path"])')" \
  PATH="$REPO_ROOT/target/debug:$PATH" \
  "$SCRIPT_DIR/roundtrip.sh" > "$PHASE_B_OUT" 2>&1 || phase_b_status=$?
cat "$PHASE_B_OUT" >&2

if [[ "$phase_a_ok" == "true" && $phase_b_status -eq 0 ]]; then
  echo "" >&2
  echo "  ok -- Phase A (vector parity) and Phase B (roundtrip) both green" >&2
  exit 0
fi

echo "" >&2
echo "  CONTRACT FAILED" >&2
if [[ "$phase_a_ok" == "false" ]]; then
  echo "  Phase A (vector parity):" >&2
  if [[ -n "$divergences" ]]; then
    echo "$divergences" >&2 | sed 's/^/    /'
  fi
  if [[ $ts_status -ne 0 ]]; then
    echo "    TS runner exit=$ts_status (some vector did not match expected_outcome)" >&2
  fi
  if [[ $py_status -ne 0 ]]; then
    echo "    Python runner exit=$py_status (some vector did not match expected_outcome)" >&2
  fi
fi
if [[ $phase_b_status -ne 0 ]]; then
  echo "  Phase B (roundtrip): exit=$phase_b_status -- see output above" >&2
fi
exit 1
