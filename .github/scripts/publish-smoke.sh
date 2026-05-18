#!/usr/bin/env bash
# Post-publish smoke: install treeship from npm and treeship-sdk from PyPI
# the way real users do, then run init → session start → wrap → close → report.
#
# The release workflow's `smoke` job mounts the GitHub Release binary
# directly into containers. This script catches wrapper/optional-dep,
# postinstall, and PyPI bootstrap/checksum failures that only show up
# when installing from the registries.
#
# Usage: publish-smoke.sh <version>   # e.g. 0.10.3 (no leading v)

set -euo pipefail

VERSION="${1:?usage: $0 <version>}"
WORKROOT="$(mktemp -d)"

assert_cli_version() {
  local label="$1"
  local out="$2"
  if ! printf '%s' "$out" | grep -Fq "$VERSION"; then
    echo "::error::${label}: expected version ${VERSION} in output, got: ${out}"
    exit 1
  fi
}

session_roundtrip() {
  local label="$1"
  local workdir="$2"
  mkdir -p "$workdir"
  cd "$workdir"
  rm -rf .treeship
  echo "--- ${label}: init"
  treeship init
  echo "--- ${label}: session start"
  treeship session start --name "publish-smoke-${label}"
  echo "--- ${label}: wrap"
  treeship wrap -- echo "publish-smoke-${label}"
  echo "--- ${label}: session close"
  treeship session close
  echo "--- ${label}: session report"
  REPORT_JSON="$(treeship session report --no-upload --format json)"
  python3 - <<'PY' "$REPORT_JSON" "$VERSION" "$label"
import json, sys
report, version, label = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(report)
schema = data.get("schema")
status = data.get("verification_status")
if schema != "treeship/share-result/v1":
    raise SystemExit(f"::error::{label}: unexpected schema {schema!r}")
if status != "pass":
    raise SystemExit(f"::error::{label}: verification_status={status!r}")
print(f"  ✓ {label}: session report schema={schema} verification_status={status}")
PY
}

echo "=== publish-smoke ${VERSION} (workroot=${WORKROOT}) ==="

# ---------------------------------------------------------------------------
# npm: treeship@VERSION (global install, linux x86_64 optional dep)
# ---------------------------------------------------------------------------
export HOME="${WORKROOT}/home-npm"
mkdir -p "$HOME"
NPM_PREFIX="${WORKROOT}/npm-global"
export NPM_CONFIG_PREFIX="$NPM_PREFIX"
export PATH="${NPM_PREFIX}/bin:${PATH}"

echo "--- npm install -g treeship@${VERSION}"
npm install -g "treeship@${VERSION}"

if ! command -v treeship >/dev/null 2>&1; then
  echo "::error::npm: treeship not on PATH after global install (prefix=${NPM_PREFIX})"
  exit 1
fi

NPM_VERSION_OUT="$(treeship --version)"
echo "  ${NPM_VERSION_OUT}"
assert_cli_version "npm" "$NPM_VERSION_OUT"
session_roundtrip "npm" "${WORKROOT}/work-npm"

# ---------------------------------------------------------------------------
# PyPI: treeship-sdk==VERSION → bootstrap CLI → same session round-trip
# ---------------------------------------------------------------------------
export HOME="${WORKROOT}/home-pypi"
mkdir -p "$HOME"
PY_VENV="${WORKROOT}/venv"
export PATH="/usr/bin:/bin"
python3 -m venv "$PY_VENV"
# shellcheck source=/dev/null
source "${PY_VENV}/bin/activate"

echo "--- pip install treeship-sdk==${VERSION}"
pip install --no-cache-dir "treeship-sdk==${VERSION}"

SDK_VER="$(python -c "import treeship_sdk; print(treeship_sdk.__version__)")"
if [ "$SDK_VER" != "$VERSION" ]; then
  echo "::error::pypi: treeship-sdk version ${SDK_VER} != ${VERSION}"
  exit 1
fi
echo "  ✓ treeship-sdk ${SDK_VER}"

if command -v treeship >/dev/null 2>&1; then
  echo "::error::pypi: treeship unexpectedly on PATH before bootstrap (would mask bootstrap)"
  exit 1
fi

echo "--- python -m treeship_sdk.bootstrap_cli"
BOOT_JSON="$(python -m treeship_sdk.bootstrap_cli --json)"
python3 - <<'PY' "$BOOT_JSON" "$VERSION"
import json, sys
data = json.loads(sys.argv[1])
version = sys.argv[2]
if not data.get("ok"):
    raise SystemExit(f"::error::pypi bootstrap failed: {data!r}")
if version not in data.get("version", ""):
    raise SystemExit(f"::error::pypi bootstrap version {data.get('version')!r} != {version}")
if data.get("source") not in ("github-release", "cache", "path", "npm"):
    raise SystemExit(f"::error::pypi bootstrap unexpected source: {data.get('source')!r}")
print(f"  ✓ bootstrap ok source={data.get('source')} binary={data.get('binary')}")
PY

BIN="$(python3 -c "import json,sys; print(json.load(sys.stdin)['binary'])" <<<"$BOOT_JSON")"
export PATH="$(dirname "$BIN"):${PATH}"

PYPI_VERSION_OUT="$(treeship --version)"
echo "  ${PYPI_VERSION_OUT}"
assert_cli_version "pypi" "$PYPI_VERSION_OUT"
session_roundtrip "pypi" "${WORKROOT}/work-pypi"

echo "=== publish-smoke ${VERSION} OK ==="
