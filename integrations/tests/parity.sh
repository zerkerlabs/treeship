#!/bin/sh
# Integration parity test runner.
# Usage:
#   integrations/tests/parity.sh                 # all plugins
#   integrations/tests/parity.sh kimi-code-plugin  # one plugin

set -e

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
INTEGRATIONS_DIR=$(cd "$TESTS_DIR/.." && pwd)
FIXTURES_DIR="$TESTS_DIR/fixtures"
EXPECT_DIR="$TESTS_DIR/expectations"
MOCK_SCRIPT="$TESTS_DIR/lib/mock-treeship.sh"

[ -f "$MOCK_SCRIPT" ] || { echo "error: mock-treeship.sh not found" >&2; exit 2; }

FILTER="${1:-}"
PASS=0
FAIL=0
FAILED_TESTS=""

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

MOCK_BIN_DIR="$WORKDIR/bin"
mkdir -p "$MOCK_BIN_DIR"
cp "$MOCK_SCRIPT" "$MOCK_BIN_DIR/treeship"
chmod +x "$MOCK_BIN_DIR/treeship"
mkdir -p "$WORKDIR/proj/.treeship"

script_for_fixture() {
  base="$1"
  candidate="$base"
  while [ -n "$candidate" ]; do
    if [ -f "$PLUGIN_SCRIPTS/$candidate.sh" ]; then
      printf '%s.sh' "$candidate"
      return 0
    fi
    case "$candidate" in
      *-*) candidate="${candidate%-*}" ;;
      *)   break ;;
    esac
  done
  return 1
}

run_test() {
  fixture="$1"
  expected="$2"
  basename=$(basename "$fixture" .json)
  script_name=$(script_for_fixture "$basename") || {
    echo "  SKIP  $basename (no matching hook script)"
    return
  }
  script_path="$PLUGIN_SCRIPTS/$script_name"
  LOG="$WORKDIR/calls-$basename.log"
  : > "$LOG"

  PATH="$MOCK_BIN_DIR:$PATH" \
  MOCK_TREESHIP_LOG="$LOG" \
  TREESHIP_PROJECT_ROOT="$WORKDIR/proj" \
  HOME="$WORKDIR" \
  sh "$script_path" < "$fixture" > "$WORKDIR/stdout-$basename" 2>&1 || true

  if diff -u "$expected" "$LOG" > "$WORKDIR/diff-$basename" 2>&1; then
    echo "  PASS  $basename"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $basename"
    sed 's/^/        /' "$WORKDIR/diff-$basename"
    FAIL=$((FAIL + 1))
    FAILED_TESTS="$FAILED_TESTS $PLUGIN_NAME/$basename"
  fi
}

run_plugin() {
  PLUGIN_NAME="$1"
  echo ""
  echo "=== $PLUGIN_NAME ==="
  PLUGIN_SCRIPTS="$INTEGRATIONS_DIR/$PLUGIN_NAME/scripts"
  if [ ! -d "$PLUGIN_SCRIPTS" ]; then
    echo "  ERROR scripts dir not found: $PLUGIN_SCRIPTS"
    FAIL=$((FAIL + 1))
    return
  fi
  FIX_DIR="$FIXTURES_DIR/$PLUGIN_NAME"
  EXP_DIR="$EXPECT_DIR/$PLUGIN_NAME"
  if [ ! -d "$FIX_DIR" ]; then
    echo "  no fixtures (skipping)"
    return
  fi
  for fixture in "$FIX_DIR"/*.json; do
    [ -f "$fixture" ] || continue
    basename=$(basename "$fixture" .json)
    expected="$EXP_DIR/$basename.txt"
    if [ ! -f "$expected" ]; then
      echo "  FAIL  $basename (no expectations file)"
      FAIL=$((FAIL + 1))
      FAILED_TESTS="$FAILED_TESTS $PLUGIN_NAME/$basename"
      continue
    fi
    run_test "$fixture" "$expected"
  done
}

if [ -n "$FILTER" ]; then
  run_plugin "$FILTER"
else
  for plugin_fix in "$FIXTURES_DIR"/*/; do
    [ -d "$plugin_fix" ] || continue
    plugin=$(basename "$plugin_fix")
    run_plugin "$plugin"
  done
fi

echo ""
echo "================================================================"
echo " Parity test summary: $PASS passed, $FAIL failed"
echo "================================================================"
if [ "$FAIL" -gt 0 ]; then
  echo " Failed tests:$FAILED_TESTS"
  exit 1
fi
exit 0
