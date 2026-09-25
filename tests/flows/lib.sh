# tests/flows/lib.sh -- shared harness for the T1 honest-flow suite.
#
# Sourced by every flow. Each flow runs in its own temp dir with its own
# HOME and TREESHIP_CONFIG, so nothing reads or writes the real ~/.treeship
# and no flow sees another's keys. Nothing here talks to a network hub.
#
# A flow is a plain bash script: it calls `ts` (the CLI under test) and the
# expect_* helpers, and exits nonzero on the first broken expectation.

set -uo pipefail

: "${TREESHIP_CLI:?set TREESHIP_CLI to the treeship binary under test}"

FLOW_DIR="$(mktemp -d "${TMPDIR:-/tmp}/treeship-flow.XXXXXX")"
export HOME="$FLOW_DIR/home"
export TREESHIP_CONFIG="$HOME/.treeship/config.json"
mkdir -p "$HOME" "$FLOW_DIR/work"
cd "$FLOW_DIR/work" || exit 2
trap 'rm -rf "$FLOW_DIR"' EXIT

ts() { "$TREESHIP_CLI" "$@"; }

# A second, independent ship in the same flow (its own HOME and keys), for
# flows with more than one party. Usage: as_ship <name> <treeship args...>
as_ship() {
  local name="$1"; shift
  local h="$FLOW_DIR/ships/$name"
  mkdir -p "$h/work"
  (export HOME="$h" TREESHIP_CONFIG="$h/.treeship/config.json"; cd "$h/work" && "$TREESHIP_CLI" "$@")
}

fail() { echo "FLOW FAIL: $*" >&2; exit 1; }

# json_field <field> reads one top-level field from JSON on stdin.
json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

# expect_pass <cmd...>: the command exits 0. Its output is shown on failure.
expect_pass() {
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -ne 0 ]; then
    printf '%s\n' "$out" >&2
    fail "expected exit 0, got $rc: $*"
  fi
}

# expect_fail <cmd...>: the command exits nonzero.
expect_fail() {
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    printf '%s\n' "$out" >&2
    fail "expected a nonzero exit, got 0: $*"
  fi
}

# expect_output <regex> <cmd...>: the command's combined output matches.
expect_output() {
  local re="$1"; shift
  local out
  out="$("$@" 2>&1)"
  if ! printf '%s\n' "$out" | grep -Eq -- "$re"; then
    printf '%s\n' "$out" >&2
    fail "output did not match /$re/: $*"
  fi
}

# The single package a `session close --receipt-dir <dir>` wrote.
package_in() {
  local p
  p="$(ls -d "$1"/*.treeship 2>/dev/null | head -1)"
  [ -n "$p" ] || fail "no .treeship package in $1"
  printf '%s\n' "$p"
}
