#!/usr/bin/env bash
# tests/flows/run.sh -- T1 honest-flow conformance suite.
#
# Every documented workflow runs end to end against the CLI and must verify.
# An honest flow that fails verification is a P0: a verifier that cries wolf
# trains people to ignore it.
#
#   bash tests/flows/run.sh [treeship-binary] [flow-name ...]
#
# A flow that is known to fail on main carries a header line
#
#   # xfail: W1-1 <why>
#
# naming the fix-plan task that repairs it. The runner reports it as XFAIL and
# stays green. When that flow starts passing the runner FAILS with XPASS, so
# the fixing PR has to delete the xfail line in the same change: the gate
# cannot be left pointing at a bug that is gone.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export TREESHIP_CLI="${1:-${TREESHIP_CLI:-$ROOT/target/debug/treeship}}"
shift || true
[ -x "$TREESHIP_CLI" ] || { echo "treeship binary not found: $TREESHIP_CLI" >&2; exit 2; }
TREESHIP_CLI="$(cd "$(dirname "$TREESHIP_CLI")" && pwd)/$(basename "$TREESHIP_CLI")"

flows=()
if [ $# -gt 0 ]; then
  for n in "$@"; do flows+=("$ROOT/tests/flows/${n%.sh}.sh"); done
else
  for f in "$ROOT"/tests/flows/*.sh; do
    case "$(basename "$f")" in lib.sh|run.sh) continue ;; esac
    flows+=("$f")
  done
fi

pass=0; xfail=0; bad=()
for f in "${flows[@]}"; do
  name="$(basename "$f" .sh)"
  xf="$(sed -n 's/^# xfail: *//p' "$f" | head -1)"
  log="$(mktemp)"
  if bash "$f" >"$log" 2>&1; then rc=0; else rc=$?; fi
  if [ -z "$xf" ] && [ $rc -eq 0 ]; then
    echo "PASS   $name"; pass=$((pass + 1))
  elif [ -z "$xf" ]; then
    echo "FAIL   $name"; sed 's/^/       /' "$log"; bad+=("$name")
  elif [ $rc -ne 0 ]; then
    echo "XFAIL  $name  ($xf)"; xfail=$((xfail + 1))
  else
    echo "XPASS  $name  -- passes now; delete its '# xfail: $xf' line"; bad+=("$name")
  fi
  rm -f "$log"
done

echo
echo "flows: $pass passed, $xfail expected failures, ${#bad[@]} broken"
[ ${#bad[@]} -eq 0 ]
