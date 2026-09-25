#!/usr/bin/env bash
# tests/flows/run.sh -- T1 honest-flow conformance suite.
#
# Every documented workflow runs end to end against the CLI and must verify.
# An honest flow that fails verification is a P0: a verifier that cries wolf
# trains people to ignore it.
#
#   bash tests/flows/run.sh [treeship-binary] [flow-name ...]
#
# A flow that is known to fail on main carries two header lines
#
#   # xfail: W1-1 <why>
#   # xfail-match: <extended regex the failing output must match>
#
# naming the fix-plan task that repairs it and how it fails today. The runner
# reports XFAIL and stays green only while the flow fails THAT way; failing
# any other way (a setup step breaking, a different verdict) is a FAIL. When
# the flow starts passing the runner fails with XPASS, so the fixing PR has
# to delete both lines in the same change: the gate cannot be left pointing
# at a bug that is gone.

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
  xm="$(sed -n 's/^# xfail-match: *//p' "$f" | head -1)"
  if [ -n "$xf" ] && [ -z "$xm" ]; then
    echo "FAIL   $name: '# xfail:' without '# xfail-match:'"; bad+=("$name"); continue
  fi
  log="$(mktemp)"
  if bash "$f" >"$log" 2>&1; then rc=0; else rc=$?; fi
  if [ -z "$xf" ] && [ $rc -eq 0 ]; then
    echo "PASS   $name"; pass=$((pass + 1))
  elif [ -z "$xf" ]; then
    echo "FAIL   $name"; sed 's/^/       /' "$log"; bad+=("$name")
  elif [ $rc -ne 0 ] && grep -Eq -- "$xm" "$log"; then
    echo "XFAIL  $name  ($xf)"; xfail=$((xfail + 1))
  elif [ $rc -ne 0 ]; then
    echo "FAIL   $name: failed, but not the known way (/$xm/)"; sed 's/^/       /' "$log"; bad+=("$name")
  else
    echo "XPASS  $name  -- passes now; delete its '# xfail:' and '# xfail-match:' lines ($xf)"; bad+=("$name")
  fi
  rm -f "$log"
done

echo
echo "flows: $pass passed, $xfail expected failures, ${#bad[@]} broken"
[ ${#bad[@]} -eq 0 ]
