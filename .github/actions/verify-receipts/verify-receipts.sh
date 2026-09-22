#!/usr/bin/env bash
# Verify every sealed Treeship package a pull request carries, under the
# repository's pinned roots, in strict mode. Cross-check the commits'
# Treeship-Receipt trailers against the packages' receipt digests. Write a
# step summary. Fail on any package that is not verified, and, when REQUIRE
# is true, on a PR with no packages at all.
#
# Silence is not success: a PR with zero packages says "0 packages" in the
# summary and in the log, never a bare green.
set -euo pipefail

PACKAGES="${PACKAGES:-receipts/**/*.treeship}"
TRUST_ROOTS="${TRUST_ROOTS:-receipts/trust_roots.json}"
REQUIRE="${REQUIRE:-false}"
BASE_REF="${BASE_REF:-}"
HEAD_REF="${HEAD_REF:-HEAD}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [ ! -f "$TRUST_ROOTS" ]; then
  echo "::error::pinned trust roots not found at $TRUST_ROOTS; commit the producing ship's public key there (kind session_host)"
  exit 1
fi
# A fresh HOME so nothing from the runner's user leaks into the verdict, and
# a private (mode 600) copy of the pinned roots: treeship refuses a trust
# store other users can write, and a git checkout is mode 644.
export HOME="${RUNNER_TEMP:-/tmp}/treeship-home"
mkdir -p "$HOME"
cp "$TRUST_ROOTS" "$HOME/trust_roots.json"
chmod 600 "$HOME/trust_roots.json"
export TREESHIP_TRUST_ROOTS="$HOME/trust_roots.json"

# Glob expansion in python so `**` works on bash 3 (macOS) and bash 5 alike.
pkgs=()
while IFS= read -r p; do
  [ -n "$p" ] && [ -d "$p" ] && [ -f "$p/receipt.json" ] && pkgs+=("$p")
done < <(python3 -c 'import glob,sys
for p in sorted(glob.glob(sys.argv[1], recursive=True)): print(p)' "$PACKAGES")

# Trailers on the PR's commits: "Treeship-Receipt: <session_id> sha256:<hex>".
# Kept in a file (session id, digest per line) so the script runs on bash 3.
TRAILERS="${RUNNER_TEMP:-/tmp}/treeship-trailers.txt"
if [ -n "$BASE_REF" ] && git rev-parse --verify -q "$BASE_REF" >/dev/null 2>&1; then
  range="$BASE_REF..$HEAD_REF"
else
  range="-1 $HEAD_REF"
fi
git log $range --format=%B 2>/dev/null | awk '/^Treeship-Receipt: / && NF>=3 {print $2, $3}' > "$TRAILERS" || true
trailer_for() { awk -v s="$1" '$1==s {print $2; exit}' "$TRAILERS"; }

{
  echo "## Treeship receipts"
  echo
  echo "| package | verdict | signer pinned | passed | failed | warnings | trailer |"
  echo "|---|---|---|---|---|---|---|"
} >> "$SUMMARY"

fail=0
for p in ${pkgs[@]+"${pkgs[@]}"}; do
  errfile="${RUNNER_TEMP:-/tmp}/treeship-verify-err.txt"
  out=$(treeship package verify "$p" --strict --format json 2>"$errfile" || true)
  verdict=$(printf '%s' "$out" | python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{")
try:
  d=json.loads(raw[i:]) if i>=0 else {}
except Exception: d={}
print(d.get("verdict","no-verdict"), d.get("signer_pinned","-"), d.get("passed","-"), d.get("failed","-"), d.get("warnings","-"))')
  read -r v pinned passed failed warnings <<<"$verdict"
  if [ "$v" = "no-verdict" ]; then
    # The verifier printed no JSON verdict: surface its first error line so
    # the log says why instead of a bare failure.
    firsterr=$(grep -v '^\s*$' "$errfile" | head -1 || true)
    echo "::error file=$p::treeship package verify printed no verdict: ${firsterr:-no output}"
  fi
  sid=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("session",{}).get("id",""))' "$p/receipt.json" 2>/dev/null || true)
  digest="sha256:$(sha256sum "$p/receipt.json" | awk '{print $1}')"
  trailer="none"
  if [ -n "$sid" ]; then
    claimed=$(trailer_for "$sid")
    if [ -n "$claimed" ]; then
      if [ "$claimed" = "$digest" ]; then trailer="matches"; else trailer="MISMATCH"; fi
    fi
  fi
  status="$v"
  if [ "$v" != "verified" ] || [ "$trailer" = "MISMATCH" ]; then
    fail=1
    echo "::error file=$p::Treeship: $p is $v (trailer: $trailer)"
    status="**$v**"
  fi
  echo "| \`$p\` | $status | $pinned | $passed | $failed | $warnings | $trailer |" >> "$SUMMARY"
  echo "$p: $v (signer_pinned=$pinned passed=$passed failed=$failed trailer=$trailer)"
done

count=${#pkgs[@]}
{
  echo
  echo "$count package(s) checked under \`$TRUST_ROOTS\` with \`--strict\`."
  if [ "$count" -eq 0 ]; then
    echo
    echo "No Treeship packages in this pull request. This check verified nothing."
  fi
} >> "$SUMMARY"

if [ "$count" -eq 0 ]; then
  echo "::warning::no Treeship packages matched $PACKAGES; this check verified nothing"
  if [ "$REQUIRE" = "true" ]; then
    echo "::error::receipts are required for this repository and the pull request carries none"
    exit 1
  fi
fi
exit $fail
