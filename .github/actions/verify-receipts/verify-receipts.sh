#!/usr/bin/env bash
# Verify every sealed Treeship package a pull request carries, under the
# repository's pinned roots, in strict mode. Cross-check the commits'
# Treeship-Receipt trailers against the packages' receipt digests. Write a
# step summary, post a verdict comment on the pull request, and fail on any
# package that is not verified, and, when REQUIRE is true, on a PR with no
# packages at all.
#
# The comment exists because the step summary is behind a click into the
# Actions tab, which is the same place nobody looks. A reviewer should see
# what the agent did, and what was not proven, in the thread they are already
# reading.
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
FACTS="${RUNNER_TEMP:-/tmp}/treeship-facts.jsonl"
: > "$FACTS"
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
  # What the session actually contains, for the reviewer's line. Counts only:
  # the comment names the shape of the work, never its content.
  python3 - "$p/receipt.json" "$v" >> "$FACTS" <<'PYEOF'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
se=d.get("side_effects") or {}
pa=d.get("participants") or {}
cov=(d.get("session") or {}).get("coverage") or {}
print(json.dumps({
  "verdict": sys.argv[2],
  "files": len(se.get("files_written") or []),
  "reads": len(se.get("files_read") or []),
  "procs": len(se.get("processes") or []),
  "net": len(se.get("network_connections") or []),
  "agents": pa.get("total_agents") or 0,
  "handoffs": pa.get("handoffs") or 0,
  "spawned": pa.get("spawned_subagents") or 0,
  "name": (d.get("session") or {}).get("name") or "",
  "receipts": len(d.get("artifacts") or []),
  "judgements": len(d.get("judgements") or []),
  "approvals": len(d.get("approvals") or []),
  "anchored": bool((d.get("proofs") or {}).get("anchors_present")),
  "witness": ((d.get("session") or {}).get("witness") or ""),
}))
PYEOF
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

# ── The verdict comment ────────────────────────────────────────────
# Five lines: the verdict, what the agent did, what was checked, what is
# NOT proven, and how to check it yourself. The fourth line is not optional
# padding: a green tick that does not say what it failed to cover is the
# kind of false comfort this project exists to avoid.
if [ "${COMMENT:-true}" = "true" ] && [ -n "${PR_NUMBER:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  BODY="${RUNNER_TEMP:-/tmp}/treeship-comment.md"
  python3 - "$FACTS" "$count" "$fail" "$TRUST_ROOTS" > "$BODY" <<'PYEOF'
import json,sys
# The shape is fixed by the Traces design: a monospace block of at most five
# glyph-led lines. A line whose evidence is not in the package is omitted, not
# invented, so the comment never implies a capability the package did not carry.
facts=[]
try:
    for line in open(sys.argv[1]):
        line=line.strip()
        if line: facts.append(json.loads(line))
except Exception: pass
count=int(sys.argv[2]); fail=int(sys.argv[3]); roots=sys.argv[4]
def total(k): return sum(f.get(k) or 0 for f in facts)
bad=[f for f in facts if f.get("verdict")!="verified"]

print("<!-- treeship-receipts -->")
if count==0:
    print("```")
    print("\u25cb No sealed sessions in this pull request. This check verified nothing.")
    print("```")
    print()
    print("That is a statement about coverage, not a pass.")
    raise SystemExit(0)

lines=[]
receipts=total("receipts")
chain="chain intact" if not bad else "chain broken"
anchored=[f for f in facts if f.get("anchored")]
witnessed=sorted({f.get("witness") for f in facts if f.get("witness")})
if bad:
    head=f"\u2717 Trace not verified. {len(bad)} of {count} session(s) failed under pinned keys."
else:
    tail=[f"{receipts} receipt(s)", chain]
    if witnessed: tail.append(", ".join(witnessed)+"-witnessed")
    if anchored: tail.append("anchored in Rekor")
    head="\u2713 Trace verified. "+", ".join(tail)+"."
lines.append(("ok" if not bad else "bad", head))

# What the agent did. Counts only: the comment names the shape of the work,
# never its content.
bits=[]
for k,label in (("files","file(s) written"),("reads","read"),("procs","command(s)"),
                ("net","external call(s)")):
    if total(k): bits.append(f"{total(k)} {label}")
if total("agents"): bits.append(f'{total("agents")} agent(s)')
if total("spawned"): bits.append(f'{total("spawned")} subagent(s)')
if total("handoffs"): bits.append(f'{total("handoffs")} handoff(s)')
if bits:
    lines.append(("dot", "\u25cf Work: "+", ".join(bits)+"."))

# Judgements and signed human decisions, only when the package carries them.
j=total("judgements"); a=total("approvals")
if j:
    lines.append(("flag", f"\u2691 {j} signed judgement(s) chained to the steps they grade."))
if a:
    lines.append(("dot", f"\u25cf {a} signed approval(s), each bound by nonce to one action."))

# The line that never gets cut.
lines.append(("open", "\u25cb Not captured: model reasoning, and anything done outside the recorder. "
                      "Verify offline: treeship package verify <package> --strict"))

print("```")
for _,t in lines[:5]:
    print(t)
print("```")
print()
print(f"Checked against `{roots}` in strict mode: signatures, parent chain, Merkle inclusion, "
      f"and the commit trailer binding.")
PYEOF
  # Append the per-package detail the summary already built.
  {
    echo
    echo "<details><summary>Per-package verdicts</summary>"
    echo
    sed -n "/^| package |/,/^$/p" "$SUMMARY" 2>/dev/null || true
    echo
    echo "</details>"
  } >> "$BODY" || true

  API="${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}"
  existing=$(curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "$API/issues/${PR_NUMBER}/comments?per_page=100" 2>/dev/null |
    python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
for c in d if isinstance(d,list) else []:
    if "<!-- treeship-receipts -->" in (c.get("body") or ""):
        print(c["id"]); break' 2>/dev/null || true)

  payload="${RUNNER_TEMP:-/tmp}/treeship-comment.json"
  python3 -c 'import json,sys;json.dump({"body":open(sys.argv[1]).read()},open(sys.argv[2],"w"))' "$BODY" "$payload"

  # A comment must never decide whether the check passes. A fork PR gets a
  # read-only token and this will fail; the verdict still stands in the log,
  # the annotations and the step summary.
  if [ -n "$existing" ]; then
    curl -sS -X PATCH -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "$API/issues/comments/$existing" -d @"$payload" >/dev/null 2>&1 \
      || echo "::warning::could not update the Treeship verdict comment (needs pull-requests: write)"
  else
    curl -sS -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "$API/issues/${PR_NUMBER}/comments" -d @"$payload" >/dev/null 2>&1 \
      || echo "::warning::could not post the Treeship verdict comment (needs pull-requests: write)"
  fi
fi

if [ "$count" -eq 0 ]; then
  echo "::warning::no Treeship packages matched $PACKAGES; this check verified nothing"
  if [ "$REQUIRE" = "true" ]; then
    echo "::error::receipts are required for this repository and the pull request carries none"
    exit 1
  fi
fi
exit $fail
