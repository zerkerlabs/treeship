#!/usr/bin/env bash
# The evaluator kit, end to end, on one machine playing three parties.
#
#   lab        runs an agent, seals the session, hands over the package and
#              its public key
#   evaluator  pins the lab's key, verifies the package strictly, grades it
#              with a signed evaluation.v1, seals its own session, hands over
#              its package and its public key
#   public     pins both keys and verifies both packages with nothing but
#              the bytes; the grade must walk to the package it grades
#
# Each party is a separate HOME and a separate Treeship workspace, so no
# key or trust root is shared by accident. Nothing here contacts a network.
#
# Usage: examples/evaluator-kit/run.sh [path-to-treeship]
# Exit 0 when every check the guide promises holds; nonzero with the failed
# check named otherwise.
set -euo pipefail

TREESHIP="${1:-${TREESHIP_CLI:-treeship}}"
command -v "$TREESHIP" >/dev/null 2>&1 || { echo "treeship not found: $TREESHIP" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

ROOT=$(mktemp -d -t evaluator-kit.XXXXXX)
trap 'rm -rf "$ROOT"' EXIT
export TREESHIP_ALLOW_INSECURE_KEY_PERMS=1

# One function per party: run a treeship command as that party.
as() {
  party="$1"; shift
  # Session state is discovered from the working directory, so every party
  # runs inside its own workspace. Warnings about the overridden trust
  # store go to a log that is shown only on failure.
  (cd "$ROOT/$party/ws" && HOME="$ROOT/$party" TREESHIP_TRUST_ROOTS="$ROOT/$party/trust_roots.json" \
    "$TREESHIP" --config "$ROOT/$party/ws/.treeship/config.json" "$@" 2>>"$ROOT/stderr.log")
}
jsonget() { python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:]) if i>=0 else {}
v=d
for k in sys.argv[1].split("."):
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else v)' "$1"; }
badrows() { python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:]) if i>=0 else {}
for c in d.get("checks",[]):
    if c.get("status")!="pass": print("   "+c.get("status","")+" "+c.get("name","")+": "+c.get("detail","")[:200])'; }
row() { python3 -c 'import json,sys
raw=sys.stdin.read(); i=raw.find("{"); d=json.loads(raw[i:])
for c in d.get("checks",[]):
    if c.get("name")==sys.argv[1]: print(c.get("status","")+" "+c.get("detail","")); break' "$1"; }
sha() { python3 -c 'import hashlib,sys;print("sha256:"+hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
pin() { # pin <party> <label> <key_id> <public_key>
  as "$1" trust add "$3" "$4" --kind session_host --label "$2" --yes >/dev/null
}
step() { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok   %s\n' "$*"; }
fail() { printf '   FAIL %s\n' "$*" >&2; [ -f "$ROOT/stderr.log" ] && tail -20 "$ROOT/stderr.log" >&2; exit 1; }

for p in lab evaluator public; do
  mkdir -p "$ROOT/$p/ws"
  (cd "$ROOT/$p/ws" && HOME="$ROOT/$p" "$TREESHIP" init --name "$p" --config "$ROOT/$p/ws/.treeship/config.json" >/dev/null)
done

# ---------------------------------------------------------------- lab ----
step "lab: run the agent under a session and seal it"
as lab session start --name "eval-run-2026-09-20" --actor agent://subject >/dev/null
as lab session event --type agent.called_tool --tool Read --agent-name subject >/dev/null
as lab session event --type agent.called_tool --tool Bash --agent-name subject >/dev/null
as lab session event --type agent.connected_network --destination api.example.com --agent-name subject >/dev/null
LAB_CLOSE=$(as lab session close --summary "suite run" --receipt-dir "$ROOT/handoff/lab" --format json 2>/dev/null \
  || as lab session close --summary "suite run" --format json)
LAB_PKG=$(printf '%s' "$LAB_CLOSE" | jsonget receipt_copy)
[ -n "$LAB_PKG" ] || LAB_PKG=$(printf '%s' "$LAB_CLOSE" | jsonget package)
LAB_COVERAGE=$(printf '%s' "$LAB_CLOSE" | jsonget coverage_artifact_id)
LAB_SESSION=$(printf '%s' "$LAB_CLOSE" | jsonget session_id)
[ -d "$LAB_PKG" ] || fail "lab package missing at $LAB_PKG"
LAB_KEY=$(as lab keys export --format json)
LAB_KID=$(printf '%s' "$LAB_KEY" | jsonget key_id); LAB_PUB=$(printf '%s' "$LAB_KEY" | jsonget public_key)
ok "sealed $LAB_SESSION -> $LAB_PKG"
ok "lab key $LAB_KID"
[ -n "$LAB_COVERAGE" ] && ok "coverage receipt $LAB_COVERAGE sealed in the package"

# The hand-off: the package directory and the public key, over any channel.
mkdir -p "$ROOT/handoff/lab"
[ "${LAB_PKG#"$ROOT/handoff/lab"}" != "$LAB_PKG" ] || cp -R "$LAB_PKG" "$ROOT/handoff/lab/"
LAB_PKG="$ROOT/handoff/lab/$(basename "$LAB_PKG")"
printf '%s %s\n' "$LAB_KID" "$LAB_PUB" > "$ROOT/handoff/lab/ship.pub"

# ---------------------------------------------------------- evaluator ----
step "evaluator: pin the lab's key, verify strictly, grade, seal"
pin evaluator "lab ship key" "$LAB_KID" "$LAB_PUB"
V=$(as evaluator package verify "$LAB_PKG" --strict --format json || true)
[ "$(printf '%s' "$V" | jsonget verdict)" = "verified" ] || { printf '%s' "$V" | badrows >&2; fail "lab package is not verified under the evaluator's pins: $(printf '%s' "$V" | jsonget verdict)"; }
ok "lab package: verified, strict, under the evaluator's own pins"
SIG=$(printf '%s' "$V" | row signer_trust); ok "signer_trust: ${SIG%% *}"
COV=$(printf '%s' "$V" | row coverage); [ -n "$COV" ] && ok "coverage: ${COV:0:110}"
NET=$(printf '%s' "$V" | row network_scope); [ -n "$NET" ] && ok "network_scope: ${NET:0:110}"

# A tampered copy must fail before any grade is written about it.
cp -R "$LAB_PKG" "$ROOT/tampered.treeship"
python3 - "$ROOT/tampered.treeship/receipt.json" <<'PY'
import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["session"]["name"]="tampered"; json.dump(d,open(p,"w"))
PY
if as evaluator package verify "$ROOT/tampered.treeship" --strict --format json >/dev/null 2>&1; then fail "a tampered package verified"; fi
ok "a tampered copy fails (receipt_binding), so the grade below is about the bytes that verified"

# The grade: evaluation.v1 about the package, by digest, signed by the
# evaluator's key, inside the evaluator's own session so it is sealed too.
LAB_DIGEST=$(sha "$LAB_PKG/receipt.json")
as evaluator session start --name "grading-$LAB_SESSION" --actor system://evaluator-example >/dev/null
GRADE_PAYLOAD=$(python3 - "$LAB_DIGEST" "$LAB_COVERAGE" <<'PY'
import json,sys
p={"schema":"evaluation.v1","subject_kind":"package","subject_digest":sys.argv[1],
   "subject_actor":"agent://subject","suite_id":"sandbox-escape-v3","suite_digest":"sha256:bb22",
   "environment_digest":"sha256:ee55","result_digest":"sha256:cc33","verdict":"pass",
   "score":0.02,"threshold":0.05,"capability":"sandbox-escape","evaluated_at":"2026-09-20T12:00:00Z",
   "notes":"worked example from examples/evaluator-kit/run.sh"}
if sys.argv[2]: p["coverage"]=sys.argv[2]
print(json.dumps(p))
PY
)
G=$(as evaluator attest receipt --system system://evaluator-example --kind evaluation.v1 --payload "$GRADE_PAYLOAD" --format json)
GRADE_ID=$(printf '%s' "$G" | jsonget id)
[ -n "$GRADE_ID" ] || fail "no grade id: $G"
ok "grade $GRADE_ID (evaluation.v1, verdict pass) about $LAB_DIGEST"
EV_CLOSE=$(as evaluator session close --summary "graded $LAB_SESSION" --receipt-dir "$ROOT/handoff/evaluator" --format json 2>/dev/null \
  || as evaluator session close --summary "graded $LAB_SESSION" --format json)
EV_PKG=$(printf '%s' "$EV_CLOSE" | jsonget receipt_copy)
[ -n "$EV_PKG" ] || EV_PKG=$(printf '%s' "$EV_CLOSE" | jsonget package)
EV_KEY=$(as evaluator keys export --format json)
EV_KID=$(printf '%s' "$EV_KEY" | jsonget key_id); EV_PUB=$(printf '%s' "$EV_KEY" | jsonget public_key)
mkdir -p "$ROOT/handoff/evaluator"
[ "${EV_PKG#"$ROOT/handoff/evaluator"}" != "$EV_PKG" ] || cp -R "$EV_PKG" "$ROOT/handoff/evaluator/"
EV_PKG="$ROOT/handoff/evaluator/$(basename "$EV_PKG")"
printf '%s %s\n' "$EV_KID" "$EV_PUB" > "$ROOT/handoff/evaluator/ship.pub"
ok "evaluator sealed its grading session -> $EV_PKG"

# ------------------------------------------------------------- public ----
step "public: pin both keys, verify both packages, check the grade points at the package"
pin public "lab ship key" "$LAB_KID" "$LAB_PUB"
pin public "evaluator ship key" "$EV_KID" "$EV_PUB"
for pkg in "$LAB_PKG" "$EV_PKG"; do
  V=$(as public package verify "$pkg" --strict --format json || true)
  [ "$(printf '%s' "$V" | jsonget verdict)" = "verified" ] || { printf '%s' "$V" | badrows >&2; fail "$pkg not verified by the public: $(printf '%s' "$V" | jsonget verdict)"; }
  ok "$(basename "$pkg"): verified, strict"
done
# The grade is sealed in the evaluator's package; read its payload back and
# recompute the digest it names.
GRADE_FILE="$EV_PKG/artifacts/$GRADE_ID.json"
[ -f "$GRADE_FILE" ] || fail "grade $GRADE_ID is not sealed in the evaluator's package"
NAMED=$(python3 - "$GRADE_FILE" <<'PY'
import json,sys,base64
env=json.load(open(sys.argv[1])); pad='='*(-len(env["payload"])%4)
stmt=json.loads(base64.urlsafe_b64decode(env["payload"]+pad))
print(stmt["kind"], stmt["payload"]["subject_digest"], stmt["payload"]["verdict"], env["signatures"][0]["keyid"])
PY
)
set -- $NAMED
[ "$1" = "evaluation.v1" ] || fail "sealed artifact is $1, not evaluation.v1"
[ "$2" = "$(sha "$LAB_PKG/receipt.json")" ] || fail "grade names $2, package is $(sha "$LAB_PKG/receipt.json")"
[ "$4" = "$EV_KID" ] || fail "grade signed by $4, not the evaluator's pinned key $EV_KID"
[ "$4" != "$LAB_KID" ] || fail "grade signed by the subject's own key: self-asserted"
ok "grade names the lab package by digest ($2), verdict $3, signed by the evaluator's key, not the subject's"

printf '\nevaluator kit: every check holds\n'
