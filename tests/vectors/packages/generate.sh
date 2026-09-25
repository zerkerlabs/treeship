#!/usr/bin/env bash
# tests/vectors/packages/generate.sh -- rebuild the frozen T2 package vectors.
#
#   bash tests/vectors/packages/generate.sh <treeship-binary> [legacy-0.24-binary]
#
# The vectors are committed and frozen: run.sh verifies the bytes in this
# directory, not a fresh build, so a writer change can't quietly move the
# goalposts. Regenerate only to add a vector, and review the diff. Every
# vector is signed by a throwaway key made here; nothing touches ~/.treeship.
#
# preview.html is dropped from every vector: it is optional, ~150 KB, and no
# verifier reads it.

set -euo pipefail
BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
LEGACY="${2:-}"
OUT="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/treeship-vectors.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

ship() { # ship <dir> <bin> <args...>
  local d="$1" b="$2"; shift 2
  (export HOME="$d" TREESHIP_CONFIG="$d/.treeship/config.json"; mkdir -p "$d/w"; cd "$d/w" && "$b" "$@")
}
id_of() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

freeze() { # freeze <package-dir> <vector-name>
  rm -rf "${OUT:?}/$2"; mkdir -p "$(dirname "$OUT/$2")"
  cp -R "$1" "$OUT/$2"; rm -f "$OUT/$2/preview.html"
}

# --- honest/basic: two chained actions in one session ------------------------
S="$WORK/basic"
ship "$S" "$BIN" init --name vectors >/dev/null
ship "$S" "$BIN" session start --name basic --actor agent://vector >/dev/null
A=$(ship "$S" "$BIN" --format json attest action --actor agent://vector --action read | id_of id)
ship "$S" "$BIN" attest action --actor agent://vector --action write --parent "$A" >/dev/null
ship "$S" "$BIN" session close --headline basic --summary vector --receipt-dir "$S/r" >/dev/null
freeze "$(ls -d "$S"/r/*.treeship)" honest/basic

# --- honest/approval: a single-use approval consumed by an action -----------
S="$WORK/approval"
ship "$S" "$BIN" init --name vectors >/dev/null
ship "$S" "$BIN" session start --name approval --actor agent://vector >/dev/null
N=$(ship "$S" "$BIN" --format json attest approval --approver human://reviewer \
      --allowed-actor agent://vector --allowed-action deploy --max-uses 1 | id_of nonce)
ship "$S" "$BIN" attest action --actor agent://vector --action deploy --approval-nonce "$N" >/dev/null
ship "$S" "$BIN" session close --headline approval --summary vector --receipt-dir "$S/r" >/dev/null
freeze "$(ls -d "$S"/r/*.treeship)" honest/approval

# --- honest/legacy-0.24: a real package from before envelopes (0.31.2) ------
if [ -n "$LEGACY" ]; then
  S="$WORK/legacy"
  ship "$S" "$LEGACY" init --name vectors >/dev/null
  ship "$S" "$LEGACY" session start --name legacy --actor agent://vector >/dev/null
  ship "$S" "$LEGACY" attest action --actor agent://vector --action read >/dev/null
  ship "$S" "$LEGACY" session close --headline legacy --summary vector >/dev/null
  freeze "$(ls -d "$S"/w/.treeship/sessions/*.treeship "$S"/.treeship/sessions/*.treeship 2>/dev/null | head -1)" honest/legacy-0.24
else
  echo "no 0.24.0 binary given: honest/legacy-0.24 left as committed" >&2
fi

# --- tampered/*: each one edit away from honest/basic ------------------------
H="$OUT/honest/basic"
tamper() { # tamper <name>; prints the new vector dir
  rm -rf "${OUT:?}/tampered/$1"; mkdir -p "$OUT/tampered"
  cp -R "$H" "$OUT/tampered/$1"; printf '%s\n' "$OUT/tampered/$1"
}
edit_receipt() { # edit_receipt <dir> <python statement over r>
  python3 - "$1/receipt.json" "$2" <<'PY'
import json, sys
p, stmt = sys.argv[1], sys.argv[2]
r = json.load(open(p))
exec(stmt)
open(p, "w").write(json.dumps(r, indent=2))
PY
}

# CLI-4: delete the signed close record. Nothing else changes.
T=$(tamper drop-record-json); rm "$T/record.json"

# CLI-4: delete the close record, then rename the session it would have bound.
T=$(tamper drop-record-json+rename); rm "$T/record.json"
edit_receipt "$T" 'r["session"]["name"] = "EVIL"'

# The close record is present and binds the old receipt digest.
T=$(tamper rename-session); edit_receipt "$T" 'r["session"]["name"] = "EVIL"'
T=$(tamper narrative-edit); edit_receipt "$T" 'r["session"]["narrative"]["headline"] = "all approvals obtained"'

# An artifact envelope's signed payload is edited (the signature no longer holds).
T=$(tamper artifact-payload-edit)
python3 - "$T" <<'PY'
import base64, glob, json, sys
f = sorted(glob.glob(sys.argv[1] + "/artifacts/*.json"))[0]
env = json.load(open(f))
raw = env["payload"]  # unpadded base64url
body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
body["timestamp"] = "2020-01-01T00:00:00Z"
enc = json.dumps(body, separators=(",", ":")).encode()
env["payload"] = base64.urlsafe_b64encode(enc).decode().rstrip("=")
json.dump(env, open(f, "w"))
PY

# A sealed artifact's envelope is removed from the package.
T=$(tamper drop-artifact-envelope); rm "$(ls "$T"/artifacts/*.json | head -1)"

# The signing key in keys.json is replaced by a stranger's.
T=$(tamper swap-package-key)
python3 - "$T/keys.json" <<'PY'
import json, sys
p = sys.argv[1]; k = json.load(open(p))
for kid in k["keys"]:
    k["keys"][kid] = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
json.dump(k, open(p, "w"), indent=2)
PY

echo "vectors written to $OUT"
