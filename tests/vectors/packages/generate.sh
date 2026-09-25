#!/usr/bin/env bash
# tests/vectors/packages/generate.sh -- rebuild the frozen T2 package vectors.
#
#   bash tests/vectors/packages/generate.sh <treeship-binary> [vector ...]
#
# With no vector names, every vector is rebuilt. Name vectors (honest/basic,
# tampered/rename-session, ...) to rebuild only those, which is how a new
# vector is added without re-keying the others. Vectors written by an older
# release take that binary from the environment and are skipped without it:
#
#   LEGACY_024_BIN    treeship 0.24.0   honest/legacy-0.24
#   RELEASE_0319_BIN  treeship 0.31.9   honest/legacy-endorsement-0.31.9
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
shift
WANT=("$@")
LEGACY="${LEGACY_024_BIN:-}"
R0319="${RELEASE_0319_BIN:-}"
OUT="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/treeship-vectors.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

ship() { # ship <dir> <bin> <args...>
  local d="$1" b="$2"; shift 2
  (export HOME="$d" TREESHIP_CONFIG="$d/.treeship/config.json"; mkdir -p "$d/w"; cd "$d/w" && "$b" "$@")
}
id_of() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

want() { # want <vector-name>: named on the command line, or nothing was named
  [ ${#WANT[@]} -eq 0 ] && return 0
  local w; for w in "${WANT[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1
}

freeze() { # freeze <package-dir> <vector-name>
  rm -rf "${OUT:?}/$2"; mkdir -p "$(dirname "$OUT/$2")"
  cp -R "$1" "$OUT/$2"; rm -f "$OUT/$2/preview.html"
}

# --- honest/basic: two chained actions in one session ------------------------
if want honest/basic; then
  S="$WORK/basic"
  ship "$S" "$BIN" init --name vectors >/dev/null
  ship "$S" "$BIN" session start --name basic --actor agent://vector >/dev/null
  A=$(ship "$S" "$BIN" --format json attest action --actor agent://vector --action read | id_of id)
  ship "$S" "$BIN" attest action --actor agent://vector --action write --parent "$A" >/dev/null
  ship "$S" "$BIN" session close --headline basic --summary vector --receipt-dir "$S/r" >/dev/null
  freeze "$(ls -d "$S"/r/*.treeship)" honest/basic
fi

# --- honest/approval: a single-use approval consumed by an action -----------
if want honest/approval; then
  S="$WORK/approval"
  ship "$S" "$BIN" init --name vectors >/dev/null
  ship "$S" "$BIN" session start --name approval --actor agent://vector >/dev/null
  N=$(ship "$S" "$BIN" --format json attest approval --approver human://reviewer \
        --allowed-actor agent://vector --allowed-action deploy --max-uses 1 | id_of nonce)
  ship "$S" "$BIN" attest action --actor agent://vector --action deploy --approval-nonce "$N" >/dev/null
  ship "$S" "$BIN" session close --headline approval --summary vector --receipt-dir "$S/r" >/dev/null
  freeze "$(ls -d "$S"/r/*.treeship)" honest/approval
fi

# --- CLI-1: an endorsement of an older artifact, with an action chained on it -
endorse_session() { # endorse_session <dir> <bin>
  local S="$1" B="$2" A
  ship "$S" "$B" init --name vectors >/dev/null
  ship "$S" "$B" session start --name endorse --actor agent://vector >/dev/null
  A=$(ship "$S" "$B" --format json attest action --actor agent://vector --action draft | id_of id)
  ship "$S" "$B" attest action --actor agent://vector --action publish >/dev/null
  ship "$S" "$B" attest endorsement --endorser human://reviewer --subject "$A" --kind review >/dev/null
  ship "$S" "$B" attest action --actor agent://vector --action ship >/dev/null
  ship "$S" "$B" session close --headline endorse --summary vector --receipt-dir "$S/r" >/dev/null
}
if want honest/endorse-non-latest; then
  endorse_session "$WORK/endorse" "$BIN"
  freeze "$(ls -d "$WORK"/endorse/r/*.treeship)" honest/endorse-non-latest
fi
# The same flow written by 0.31.9, whose endorsements sign no parent.
if want honest/legacy-endorsement-0.31.9; then
  if [ -n "$R0319" ]; then
    endorse_session "$WORK/endorse-0319" "$R0319"
    freeze "$(ls -d "$WORK"/endorse-0319/r/*.treeship)" honest/legacy-endorsement-0.31.9
  else
    echo "RELEASE_0319_BIN not set: honest/legacy-endorsement-0.31.9 left as committed" >&2
  fi
fi

# --- honest/room-countersigned: CLI-3, invite -> join -> challenge -> countersign
if want honest/room-countersigned; then
  S="$WORK/room"
  ship "$S" "$BIN" init --name vectors >/dev/null
  ship "$S" "$BIN" session start --name room --actor agent://host >/dev/null
  ship "$S" "$BIN" session invite --open --expires 10m >"$S/inv.txt" 2>/dev/null
  HP=$(ship "$S" "$BIN" session join --invite-file "$S/inv.txt" --actor agent://j 2>&1 \
    | sed -n 's/.*trust add <key_id> \(ed25519:[^ ]*\).*/\1/p' | head -1 || true)
  # (that first join is refused -- the host key is not pinned yet -- and
  # prints the key to pin)
  [ -n "$HP" ]
  ship "$S" "$BIN" trust add room_host "$HP" --kind session_host --yes >/dev/null
  PID=$(ship "$S" "$BIN" --format json session join --invite-file "$S/inv.txt" --actor agent://j | id_of participant_id)
  MC=$(ship "$S" "$BIN" --format json session mint-challenge)
  N=$(printf '%s' "$MC" | id_of nonce); IAT=$(printf '%s' "$MC" | id_of issued_at)
  ship "$S" "$BIN" session answer-challenge "$PID" --challenge "$N" --actor agent://j --out "$S/resp.json" >/dev/null
  ship "$S" "$BIN" session countersign "$PID" --challenge "$N" --challenge-issued-at "$IAT" \
    --challenge-response "$S/resp.json" >/dev/null
  ship "$S" "$BIN" session close --headline room --summary vector --receipt-dir "$S/r" >/dev/null
  freeze "$(ls -d "$S"/r/*.treeship)" honest/room-countersigned
fi

# --- honest/legacy-0.24: a real package from before envelopes (0.31.2) ------
if want honest/legacy-0.24; then
  if [ -n "$LEGACY" ]; then
    S="$WORK/legacy"
    ship "$S" "$LEGACY" init --name vectors >/dev/null
    ship "$S" "$LEGACY" session start --name legacy --actor agent://vector >/dev/null
    ship "$S" "$LEGACY" attest action --actor agent://vector --action read >/dev/null
    ship "$S" "$LEGACY" session close --headline legacy --summary vector >/dev/null
    freeze "$(ls -d "$S"/w/.treeship/sessions/*.treeship "$S"/.treeship/sessions/*.treeship 2>/dev/null | head -1)" honest/legacy-0.24
  else
    echo "LEGACY_024_BIN not set: honest/legacy-0.24 left as committed" >&2
  fi
fi

# --- tampered/*: each one edit away from an honest vector -------------------
tamper() { # tamper <name> [base-vector]; prints the new vector dir
  rm -rf "${OUT:?}/tampered/$1"; mkdir -p "$OUT/tampered"
  cp -R "$OUT/${2:-honest/basic}" "$OUT/tampered/$1"; printf '%s\n' "$OUT/tampered/$1"
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
edit_payload() { # edit_payload <envelope.json> <python statement over body>
  python3 - "$1" "$2" <<'PY'
import base64, json, sys
f, stmt = sys.argv[1], sys.argv[2]
env = json.load(open(f))
raw = env["payload"]  # unpadded base64url
body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
exec(stmt)
enc = json.dumps(body, separators=(",", ":")).encode()
env["payload"] = base64.urlsafe_b64encode(enc).decode().rstrip("=")
json.dump(env, open(f, "w"))
PY
}

# CLI-4: delete the signed close record. Nothing else changes.
if want tampered/drop-record-json; then
  T=$(tamper drop-record-json); rm "$T/record.json"
fi

# CLI-4: delete the close record, then rename the session it would have bound.
if want tampered/drop-record-json+rename; then
  T=$(tamper drop-record-json+rename); rm "$T/record.json"
  edit_receipt "$T" 'r["session"]["name"] = "EVIL"'
fi

# The close record is present and binds the old receipt digest.
if want tampered/rename-session; then
  T=$(tamper rename-session); edit_receipt "$T" 'r["session"]["name"] = "EVIL"'
fi
if want tampered/narrative-edit; then
  T=$(tamper narrative-edit)
  edit_receipt "$T" 'r["session"]["narrative"]["headline"] = "all approvals obtained"'
fi

# An artifact envelope's signed payload is edited (the signature no longer holds).
if want tampered/artifact-payload-edit; then
  T=$(tamper artifact-payload-edit)
  edit_payload "$(ls "$T"/artifacts/*.json | sort | head -1)" 'body["timestamp"] = "2020-01-01T00:00:00Z"'
fi

# A sealed artifact's envelope is removed from the package.
if want tampered/drop-artifact-envelope; then
  T=$(tamper drop-artifact-envelope); rm "$(ls "$T"/artifacts/*.json | head -1)"
fi

# The signing key in keys.json is replaced by a stranger's.
if want tampered/swap-package-key; then
  T=$(tamper swap-package-key)
  python3 - "$T/keys.json" <<'PY'
import json, sys
p = sys.argv[1]; k = json.load(open(p))
for kid in k["keys"]:
    k["keys"][kid] = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
json.dump(k, open(p, "w"), indent=2)
PY
fi

# CLI-1: the endorsement's signed parentId is pointed at its subject. A
# present parentId is never read as a legacy endorsement, so this fails.
if want tampered/endorsement-parent-edited; then
  T=$(tamper endorsement-parent-edited honest/endorse-non-latest)
  for f in "$T"/artifacts/*.json; do
    if grep -q 'vnd.treeship.endorsement' "$f"; then
      edit_payload "$f" 'body["parentId"] = body["subject"]["artifactId"]'
    fi
  done
fi

# CLI-4: a cross-session splice. One ship closes session 1, then signs, in
# session 2, an action and a handoff that name session 1's last chained
# artifact as parent. Each is appended to session 1's package with the tree
# recomputed (splice.py). With record.json deleted this verified by default
# before W1-4; with it kept, receipt_binding catches it.
if want tampered/splice-action || want tampered/splice-handoff || want tampered/splice-action-record-kept; then
  S="$WORK/splice"
  ship "$S" "$BIN" init --name vectors >/dev/null
  ship "$S" "$BIN" session start --name first --actor agent://vector >/dev/null
  ship "$S" "$BIN" attest action --actor agent://vector --action read >/dev/null
  ship "$S" "$BIN" session close --headline first --summary vector --receipt-dir "$S/r" >/dev/null
  P1="$(ls -d "$S"/r/*.treeship)"
  LAST=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print([a["artifact_id"] for a in r["artifacts"] if not a.get("unchained")][-1])' "$P1/receipt.json")
  ship "$S" "$BIN" session start --name second --actor agent://vector >/dev/null
  ACT=$(ship "$S" "$BIN" --format json attest action --actor agent://vector --action wire.transfer --parent "$LAST" | id_of id)
  HOF=$(ship "$S" "$BIN" --format json attest handoff --from agent://vector --to agent://mallory --artifacts "$LAST" | id_of id)
  envelope_of() { # envelope_of <artifact-id>: the signed envelope from the ship's store
    python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["envelope"], open(sys.argv[2], "w"))' \
      "$S/.treeship/artifacts/$1.json" "$S/$1.json"
    printf '%s\n' "$S/$1.json"
  }
  if want tampered/splice-action; then
    python3 "$OUT/splice.py" "$P1" "$OUT/tampered/splice-action" "$(envelope_of "$ACT")" 0 0 >/dev/null
    rm -f "$OUT/tampered/splice-action/preview.html"
  fi
  if want tampered/splice-handoff; then
    python3 "$OUT/splice.py" "$P1" "$OUT/tampered/splice-handoff" "$(envelope_of "$HOF")" 0 0 >/dev/null
    rm -f "$OUT/tampered/splice-handoff/preview.html"
  fi
  if want tampered/splice-action-record-kept; then
    python3 "$OUT/splice.py" "$P1" "$OUT/tampered/splice-action-record-kept" "$(envelope_of "$ACT")" 1 0 >/dev/null
    rm -f "$OUT/tampered/splice-action-record-kept/preview.html"
  fi
fi

# CLI-3: the host countersign is stripped from the sealed participant.
if want tampered/room-countersign-stripped; then
  T=$(tamper room-countersign-stripped honest/room-countersigned)
  for f in "$T"/artifacts/*.json; do
    if grep -q 'vnd.treeship.session-participant' "$f"; then
      python3 - "$f" <<'PY'
import json, sys
f = sys.argv[1]; env = json.load(open(f))
env["signatures"] = env["signatures"][:1]
json.dump(env, open(f, "w"))
PY
    fi
  done
fi

# CLI-3: the invitation the participant redeems is removed from the package.
if want tampered/room-invitation-dropped; then
  T=$(tamper room-invitation-dropped honest/room-countersigned)
  for f in "$T"/artifacts/*.json; do
    if grep -q 'vnd.treeship.invitation' "$f"; then rm "$f"; fi
  done
fi

# CLI-3 (#483 review): one single-use invitation, two participants, both
# countersigned by the host. The second joiner's pending envelope reaches
# the host's store, and countersign accepts it because the invitation was
# already consumed once (the producer-side gap W1-3b closes).
if want tampered/room-double-redemption; then
  S="$WORK/room2"; S2="$WORK/room2-joiner"
  ship "$S" "$BIN" init --name vectors >/dev/null
  ship "$S2" "$BIN" init --name joiner2 >/dev/null
  ship "$S" "$BIN" session start --name room --actor agent://host >/dev/null
  ship "$S" "$BIN" session invite --open --expires 10m >"$S/inv.txt" 2>/dev/null
  HP=$(ship "$S" "$BIN" session join --invite-file "$S/inv.txt" --actor agent://j 2>&1 \
    | sed -n 's/.*trust add <key_id> \(ed25519:[^ ]*\).*/\1/p' | head -1 || true)
  [ -n "$HP" ]
  ship "$S" "$BIN" trust add room_host "$HP" --kind session_host --yes >/dev/null
  ship "$S2" "$BIN" trust add room_host "$HP" --kind session_host --yes >/dev/null
  P1=$(ship "$S" "$BIN" --format json session join --invite-file "$S/inv.txt" --actor agent://j | id_of participant_id)
  P2=$(ship "$S2" "$BIN" --format json session join --invite-file "$S/inv.txt" --actor agent://k | id_of participant_id)
  cp "$S2/.treeship/artifacts/$P2.json" "$S/.treeship/artifacts/"
  ship "$S" "$BIN" session countersign "$P1" >/dev/null
  ship "$S" "$BIN" session countersign "$P2" >/dev/null
  ship "$S" "$BIN" session close --headline room --summary vector --receipt-dir "$S/r" >/dev/null
  freeze "$(ls -d "$S"/r/*.treeship)" tampered/room-double-redemption
fi

# The sealed participant is listed twice, with the tree recomputed (the
# close record no longer binds it, so this also fails receipt_binding; the
# unit test isolates the duplicate-id row).
if want tampered/room-participant-sealed-twice; then
  T=$(tamper room-participant-sealed-twice honest/room-countersigned)
  python3 - "$T" <<'PY'
import hashlib, json, sys
d = sys.argv[1]; r = json.load(open(f"{d}/receipt.json"))
dup = next(a for a in r["artifacts"] if "session-participant" in a["payload_type"])
r["artifacts"].append(dict(dup))
leaf = lambda i: hashlib.sha256(b"\x00" + i.encode()).digest()
node = lambda a, b: hashlib.sha256(b"\x01" + a + b).digest()
leaves = [leaf(a["artifact_id"]) for a in r["artifacts"]]
def proof(i):
    lvl, path = leaves[:], []
    while len(lvl) > 1:
        if i % 2 == 0 and i + 1 < len(lvl): path.append({"direction": "Right", "hash": lvl[i + 1].hex()})
        elif i % 2 == 1: path.append({"direction": "Left", "hash": lvl[i - 1].hex()})
        lvl = [node(lvl[j], lvl[j + 1]) if j + 1 < len(lvl) else lvl[j] for j in range(0, len(lvl), 2)]
        i //= 2
    return path, lvl[0]
_, root = proof(0)
r["merkle"]["root"] = "mroot_" + root.hex(); r["merkle"]["leaf_count"] = len(leaves)
tmpl = r["merkle"]["inclusion_proofs"][0]; out = []
for i, a in enumerate(r["artifacts"]):
    p = json.loads(json.dumps(tmpl)); p["artifact_id"] = a["artifact_id"]
    path, _ = proof(i); p["proof"]["path"] = path; p["proof"]["leaf_index"] = i
    p["leaf_index"] = i; p["proof"]["leaf_hash"] = leaves[i].hex()
    out.append(p)
r["merkle"]["inclusion_proofs"] = out
open(f"{d}/receipt.json", "w").write(json.dumps(r, indent=2))
PY
fi

echo "vectors written to $OUT"
