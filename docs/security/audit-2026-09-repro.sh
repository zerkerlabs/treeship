#!/usr/bin/env bash
# Reproduces the September 2026 audit findings against a from-source build.
#   AUD-31  package verify accepts a fabricated artifact (exit 0)
#   AUD-32  unchained `attest action` artifacts are dropped from the sealed receipt
#   CORE    treeship verify <id> rejects a tampered envelope (exit 1)  -- control
#
# Runs entirely under target/audit-2026-09/repro (gitignored), with its own HOME,
# so your real ~/.treeship is never touched. No network.
#
#   ./docs/security/audit-2026-09-repro.sh            # from the repo root
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && git rev-parse --show-toplevel)"
cd "$REPO"
BIN="$REPO/target/debug/treeship"
if [ ! -x "$BIN" ]; then echo "==> building treeship (debug)"; cargo build --bin treeship -q; fi
echo "==> $("$BIN" --version)  @ $(git rev-parse --short HEAD)"

W="$REPO/target/audit-2026-09/repro"; rm -rf "$W"; mkdir -p "$W/home" "$W/proj"
export HOME="$W/home"; cd "$W/proj"
git init -q . && git -c user.email=a@b -c user.name=a commit -q --allow-empty -m init
CFG="$W/proj/.treeship/config.json"
T() { "$BIN" --config "$CFG" "$@"; }
jid() { python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])'; }
T init --quiet

# ---------------------------------------------------------------- AUD-32 ----
echo; echo "==> AUD-32: three UNCHAINED actions in a session"
T session start --name unchained --quiet
A=$(T attest action --actor agent://x --action act.A --format json | jid)
B=$(T attest action --actor agent://x --action act.B --format json | jid)
C=$(T attest action --actor agent://x --action act.C --format json | jid)
PKG1=$(T session close --summary unchained --format json | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["package"]);sys.stderr.write("    close: receipts=%s unsealed_branches=%s\n"%(d["receipts"],d["unsealed_branches"]))')
SEALED1=$(python3 -c "import json;print(' '.join(a['artifact_id'] for a in json.load(open('$PKG1/receipt.json'))['artifacts']))")
echo "    attested: $A $B $C"
echo "    sealed:   $SEALED1"
DROPPED=0; for x in $A $B $C; do case " $SEALED1 " in *" $x "*) ;; *) DROPPED=$((DROPPED+1));; esac; done
echo "    -> $DROPPED of 3 signed actions are NOT in the sealed receipt"

echo "==> AUD-32 control: same three actions CHAINED with --parent"
T session start --name chained --quiet
A2=$(T attest action --actor agent://x --action act.A --format json | jid)
B2=$(T attest action --actor agent://x --action act.B --parent "$A2" --format json | jid)
C2=$(T attest action --actor agent://x --action act.C --parent "$B2" --format json | jid)
PKG2=$(T session close --summary chained --format json | python3 -c 'import sys,json;print(json.load(sys.stdin)["package"])')
python3 -c "import json;r=json.load(open('$PKG2/receipt.json'));print('    sealed leaf_count =',r['merkle']['leaf_count'],'(3 actions + close)')"

# ---------------------------------------------------------------- AUD-31 ----
echo; echo "==> AUD-31: substitute a FABRICATED artifact into the sealed Merkle set"
TAMP="$W/tampered.treeship"; rm -rf "$TAMP"; cp -r "$PKG1" "$TAMP"
python3 - "$TAMP" <<'PY'
import hashlib, json, os, sys, glob
T = sys.argv[1]
leaf = lambda aid: hashlib.sha256(b'\x00' + aid.encode()).hexdigest()          # RFC 9162 leaf
node = lambda l, r: hashlib.sha256(b'\x01' + bytes.fromhex(l) + bytes.fromhex(r)).hexdigest()
r = json.load(open(f"{T}/receipt.json")); arts = r["artifacts"]
EVIL = "art_ev11wire1000000usd0000000000000"          # no envelope, no signature, invented digest
arts[0]["artifact_id"] = EVIL; arts[0]["digest"] = "sha256:" + "ab" * 32
ids = [a["artifact_id"] for a in arts]; L = [leaf(i) for i in ids]
def split(n):                                           # RFC 9162: largest power of two < n
    k = 1
    while k * 2 < n: k *= 2
    return k
def mth(hs):
    if len(hs) == 1: return hs[0]
    k = split(len(hs)); return node(mth(hs[:k]), mth(hs[k:]))
def path(m, hs):
    if len(hs) == 1: return []
    k = split(len(hs))
    if m < k: return path(m, hs[:k]) + [{"direction": "Right", "hash": mth(hs[k:])}]
    return path(m - k, hs[k:]) + [{"direction": "Left", "hash": mth(hs[:k])}]
root = mth(L)
m = {"leaf_count": len(L), "root": "mroot_" + root, "merkle_version": 2, "inclusion_proofs": [
    {"artifact_id": ids[i], "leaf_index": i, "proof": {"leaf_index": i, "leaf_hash": L[i], "path": path(i, L), "algorithm": "sha256-rfc9162", "merkle_version": 2}}
    for i in range(len(L))]}
r["merkle"] = m
json.dump(m, open(f"{T}/merkle.json", "w"), indent=2); json.dump(r, open(f"{T}/receipt.json", "w"), indent=2)
for f in glob.glob(f"{T}/proofs/*.json"): os.remove(f)
for ip in m["inclusion_proofs"]:
    json.dump({"artifact_id": ip["artifact_id"], "leaf_index": ip["leaf_index"], "proof": ip["proof"]}, open(f"{T}/proofs/{ip['artifact_id']}.proof.json", "w"), indent=2)
print("    sealed set is now:", ids)
PY
T package verify "$TAMP" >/dev/null 2>&1; E31=$?
echo "    package verify (text) -> exit $E31"
echo "    package verify (json) -> $(T package verify "$TAMP" --format json 2>/dev/null)"
T package verify "$TAMP" 2>/dev/null | grep -E 'inclusion:art_ev11|signature:art_ev11|chain_linkage|package verified|package structure' | sed 's/^/    /'

# ------------------------------------------------------------------ CORE ----
echo; echo "==> CORE control: tamper a stored envelope payload, then treeship verify <id>"
ART=".treeship/artifacts/$C.json"
python3 - "$ART" <<'PY'
import json, base64, sys
f = sys.argv[1]; a = json.load(open(f)); env = a.get('envelope', a)
p = env['payload']; st = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))
st['action'] = 'transfer.money'
env['payload'] = base64.urlsafe_b64encode(json.dumps(st, separators=(',', ':')).encode()).rstrip(b'=').decode()
json.dump((dict(a, envelope=env) if 'envelope' in a else env), open(f, 'w'))
PY
T verify "$C" >/dev/null 2>&1; ECORE=$?
echo "    treeship verify $C -> exit $ECORE  ($(T verify "$C" 2>/dev/null | grep -o 'invalid signature[^,]*' | head -1))"

# --------------------------------------------------------------- summary ----
echo; echo "==> summary"
printf '    %-8s %-58s %s\n' AUD-31 "fabricated artifact in sealed set, package verify exit" "$E31  $( [ "$E31" -eq 0 ] && echo '<- REPRODUCED (should be nonzero)' || echo 'fixed?')"
printf '    %-8s %-58s %s\n' AUD-32 "unchained actions dropped from sealed receipt" "$DROPPED/3  $( [ "$DROPPED" -gt 0 ] && echo '<- REPRODUCED' || echo 'fixed?')"
printf '    %-8s %-58s %s\n' CORE   "tampered envelope rejected by treeship verify, exit" "$ECORE  $( [ "$ECORE" -ne 0 ] && echo '<- sound' || echo '!! REGRESSION')"
echo "    workspace: $W"
