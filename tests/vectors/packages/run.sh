#!/usr/bin/env bash
# tests/vectors/packages/run.sh -- T2 adversarial package vectors, CLI side.
#
#   bash tests/vectors/packages/run.sh [treeship-binary]
#
# Runs `treeship package verify` over every frozen vector in three modes and
# compares the JSON verdict to expected.json:
#
#   cli             default, on a ship that has never seen the vector's key
#   cli_strict      --strict, after pinning the key(s) the package names
#   cli_structural  --structural
#
# The receipt-only verifier (core-wasm verify_receipt, which is what
# @treeship/verify's verifyReceipt runs) is checked over the same vectors by
# packages/core/tests/package_vectors.rs.
#
# Hard rules, independent of expected.json: a tampered vector is never
# "verified" or "signatures-pass" in any mode, and a verdict of "failed"
# always exits nonzero (anything else exits 0).
#
# A column known to be wrong on main is listed under "xfail" as
# {"task": <fix-plan id>, "got": <the wrong verdict main gives today>}. It
# reports XFAIL only while the verdict is exactly that wrong one: a different
# wrong verdict (a regression to "verified", "no-json" from a crash) fails,
# and the right verdict fails as XPASS, so the fixing PR removes the entry.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BIN="${1:-${TREESHIP_CLI:-$ROOT/target/debug/treeship}}"
[ -x "$BIN" ] || { echo "treeship binary not found: $BIN" >&2; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/treeship-t2.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

python3 - "$BIN" "$HERE" "$WORK" <<'PY'
import json, os, subprocess, sys

bin_, here, work = sys.argv[1:4]
expected = json.load(open(os.path.join(here, "expected.json")))["vectors"]
MODES = {"cli": [], "cli_strict": ["--strict"], "cli_structural": ["--structural"]}
ACCEPTING = {"verified", "signatures-pass"}

def ship(name):
    home = os.path.join(work, name)
    env = dict(os.environ, HOME=home, TREESHIP_CONFIG=os.path.join(home, ".treeship", "config.json"))
    os.makedirs(home, exist_ok=True)
    subprocess.run([bin_, "init", "--name", "t2"], env=env, cwd=home, capture_output=True, check=True)
    return env, home

def verdict(env, cwd, args, pkg):
    p = subprocess.run([bin_, "package", "verify", "--format", "json", *args, pkg],
                       env=env, cwd=cwd, capture_output=True, text=True)
    try:
        v = json.loads(p.stdout).get("verdict") or "no-verdict"
    except ValueError:
        v = "no-json"
    return v, p.returncode

rows, broken, xfails = [], [], 0
on_disk = sorted(f"{k}/{v}" for k in ("honest", "tampered")
                 for v in os.listdir(os.path.join(here, k)))
for name in on_disk:
    if name not in expected:
        broken.append(f"{name}: vector on disk has no entry in expected.json")
for name, exp in sorted(expected.items()):
    pkg = os.path.join(here, name)
    if not os.path.isdir(pkg):
        broken.append(f"{name}: listed in expected.json but missing on disk"); continue
    # A fresh stranger ship per vector: nothing pinned from an earlier one.
    env, home = ship(name.replace("/", "_"))
    keys = {}
    if os.path.exists(os.path.join(pkg, "keys.json")):
        keys = json.load(open(os.path.join(pkg, "keys.json"))).get("keys", {})
    # cli_strict pins the producer's keys. By default that is every key the
    # package names; a vector whose keys.json carries an attacker's key lists
    # the keys a reader would actually have pinned in "pin_keys_from" (a
    # vector whose keys.json is the producer's).
    if "pin_keys_from" in exp:
        keys = json.load(open(os.path.join(here, exp["pin_keys_from"], "keys.json")))["keys"]
    xf = exp.get("xfail", {})
    for mode, args in MODES.items():
        if mode not in exp:
            continue
        if mode == "cli_strict":
            for kid, pub in keys.items():
                subprocess.run([bin_, "trust", "add", kid, pub, "--kind", "cert_issuer", "--yes"],
                           env=env, cwd=home, capture_output=True, check=True)
        got, rc = verdict(env, home, args, pkg)
        problems = []
        if got != exp[mode]:
            problems.append(f"verdict {got}, expected {exp[mode]}")
        if (got == "failed") != (rc != 0):
            problems.append(f"verdict {got} exited {rc}")
        if name.startswith("tampered/") and got in ACCEPTING:
            problems.append(f"tampered vector accepted as {got}")
        label = f"{name} [{mode}]"
        if mode in xf:
            task, pinned = xf[mode]["task"], xf[mode]["got"]
            if not problems:
                broken.append(f"{label}: XPASS -- now correct; remove xfail.{mode} ({task}) from expected.json")
                print(f"XPASS  {label}")
            elif got == pinned and (got == "failed") == (rc != 0):
                xfails += 1; print(f"XFAIL  {label}: {got}, expected {exp[mode]}  ({task})")
            else:
                broken.append(f"{label}: {'; '.join(problems)} -- not the known-wrong {pinned} of {task}")
                print(f"FAIL   {label}: {'; '.join(problems)} (xfail pins {pinned})")
        elif problems:
            broken.append(f"{label}: {'; '.join(problems)}"); print(f"FAIL   {label}: {'; '.join(problems)}")
        else:
            print(f"ok     {label}: {got}")

print()
for b in broken:
    print("BROKEN", b)
print(f"vectors: {len(expected)}, {xfails} expected failures, {len(broken)} broken")
sys.exit(1 if broken else 0)
PY
