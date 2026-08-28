#!/usr/bin/env python3
"""Adversarial probe of the Treeship CLI's trust surface.

Usage: verify_probes.py <path-to-treeship> <workspace-dir>
  where <workspace-dir> holds a config.json created by
  `treeship --config <dir>/config.json init`.

Written from the hostile reviewer's stance: do NOT check that good input
passes -- check that bad input fails, loudly, on both channels a caller can
read (stdout document, exit code).

The failure classes probed here are the silent ones. A loud bug (unparseable
output) announces itself; a silent one (Ok for the wrong reason) is what a
trust tool cannot afford. Each probe states what a PASS means so a green run
cannot be mistaken for "we ran something".
"""
import base64, json, os, shutil, subprocess, sys, tempfile

def b64d(x):
    # DSSE payloads here are stored without '=' padding.
    return base64.b64decode(x + "=" * (-len(x) % 4))

BIN = sys.argv[1]
WS = sys.argv[2]
results = []

def run(args, env=None):
    # Do NOT override HOME: it feeds the machine-key derivation, and changing
    # it makes the keystore undecryptable in a way that looks like a tool bug.
    e = dict(os.environ)
    if env: e.update(env)
    p = subprocess.run([BIN, "--config", os.path.join(WS, "config.json")] + args,
                       capture_output=True, text=True, env=e, cwd=WS)
    return p.returncode, p.stdout, p.stderr

def record(name, ok, detail=""):
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))

def art_path(aid):
    # Store root is the parent of the --config file, not HOME/.treeship.
    return os.path.join(WS, "artifacts", f"{aid}.json")

def load(aid):
    with open(art_path(aid)) as f: return json.load(f)

def save(aid, d):
    with open(art_path(aid), "w") as f: json.dump(d, f)

def mutate(aid, fn):
    """Apply fn to the decoded inner payload, re-encode, return restore()."""
    orig = open(art_path(aid)).read()
    d = json.loads(orig)
    inner = json.loads(b64d(d["envelope"]["payload"]))
    fn(inner, d)
    d["envelope"]["payload"] = base64.b64encode(json.dumps(inner).encode()).decode()
    save(aid, d)
    return lambda: open(art_path(aid), "w").write(orig)

def verify_json(aid):
    rc, out, err = run(["verify", aid, "--format", "json"])
    try: doc = json.loads(out)
    except Exception: doc = None
    return rc, doc, out, err

# ---------------------------------------------------------------- mint
rc, out, _ = run(["attest", "action", "--actor", "agent:probe",
                  "--action", "probe.baseline", "--format", "json"])
AID = json.loads(out)["id"]
print(f"\nbaseline artifact: {AID}\n")

# 1. baseline sanity -- if this fails every later probe is meaningless
rc, doc, out, _ = verify_json(AID)
record("baseline verifies and exits 0",
       rc == 0 and doc and doc.get("outcome") == "pass",
       f"rc={rc} outcome={doc.get('outcome') if doc else None}")

# 2. stdout carries exactly one JSON document, no leading/trailing noise
record("verify --format json stdout is exactly one document",
       out.strip().startswith("{") and out.strip().endswith("}")
       and out.count("\n{") == 0,
       f"{len(out)} bytes")

# 3-6. tamper each signed field -> must fail AND exit nonzero
for field, val in [("actor", "agent:ATTACKER"), ("action", "probe.ESCALATED"),
                   ("timestamp", "2099-01-01T00:00:00Z"), ("type", "treeship/action/v99")]:
    restore = mutate(AID, lambda i, d, f=field, v=val: i.__setitem__(f, v))
    rc, doc, _, _ = verify_json(AID)
    record(f"tampered {field!r} is rejected",
           rc != 0 and doc and doc.get("outcome") != "pass",
           f"rc={rc} outcome={doc.get('outcome') if doc else 'UNPARSEABLE'}")
    restore()

# 7. strip signatures entirely -> must NOT pass vacuously ("0 checks, all green")
orig = open(art_path(AID)).read()
d = json.loads(orig); d["envelope"]["signatures"] = []
save(AID, d)
rc, doc, _, _ = verify_json(AID)
record("empty signature array does not pass vacuously",
       rc != 0 and doc and doc.get("outcome") != "pass",
       f"rc={rc} outcome={doc.get('outcome') if doc else 'UNPARSEABLE'} passed={doc.get('passed') if doc else '?'}")
open(art_path(AID), "w").write(orig)

# 8. flip a single byte of the signature -> must fail
restore_raw = open(art_path(AID)).read()
d = json.loads(restore_raw)
sig = d["envelope"]["signatures"][0]["sig"]
flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
d["envelope"]["signatures"][0]["sig"] = flipped
save(AID, d)
rc, doc, _, _ = verify_json(AID)
record("corrupted signature is rejected",
       rc != 0 and doc and doc.get("outcome") != "pass",
       f"rc={rc} outcome={doc.get('outcome') if doc else 'UNPARSEABLE'}")
open(art_path(AID), "w").write(restore_raw)

# 9. truncated JSON -> must error, never pass
open(art_path(AID), "w").write(restore_raw[: len(restore_raw) // 2])
rc, doc, _, _ = verify_json(AID)
record("truncated artifact is rejected",
       rc != 0 and (doc is None or doc.get("outcome") != "pass"), f"rc={rc}")
open(art_path(AID), "w").write(restore_raw)

# 10. empty file -> must error, never pass
open(art_path(AID), "w").write("")
rc, doc, _, _ = verify_json(AID)
record("empty artifact file is rejected",
       rc != 0 and (doc is None or doc.get("outcome") != "pass"), f"rc={rc}")
open(art_path(AID), "w").write(restore_raw)

# 11. nonexistent artifact -> must error, never pass
rc, doc, _, _ = verify_json("art_deadbeefdeadbeef")
record("nonexistent artifact is rejected",
       rc != 0 and (doc is None or doc.get("outcome") != "pass"), f"rc={rc}")

# 12. restored artifact still verifies -- proves the probes were reversible
#     and that a PASS above was not just "everything fails now"
rc, doc, _, _ = verify_json(AID)
record("baseline still verifies after all probes",
       rc == 0 and doc and doc.get("outcome") == "pass", f"rc={rc}")

print()
bad = [r for r in results if not r[0]]
print(f"{len(results) - len(bad)}/{len(results)} probes passed")
sys.exit(1 if bad else 0)
