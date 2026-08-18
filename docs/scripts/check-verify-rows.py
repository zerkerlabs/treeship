#!/usr/bin/env python3
"""Check that verify check-row names quoted in the docs exist in the code.

A row name is what a reader sees in `treeship verify` / `package verify` output
and then searches the docs for. A name the docs invented sends them looking for
something that can never appear. Legacy names the code still references are
allowed — the docs may explain them, and this catches inventions, not history.

Usage: check-verify-rows.py <content-dir> <packages-dir>
Exit 1 if the docs quote a row name no emitter produces.
"""
import re, sys, json, subprocess
from pathlib import Path

CONTENT = Path(sys.argv[1])
PKGS = Path(sys.argv[2])

# Names constructed at an emit site: VerifyCheck::pass/fail/warn("row-name", …)
EMIT = re.compile(r'VerifyCheck::(?:pass|fail|warn|skip)\w*\(\s*"([a-z][a-z0-9_:-]*)"')
# Row-shaped identifiers the docs put in code spans.
PREFIXES = ("replay-", "approval-use", "nonce-binding", "trust-root",
            "session-participant", "receipt_body_binding", "merkle_root",
            "leaf_count", "timeline_order", "determinism")
QUOTED = re.compile(r'`([a-z][a-z0-9_-]*(?:[-:][a-z0-9_-]+)*)`')

emitted = set()
for f in PKGS.rglob("*.rs"):
    try:
        emitted |= set(EMIT.findall(f.read_text(errors="replace")))
    except OSError:
        pass
# Some rows are emitted with a dynamic suffix (inclusion:<artifact-id>).
emitted |= {n.split(":")[0] for n in emitted}

# Names the code references but no longer emits — e.g. a legacy label kept in a
# promotion set for external tooling. The docs may name these, as long as they
# say so; what must not appear is a name invented by the docs.
KNOWN = re.compile(r'"([a-z][a-z0-9_:-]*(?:[-:][a-z0-9_:-]+)+)"')
referenced = set()
for f in PKGS.rglob("*.rs"):
    try:
        referenced |= set(KNOWN.findall(f.read_text(errors="replace")))
    except OSError:
        pass
emitted |= referenced

bad = []
for f in sorted(CONTENT.rglob("*.mdx")):
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        for name in QUOTED.findall(line):
            if not name.startswith(PREFIXES):
                continue
            if name in emitted or name.split(":")[0] in emitted:
                continue
            bad.append({"file": str(f.relative_to(CONTENT.parent)), "line": i, "row": name})

print(json.dumps(bad, indent=2))
print(f"{len(emitted)} row names found in code; {len(bad)} quoted in docs that none emit",
      file=sys.stderr)
if not emitted:
    print("no emit sites matched — the parser found nothing to compare against", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if bad else 0)
