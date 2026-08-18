#!/usr/bin/env python3
"""Check that session event types quoted in the docs are ones the core serializes.

`SessionEventType` in packages/core/src/session/event.rs is the wire vocabulary.
A docs page naming an event that never serializes sends a reader matching on
receipt timelines after something that cannot appear.

Only tables with an "Event" header column are scanned — that is where event
vocabularies are actually documented, and it keeps dotted JSON field paths in
prose from being mistaken for event names. Tables under a proposed/design
heading are skipped: a design page may name a future vocabulary as long as it
says so.

Usage: check-event-types.py <content-dir> <event.rs path>
"""
import re, sys, json
from pathlib import Path

CONTENT = Path(sys.argv[1])
EVENT_RS = Path(sys.argv[2])

real = set(re.findall(r'serde\(rename\s*=\s*"([a-z][a-z0-9_.]*)"\)', EVENT_RS.read_text()))
# Only look inside tables that declare themselves to be about events. Prose is
# full of dotted JSON field paths (`session.id`, `actor.uri`) that look like
# event names and are not; scanning them produced only false positives.
TABLE_HDR = re.compile(r'^\|\s*(?:Proposed\s+)?Event\s*\|', re.I)
CANDIDATE = re.compile(r'`([a-z][a-z0-9_]*\.[a-z_]+)`')
PROPOSED = re.compile(r"proposed|not implemented|design, not|do not match", re.I)

bad = []
for f in sorted(CONTENT.rglob("*.mdx")):
    lines = f.read_text(errors="replace").splitlines()
    # A heading or callout marking a region proposed suppresses it until the
    # next H2/H3.
    suppressed = False
    in_table = False
    for i, line in enumerate(lines, 1):
        if re.match(r'^#{2,3}\s', line):
            suppressed = bool(PROPOSED.search(line))
            in_table = False
        elif PROPOSED.search(line):
            suppressed = True
        if TABLE_HDR.match(line):
            in_table = True
            continue
        if in_table and not line.startswith('|'):
            in_table = False
        if not in_table:
            continue
        for name in CANDIDATE.findall(line):
            if name in real or suppressed:
                continue
            bad.append({"file": str(f.relative_to(CONTENT.parent)), "line": i, "event": name})

print(json.dumps(bad, indent=2))
print(f"{len(real)} event types in core; {len(bad)} quoted in docs that do not serialize",
      file=sys.stderr)
if not real:
    print("no event types parsed from event.rs", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if bad else 0)
