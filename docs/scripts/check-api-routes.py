#!/usr/bin/env python3
"""Diff the Hub API docs against the routes actually registered in the Go source.

Usage: check-api-routes.py <content-dir> <path-to-packages/hub/main.go>
Exit 1 if a route is implemented but undocumented, or documented but absent.

Path params are normalized ({id}, :id) and query strings dropped, so the docs may
write a route however reads best.
"""
import re, sys, json
from pathlib import Path

CONTENT = Path(sys.argv[1])
MAIN_GO = Path(sys.argv[2])

ROUTE = re.compile(r'\.(Get|Post|Put|Delete|Patch|Head)\("(/[^"]+)"')
DOC_PATTERNS = (
    re.compile(r'^\s*(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s`]+)', re.M),
    re.compile(r'`(GET|POST|PUT|DELETE|PATCH)\s+(/[^`\s]+)`'),
)

def norm(p):
    p = p.split('?')[0].rstrip('/`')
    p = re.sub(r'\{[^}]*\}|:[A-Za-z_]+|dck_\S+', '{}', p)
    return p

impl = set()
for m in ROUTE.finditer(MAIN_GO.read_text()):
    path = m.group(2)
    if path.startswith(("/v1", "/.well-known")):
        impl.add((m.group(1).upper(), norm(path)))

documented = {}
for f in sorted((CONTENT / "docs" / "api").glob("*.mdx")):
    text = f.read_text()
    for pat in DOC_PATTERNS:
        for m in pat.finditer(text):
            documented.setdefault((m.group(1), norm(m.group(2))), set()).add(f.name)

missing = sorted(impl - set(documented))
phantom = sorted(set(documented) - impl)

for method, path in missing:
    print(f"UNDOCUMENTED  {method:5} {path}")
for method, path in phantom:
    where = ", ".join(sorted(documented[(method, path)]))
    print(f"NOT IMPLEMENTED  {method:5} {path}   (documented in {where})")

print(f"{len(impl)} routes implemented, {len(documented)} documented, "
      f"{len(missing)} undocumented, {len(phantom)} phantom", file=sys.stderr)
sys.exit(1 if (missing or phantom) else 0)
