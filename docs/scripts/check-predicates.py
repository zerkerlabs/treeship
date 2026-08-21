#!/usr/bin/env python3
"""Diff the predicate registry against reference/predicates.mdx.

A registered predicate is schema-validated before signing, so its shape is a
contract a downstream verifier relies on. One that ships undocumented is a
contract nobody outside the repo can see.

Usage: check-predicates.py <content-dir> <predicates-schemas-dir>
Exit 1 if a registered predicate has no section, or the page documents one that
is not registered.
"""
import re, sys, json
from pathlib import Path

CONTENT = Path(sys.argv[1])
SCHEMAS = Path(sys.argv[2])
PAGE = CONTENT / "docs" / "reference" / "predicates.mdx"

registered = {p.name[:-5] for p in SCHEMAS.glob("*.json")}
text = PAGE.read_text()
# A predicate is "documented" when it has its own `### `kind`` section.
documented = set(re.findall(r'^###\s+`([a-z][a-z0-9_.-]*\.v[0-9])`', text, re.M))

missing = sorted(registered - documented)
extra = sorted(documented - registered)

for k in missing:
    print(f"UNDOCUMENTED  {k}  (schema ships in packages/core/src/predicates/schemas/)")
for k in extra:
    print(f"NOT REGISTERED  {k}  (documented but no schema)")

print(f"{len(registered)} registered, {len(documented)} documented, "
      f"{len(missing)} undocumented, {len(extra)} phantom", file=sys.stderr)
if not registered:
    print("no schemas found — wrong path?", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if (missing or extra) else 0)
