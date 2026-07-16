#!/usr/bin/env python3
"""Fail if a spec in docs/specs/ has no row in the docs spec index.

The 2026-07 audit found 16 protocol specs with no index and several claiming
'not implemented' for shipped features. reference/specs.mdx is the index;
this check keeps it complete — every docs/specs/*.md must be linked there.
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS = os.path.join(REPO, "docs", "specs")
INDEX = os.path.join(REPO, "docs", "content", "docs", "reference", "specs.mdx")


def main():
    with open(INDEX) as f:
        index = f.read()

    missing = [
        name
        for name in sorted(os.listdir(SPECS))
        if name.endswith(".md") and f"docs/specs/{name}" not in index
    ]
    if missing:
        for name in missing:
            print(f"  err   docs/specs/{name} has no row in reference/specs.mdx")
        print(f"\n{len(missing)} unindexed spec(s). Add rows with an honest status.")
        return 1
    print("  ✓ every spec in docs/specs/ is indexed in reference/specs.mdx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
