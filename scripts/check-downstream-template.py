#!/usr/bin/env python3
"""Fail when the paper-receipt template changes without acknowledging the copy.

`packages/core/src/session/preview_template.html` is vendored into the website
(zerkerlabs/treeship.dev, `lib/receipt-preview/preview_template.html`) so the
online preview at /receipt/<id>/preview renders byte-identically to the
preview.html the CLI writes into a local package. That equivalence is the point
of the paper surface: pull the network cable and read the same document.

The website can check its own copy has not been edited in place. It cannot know
this file changed. That is the direction the failure actually travels, and it
already happened once: the Authority band was added here while the website copy
sat two bands behind, so the online receipt would have silently dropped the
authority story -- rendering fine, saying less.

So this is a deliberate snapshot. Changing the template fails CI until you bump
EXPECTED_SHA256, and the failure message names the file downstream that has to
move with it. Annoying by design: the alternative is a fork nobody notices.

To update:
  1. change the template
  2. copy it to the website repo and refresh its SOURCE.json
  3. put the new hash below
"""

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "packages" / "core" / "src" / "session" / "preview_template.html"

# sha256 of the template as last synced downstream.
EXPECTED_SHA256 = "ba08ea3dd0ca4dfcb672dfe1cc6f7c674063cce544801a8c3cd5bd19e3cf3887"

DOWNSTREAM = (
    "zerkerlabs/treeship.dev  lib/receipt-preview/preview_template.html\n"
    "                         lib/receipt-preview/SOURCE.json"
)


def main() -> int:
    if not TEMPLATE.is_file():
        print(f"  err   template missing: {TEMPLATE.relative_to(ROOT)}")
        return 1

    actual = hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()
    if actual == EXPECTED_SHA256:
        print("  ✓ paper-receipt template matches the copy vendored downstream")
        return 0

    print(f"  err   {TEMPLATE.relative_to(ROOT)} changed")
    print(f"        recorded {EXPECTED_SHA256[:16]}…")
    print(f"        actual   {actual[:16]}…")
    print()
    print("This template is vendored downstream. Update it there or the online")
    print("preview will render an older receipt than the packaged one:")
    print()
    print(f"  {DOWNSTREAM}")
    print()
    print("Then set EXPECTED_SHA256 in this script to:")
    print(f"  {actual}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
