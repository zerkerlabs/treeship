#!/usr/bin/env python3
"""Fail when a merge-conflict marker is committed.

This exists because it happened. PR #308 committed nine markers into
`integrations/hermes/README.md`, including the `Updated upstream` /
`Stashed changes` pair a conflicted `git stash pop` leaves behind. A
`git add -A` swept the conflicted file in, the diff was large and about
something else, and every other gate passed -- none of them read that file.

The document was published to the docs site in that state.

Nothing here is clever. It is a grep that runs, which is the entire point:
the failure mode was not that the markers were hard to see, it was that
nothing looked.

Markers are matched only at the start of a line and with the exact widths git
writes, so prose *about* conflicts and any legitimate run of `=` in a table or
underline does not trip it.
"""

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# git writes exactly seven characters, at column zero.
PATTERNS = [
    r"^<<<<<<< ",
    r"^>>>>>>> ",
    r"^\|\|\|\|\|\|\| ",  # diff3 style base section
]

# `=======` alone is too common (markdown underlines, ASCII rules) to match on
# its own. It is only a conflict when it sits between the other two, which the
# patterns above already catch.

SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".next", "vendor"}


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    )
    for path in out.stdout.split("\0"):
        if not path:
            continue
        if any(part in SKIP_DIRS for part in path.split("/")):
            continue
        yield path


def main():
    import re

    compiled = [re.compile(p) for p in PATTERNS]
    hits = []
    checked = 0

    for rel in tracked_files():
        full = os.path.join(REPO, rel)
        try:
            with open(full, encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable; a marker cannot hide in a jpeg
        checked += 1
        # This file necessarily contains the patterns it searches for.
        if rel == "scripts/check-conflict-markers.py":
            continue
        for n, line in enumerate(lines, 1):
            if any(p.match(line) for p in compiled):
                hits.append((rel, n, line.rstrip()[:70]))

    if not checked:
        # A sweep that examined nothing passes vacuously and reads as a pass.
        print("  err   no tracked files were read; this check would pass vacuously")
        return 1

    if hits:
        for rel, n, text in hits:
            print(f"  err   {rel}:{n}: committed conflict marker")
            print(f"        {text}")
        print()
        print(
            f"{len(hits)} conflict marker(s) in tracked files. A conflicted "
            "`git stash pop` or merge was committed, most likely by `git add -A`."
        )
        return 1

    print(f"  ✓ no committed conflict markers ({checked} text files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
