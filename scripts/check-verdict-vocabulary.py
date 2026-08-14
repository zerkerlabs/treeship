#!/usr/bin/env python3
"""Fail when a surface prints a verdict word DESIGN.md does not sanction.

DESIGN.md's verdict table says "no synonyms (`valid`/`ok`/`passed` for the same
state is a bug)". Nothing enforced it, and the 2026-08 dogfood found three
vocabularies in one product: the spec listed words nothing printed (`full
pass`, `permitted`), the CLI printed words the spec did not name (`asserted`,
33 sites), and the website verifier had invented four more.

The rule was written down, the file was in the repo, and a new surface still
invented its own set. That is what a spec nothing checks is worth.

# What this catches, and what it deliberately does not

It looks for a fixed list of KNOWN SYNONYMS -- words that name a state the
table already has a canonical word for. It does not try to detect "any word
that might be a verdict", which would need to understand intent and would
produce false positives on every comment and doc sentence containing "valid".

So this is a ratchet, not a proof: it stops the specific drift already
observed, and each new synonym found in review gets added here so it cannot
come back. Narrow and reliable beats broad and ignored.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESIGN = os.path.join(REPO, "DESIGN.md")

# Surfaces bound by the table. Marketing type/colour is out of scope; its
# verdict words are not (DESIGN.md, 2026-08-14).
SEARCH_ROOTS = [
    ("packages/cli/src", (".rs",)),
    ("packages/core/src", (".rs",)),
    ("packages/sdk-ts/src", (".ts",)),
    ("packages/verify-js/src", (".ts", ".js")),
]

# banned -> the canonical word from DESIGN.md that already covers it.
#
# Each entry is a synonym actually observed in the wild, not a hypothetical.
BANNED = {
    "structural-only": "structural-pass",
    "signed-unpinned": "asserted",
    "full pass": "verified",
    "self-asserted": "asserted",
}

# Contexts where a banned string is not a verdict being printed. Kept explicit
# rather than clever: a heuristic that guesses would eventually hide a real one.
ALLOW_LINE_MARKERS = (
    "check-verdict-vocabulary",  # this file's own name in a comment
    "DESIGN.md",  # prose citing the table
    "structural-only`",  # a doc mapping the divergence, not emitting it
)

# Deliberate, dated exceptions. Each names the reason and the condition for
# removal, because an exception list without those becomes the place drift
# hides -- which is how the vocabulary reached three variants in the first
# place.
#
# (path, line-substring) -> reason
EXCEPTIONS = {
    (
        "packages/cli/src/commands/capability.rs",
        '"self-asserted"',
    ): "wire value in verify-capability JSON output; renaming is a breaking "
    "change for consumers. Change at the next major, together with the "
    "verify-js type below.",
    (
        "packages/verify-js/src/index.ts",
        "status?: 'verified' | 'self-asserted' | 'violations'",
    ): "published TypeScript union mirroring the wire value above. Same "
    "breaking-change constraint; the two must move together or the type "
    "stops describing the payload.",
}


def is_excepted(relpath, line):
    for (path, marker), _reason in EXCEPTIONS.items():
        if relpath == path and marker in line:
            return True
    return False


def offenders():
    found = []
    for rel, exts in SEARCH_ROOTS:
        root = os.path.join(REPO, rel)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.endswith(exts):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    with open(path, encoding="utf-8") as f:
                        lines = f.readlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for i, line in enumerate(lines, 1):
                    if any(m in line for m in ALLOW_LINE_MARKERS):
                        continue
                    rel = os.path.relpath(path, REPO)
                    if is_excepted(rel, line):
                        continue
                    for bad, canonical in BANNED.items():
                        # Only inside a string literal: a Rust identifier or a
                        # comment mentioning the word is not a surface printing
                        # it, and failing on those trains people to add
                        # allow-markers until the check means nothing.
                        if re.search(r'["\'][^"\']*' + re.escape(bad) + r'[^"\']*["\']', line):
                            found.append(
                                (
                                    os.path.relpath(path, REPO),
                                    i,
                                    bad,
                                    canonical,
                                    line.strip()[:88],
                                )
                            )
    return found


def table_is_present():
    """The check is meaningless if the table it enforces has been removed."""
    with open(DESIGN, encoding="utf-8") as f:
        design = f.read()
    return "## Verdict vocabulary" in design and "`asserted`" in design


def main():
    if not table_is_present():
        print("  err   DESIGN.md has no verdict vocabulary table to enforce")
        print("        This check exists to keep surfaces aligned with it; without")
        print("        the table it would pass vacuously.")
        return 1

    found = offenders()
    if not found:
        print(
            f"  ✓ no known verdict synonyms in the bound surfaces "
            f"({len(EXCEPTIONS)} dated exception(s))"
        )
        return 0

    for path, line, bad, canonical, text in found:
        print(f"  err   {path}:{line}: {bad!r} — DESIGN.md's word for this state is {canonical!r}")
        print(f"        {text}")
    print()
    print(
        f"{len(found)} verdict synonym(s). One state, one word, on every surface "
        "-- see the verdict table in DESIGN.md."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
