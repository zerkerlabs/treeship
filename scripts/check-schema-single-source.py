#!/usr/bin/env python3
"""Fail when the same schema exists twice and the copies disagree.

`schemas/treeship.boundary.v1.json` is the publishable, standalone copy for
external implementers. `packages/core/src/predicates/schemas/boundary.v1.json`
is the one the Rust predicate registry validates against at attest time.

Both carry the same `$id`. That is the problem this check exists for: an `$id`
is a canonical identifier, so two files claiming it means a resolver can get
either one, and nothing tells you which is authoritative. They were byte-for-
byte equivalent the day the second was added, which is exactly when the check
is cheap to write and worth writing.

This repo has produced the same failure three times in other forms -- three
verdict vocabularies, two redactors, two SSRF guards. Every one of them agreed
on the day it was duplicated. The pairs kept in step are the ones with a gate.

Compared semantically, not byte-wise: formatting, key order and indentation are
allowed to differ, because forcing them identical would make the publishable
copy unable to carry its own `$comment` prose. Structure and constraints are
not allowed to differ.
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (publishable copy, registry copy). Add a row when a schema gains a second home.
PAIRS = [
    (
        "schemas/treeship.boundary.v1.json",
        "packages/core/src/predicates/schemas/boundary.v1.json",
    ),
]

# Keys allowed to differ between copies. Deliberately short: each entry is a
# reason the two files are *supposed* to diverge, not a place to hide drift.
IGNORED_TOP_LEVEL = {
    "$comment",  # prose aimed at external implementers
    "$schema",  # draft version may differ with the validator used
    "title",
    "description",
}


def load(rel):
    path = os.path.join(REPO, rel)
    if not os.path.exists(path):
        return None, f"missing: {rel}"
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except (OSError, json.JSONDecodeError) as e:
        return None, f"unreadable: {rel}: {e}"


def normalize(doc):
    return {k: v for k, v in doc.items() if k not in IGNORED_TOP_LEVEL}


def compare(a, b, path=""):
    """Structural diff, returning human-readable divergences."""
    out = []
    if type(a) is not type(b):
        return [f"{path or '<root>'}: type {type(a).__name__} vs {type(b).__name__}"]
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            where = f"{path}.{key}" if path else key
            if key not in a:
                out.append(f"{where}: missing from the publishable copy")
            elif key not in b:
                out.append(f"{where}: missing from the registry copy")
            else:
                out.extend(compare(a[key], b[key], where))
    elif isinstance(a, list):
        # `required` and `enum` are sets in spirit; order carries no meaning.
        if sorted(map(repr, a)) != sorted(map(repr, b)):
            out.append(f"{path}: {a!r} vs {b!r}")
    elif a != b:
        out.append(f"{path}: {a!r} vs {b!r}")
    return out


def main():
    if not PAIRS:
        # A check with nothing to check passes vacuously and reads as a pass.
        print("  err   no schema pairs configured; this check would pass vacuously")
        return 1

    failed = False
    for pub_rel, reg_rel in PAIRS:
        pub, err1 = load(pub_rel)
        reg, err2 = load(reg_rel)
        for err in (err1, err2):
            if err:
                print(f"  err   {err}")
                failed = True
        if pub is None or reg is None:
            continue

        pub_id, reg_id = pub.get("$id"), reg.get("$id")
        if pub_id != reg_id:
            print(f"  err   {pub_rel} and {reg_rel} carry different $id values")
            print(f"        {pub_id!r} vs {reg_id!r}")
            print("        Either they are the same schema and must agree, or they")
            print("        are different schemas and must not share a filename.")
            failed = True

        diffs = compare(normalize(pub), normalize(reg))
        if diffs:
            print(f"  err   {pub_rel} and {reg_rel} claim $id {pub_id} and disagree:")
            for d in diffs[:12]:
                print(f"        {d}")
            if len(diffs) > 12:
                print(f"        ... and {len(diffs) - 12} more")
            print("        Two files, one canonical id. A resolver can get either.")
            failed = True
        else:
            print(f"  ✓ {os.path.basename(pub_rel)} agrees with the registry copy")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
