#!/usr/bin/env python3
"""Fail when a package.json and its lockfile disagree.

`npm ci` refuses to run when the two are out of sync:

    npm error code EUSAGE
    `npm ci` can only install packages when your package.json and
    package-lock.json are in sync.

v0.25.0 shipped exactly that. `release.sh prepare` stamps every version site
including package.json, but did not update the lockfiles, so main declared
@treeship/core-wasm at 0.25.0 while every lockfile still said 0.24.0. Four
open PRs failed the same four JS jobs, and the failure looked like a problem
with each PR rather than with main.

Checked here rather than left to `npm ci` because the CI error names the
symptom and not the cause: a reader sees "your lockfile is out of date" on a
PR that never touched a lockfile.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every directory with both a package.json and a package-lock.json is in
# scope. An explicit list looks safer and is not: this list originally held
# only the four packages whose CI jobs broke at v0.25.0, so the three
# runtime-acceptance lockfiles drifted five releases behind on
# @treeship/verify with the gate reporting "4 package(s)" and passing.
#
# Discovering them means a new package is covered the day it is added rather
# than the day someone remembers to extend this list.
SKIP_DIRS = {"node_modules", ".git", "target", "dist", "pkg"}


def discover(root: Path):
    found = []
    for lock in sorted(root.rglob("package-lock.json")):
        rel = lock.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if (lock.parent / "package.json").is_file():
            found.append(str(rel.parent))
    return found


def declared(pkg: Path) -> dict:
    with open(pkg / "package.json", encoding="utf-8") as f:
        d = json.load(f)
    out = {}
    for key in ("dependencies", "peerDependencies"):
        out.update(d.get(key, {}))
    return out


def locked(pkg: Path) -> dict:
    with open(pkg / "package-lock.json", encoding="utf-8") as f:
        d = json.load(f)
    root = d.get("packages", {}).get("", {})
    out = {}
    for key in ("dependencies", "peerDependencies"):
        out.update(root.get(key, {}))
    return out


def main() -> int:
    checked = 0
    bad = []
    for rel in discover(ROOT):
        pkg = ROOT / rel
        if not (pkg / "package.json").is_file() or not (pkg / "package-lock.json").is_file():
            continue
        checked += 1
        dec, lck = declared(pkg), locked(pkg)
        for name, want in dec.items():
            got = lck.get(name)
            if got != want:
                bad.append((rel, name, want, got))

    if not checked:
        # A check that examined nothing passes vacuously and reads as a pass.
        print("  err   no package/lockfile pairs found; this check would pass vacuously")
        return 1

    if bad:
        for rel, name, want, got in bad:
            print(f"  err   {rel}: {name} is {want!r} in package.json but {got!r} in the lockfile")
        print()
        print(
            f"{len(bad)} mismatch(es). `npm ci` will refuse on every PR until the "
            "lockfiles are regenerated:  npm install --package-lock-only"
        )
        return 1

    print(f"  ✓ package.json and lockfile agree in {checked} package(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
