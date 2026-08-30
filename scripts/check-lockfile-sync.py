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

Two fields have to agree, not one. `npm ci` compares package.json against
BOTH the declared range in packages[""] and the version of the installed
entry in packages["node_modules/<name>"]:

    npm error Invalid: lock file's @treeship/core-wasm@0.25.0
              does not satisfy @treeship/core-wasm@0.25.1

v0.25.1 checked only the first and passed on a tree where `npm ci` failed in
every JS package on main -- the same outage as v0.25.0, reported green by the
check written to prevent it. A gate that verifies a strict subset of what the
real tool verifies will eventually pass something the real tool rejects.
"""

import json
import os
import re
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
# Between `release.sh prepare` and publish, the resolved entries legitimately
# lag the declared range: the version being released has no tarball yet, so
# there is no honest integrity hash to write (see scripts/lockfile-pin.py).
# On a release branch that is the expected state, not drift, and failing here
# would make every release PR unmergeable by a check the release itself
# created.
#
# Deliberately narrow: only the installed-entry half is relaxed, only on a
# release branch. The declared-range half -- the one that made main
# unbuildable at v0.25.0 -- still runs everywhere, and `refresh-lockfiles`
# after publish restores the resolved entries so the full check applies to
# main.
_ref = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or ""
RELEASE_WINDOW = _ref.startswith("release/v")

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
    """The declared ranges recorded in the lockfile's root entry."""
    with open(pkg / "package-lock.json", encoding="utf-8") as f:
        d = json.load(f)
    root = d.get("packages", {}).get("", {})
    out = {}
    for key in ("dependencies", "peerDependencies"):
        out.update(root.get(key, {}))
    return out


def installed(pkg: Path) -> dict:
    """The concrete version of each entry the lockfile would install.

    This is the half `npm ci` rejects on and the half the check used to miss.
    """
    with open(pkg / "package-lock.json", encoding="utf-8") as f:
        d = json.load(f)
    out = {}
    for path, entry in d.get("packages", {}).items():
        if not path.startswith("node_modules/"):
            continue
        name = path[len("node_modules/") :]
        # Nested paths (a/node_modules/b) describe a dependency's own tree,
        # not this package's top-level resolution.
        if "/node_modules/" in path:
            continue
        if "version" in entry:
            out[name] = entry["version"]
    return out


def main() -> int:
    checked = 0
    bad = []
    for rel in discover(ROOT):
        pkg = ROOT / rel
        if not (pkg / "package.json").is_file() or not (pkg / "package-lock.json").is_file():
            continue
        checked += 1
        dec, lck, inst = declared(pkg), locked(pkg), installed(pkg)
        for name, want in dec.items():
            got = lck.get(name)
            if got != want:
                bad.append((rel, name, want, got, "declared range in the lockfile"))
                continue
            # Exact pins only. A range like ^1.2.0 is legitimately satisfied by
            # many versions, and deciding which needs a semver implementation;
            # every @treeship/* pin is exact, which is the case that broke.
            if re.fullmatch(r"\d+\.\d+\.\d+", want) and not RELEASE_WINDOW:
                res = inst.get(name)
                if res is not None and res != want:
                    bad.append((rel, name, want, res, "installed entry"))

    if not checked:
        # A check that examined nothing passes vacuously and reads as a pass.
        print("  err   no package/lockfile pairs found; this check would pass vacuously")
        return 1

    if bad:
        for rel, name, want, got, where in bad:
            print(f"  err   {rel}: {name} is {want!r} in package.json but {got!r} in the {where}")
        print()
        print(
            f"{len(bad)} mismatch(es). `npm ci` will refuse on every PR until the "
            "lockfiles are regenerated:  npm install --package-lock-only"
        )
        return 1

    if RELEASE_WINDOW:
        print(
            f"  ✓ declared ranges agree in {checked} package(s); installed-entry "
            f"check relaxed on release branch {_ref!r}"
        )
        print("        Run `scripts/release.sh refresh-lockfiles` after publish.")
    else:
        print(f"  ✓ package.json and lockfile agree in {checked} package(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
