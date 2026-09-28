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

from __future__ import annotations

import json
import os
import re
import subprocess
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

# After the release PR merges, main carries the bump but the packages are not
# on the registry yet, so the installed entries still lag until publish and
# `release.sh refresh-lockfiles` (T11). That state used to fail this check on
# main, and the tag landed on a red commit: exactly what branch protection is
# for. So an installed-entry mismatch is a WARN, not a FAIL, when the declared
# version is the release in flight (the version in packages/core/Cargo.toml)
# and that exact version is not yet on npm. The moment it is published the
# same mismatch fails again, which is what forces the refresh. A registry
# lookup that cannot answer (no network) keeps the old behaviour and fails.
CORE_CARGO = Path("packages/core/Cargo.toml")


def in_flight_version(root: Path) -> str | None:
    """The version being released: the `[package]` version of the core crate."""
    try:
        text = (root / CORE_CARGO).read_text(encoding="utf-8")
    except OSError:
        return None
    pkg = re.search(r"^\[package\](.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not pkg:
        return None
    m = re.search(r'^version\s*=\s*"([^"]+)"', pkg.group(1), re.M)
    return m.group(1) if m else None


def npm_published(name: str, version: str) -> bool | None:
    """Is `name@version` on the npm registry? True / False, or None when the
    registry could not be asked (network failure, npm missing)."""
    try:
        r = subprocess.run(
            ["npm", "view", f"{name}@{version}", "version", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    err = (r.stderr or "").lower()
    if r.returncode == 0:
        out = (r.stdout or "").strip()
        return out not in ("", "[]", "{}")
    if "e404" in err or "no match found" in err or "version not found" in err:
        return False
    return None

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


def root_versions(pkg: Path) -> tuple[str | None, str | None, str | None]:
    """(package.json version, lockfile top-level version, lockfile root entry
    version). The lockfile names the package's own version twice; `npm ci`
    tolerates a stale one, so nothing else catches a lockfile left at an old
    release (the openclaw plugin's read 0.10.3 at 0.31.10)."""
    with open(pkg / "package.json", encoding="utf-8") as f:
        declared_v = json.load(f).get("version")
    with open(pkg / "package-lock.json", encoding="utf-8") as f:
        lock = json.load(f)
    return declared_v, lock.get("version"), lock.get("packages", {}).get("", {}).get("version")


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


def main(root: Path = ROOT, lookup=npm_published) -> int:
    checked = 0
    bad = []
    warn = []
    in_flight = in_flight_version(root)
    for rel in discover(root):
        pkg = root / rel
        if not (pkg / "package.json").is_file() or not (pkg / "package-lock.json").is_file():
            continue
        checked += 1
        declared_v, lock_v, root_v = root_versions(pkg)
        if declared_v is not None:
            for where, got in (("lockfile version", lock_v), ("lockfile root entry", root_v)):
                if got is not None and got != declared_v:
                    bad.append((rel, "(package version)", declared_v, got, where))
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
                    if want == in_flight and lookup(name, want) is False:
                        warn.append((rel, name, want, res))
                    else:
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

    if warn:
        for rel, name, want, res in warn:
            print(
                f"  warn  {rel}: {name} is {want!r} in package.json but {res!r} in the "
                f"installed entry; {want} is the release in flight and is not on npm yet"
            )
        print()
        print(
            f"  ✓ declared ranges agree in {checked} package(s); {len(warn)} installed "
            f"{'entry lags' if len(warn) == 1 else 'entries lag'} the unpublished release {in_flight}"
        )
        print("        This fails once the version is published. Run `scripts/release.sh refresh-lockfiles` after publish.")
        return 0
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
