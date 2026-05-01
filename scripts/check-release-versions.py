#!/usr/bin/env python3
"""
check-release-versions.py — release-version preflight.

Diffs every package manifest, version file, and internal-dep pin against the
target version. Exits 0 if every site matches, 1 if any disagree (with a table
showing each disagreement).

Used by:
  - scripts/release.sh as a final assertion before tag/commit
  - .github/workflows/release.yml as a preflight job blocking build/publish

Usage:
  scripts/check-release-versions.py <version>
  scripts/check-release-versions.py 0.9.7

Why a single script: at v0.9.6 the Python SDK and three @treeship/core-wasm
internal pins all drifted independently. The fix is one source of truth that
both local releases and CI consult.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Site:
    """One place where a version string appears."""

    path: str
    label: str
    found: str | None  # None means "file/key missing"


# ---------- parsers ----------


def read_text(rel: str) -> str | None:
    p = REPO_ROOT / rel
    return p.read_text() if p.exists() else None


def cargo_package_version(rel: str) -> str | None:
    """Read [package] version from a Cargo.toml. First top-level `version =`."""
    text = read_text(rel)
    if text is None:
        return None
    in_package = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_package = s == "[package]"
            continue
        if in_package:
            m = re.match(r'^version\s*=\s*"([^"]+)"', s)
            if m:
                return m.group(1)
    return None


def cargo_dep_version(rel: str, dep_name: str) -> str | None:
    """Read a `name = { version = "X", ... }` style pin from Cargo.toml."""
    text = read_text(rel)
    if text is None:
        return None
    pattern = (
        rf'{re.escape(dep_name)}\s*=\s*\{{[^}}]*version\s*=\s*"([^"]+)"'
    )
    m = re.search(pattern, text)
    return m.group(1) if m else None


def pkg_json_version(rel: str) -> str | None:
    text = read_text(rel)
    if text is None:
        return None
    return json.loads(text).get("version")


def pkg_json_dep_version(rel: str, dep_name: str, *, group: str = "dependencies") -> str | None:
    text = read_text(rel)
    if text is None:
        return None
    return json.loads(text).get(group, {}).get(dep_name)


def pyproject_version(rel: str) -> str | None:
    text = read_text(rel)
    if text is None:
        return None
    in_project = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_project = s == "[project]"
            continue
        if in_project:
            m = re.match(r'^version\s*=\s*"([^"]+)"', s)
            if m:
                return m.group(1)
    return None


def py_dunder_version(rel: str) -> str | None:
    """Extract the version that ``__version__`` will resolve to at runtime.

    Three accepted forms:

      __version__ = "0.10.1"
        Literal string. Returned as-is.

      __version__ = _resolve_version()
        v0.10.1+ pattern: runtime resolution from
        importlib.metadata.version("treeship-sdk"). The metadata is
        whatever pip / build wrote into the installed dist's
        package metadata, which on every release pipeline is
        synthesized from pyproject.toml's [project] version. So
        when we see this pattern, treat pyproject.toml as
        authoritative and return that version.

      __version__ = importlib.metadata.version("treeship-sdk")
        Same intent, inline. Treated identically.

    Anything else (including absence of __version__) returns None,
    which the caller reports as "not found" and the release blocks.

    The check exists to catch drift across version sites; switching
    __init__.py to a metadata-derived form removes the drift class
    by construction (one source of truth, evaluated at runtime), so
    this function honors that contract by reading pyproject.toml's
    version when the metadata pattern is detected.
    """
    text = read_text(rel)
    if text is None:
        return None

    # Form 1: literal string.
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if m:
        return m.group(1)

    # Form 2 / Form 3: metadata-derived. Detect by name heuristic and
    # fall back to pyproject.toml in the same package directory. The
    # match is conservative -- we want a clear positive signal that
    # the file is using the metadata pattern rather than e.g. a stray
    # comment that mentions the words.
    metadata_pattern = re.search(
        r'__version__\s*=\s*('
        r'_resolve_version\s*\(\s*\)'
        r'|importlib\.metadata\.version\s*\('
        r'|version\s*\(\s*"treeship-sdk"\s*\)'
        r')',
        text,
    )
    if metadata_pattern:
        # Walk up to find the matching pyproject.toml. The Python SDK
        # is the only consumer of this codepath today; the layout is
        # packages/sdk-python/treeship_sdk/__init__.py and
        # packages/sdk-python/pyproject.toml.
        from pathlib import Path
        rel_path = Path(rel)
        for parent in rel_path.parents:
            candidate = parent / "pyproject.toml"
            if candidate.exists():
                return pyproject_version(str(candidate))
        return None

    return None


# ---------- site discovery ----------


def collect_sites() -> list[Site]:
    sites: list[Site] = []

    # Workspace Rust crates that are published or shipped as binaries.
    for rel, label in [
        ("packages/core/Cargo.toml", "rust crate treeship-core"),
        ("packages/cli/Cargo.toml", "rust crate treeship-cli"),
        ("packages/core-wasm/Cargo.toml", "rust crate treeship-core-wasm"),
    ]:
        sites.append(Site(rel, label, cargo_package_version(rel)))

    # Workspace-internal Cargo pin: cli depends on core at the same version.
    sites.append(
        Site(
            "packages/cli/Cargo.toml",
            "cargo dep treeship-core (in cli)",
            cargo_dep_version("packages/cli/Cargo.toml", "treeship-core"),
        )
    )

    # All published npm packages.
    for rel, label in [
        ("packages/sdk-ts/package.json", "npm @treeship/sdk"),
        ("bridges/mcp/package.json", "npm @treeship/mcp"),
        ("bridges/a2a/package.json", "npm @treeship/a2a"),
        ("packages/verify-js/package.json", "npm @treeship/verify"),
        ("npm/treeship/package.json", "npm treeship (wrapper)"),
        ("npm/@treeship/cli-linux-x64/package.json", "npm @treeship/cli-linux-x64"),
        ("npm/@treeship/cli-darwin-arm64/package.json", "npm @treeship/cli-darwin-arm64"),
        ("npm/@treeship/cli-darwin-x64/package.json", "npm @treeship/cli-darwin-x64"),
    ]:
        sites.append(Site(rel, label, pkg_json_version(rel)))

    # Internal pin: every package depending on @treeship/core-wasm must pin the
    # exact release version. A mismatch here is what shipped in 0.9.6: bridges
    # and verify-js declared 0.9.4/0.9.5 even though core-wasm itself was
    # published at 0.9.6.
    for rel in [
        "packages/sdk-ts/package.json",
        "bridges/mcp/package.json",
        "bridges/a2a/package.json",
        "packages/verify-js/package.json",
    ]:
        pin = pkg_json_dep_version(rel, "@treeship/core-wasm")
        if pin is not None:
            sites.append(
                Site(rel, f"npm dep @treeship/core-wasm (in {rel})", pin)
            )

    # The wrapper's optionalDependencies select the right CLI binary for each
    # platform; they MUST match the platform packages it routes to or `npm i
    # treeship` resolves to a stale binary.
    for cli in ("@treeship/cli-linux-x64", "@treeship/cli-darwin-arm64", "@treeship/cli-darwin-x64"):
        pin = pkg_json_dep_version(
            "npm/treeship/package.json", cli, group="optionalDependencies"
        )
        if pin is not None:
            sites.append(
                Site(
                    "npm/treeship/package.json",
                    f"npm wrapper optionalDependencies[{cli}]",
                    pin,
                )
            )

    # Python SDK: distribution metadata + runtime __version__. Drift between
    # these two is what produced the 0.9.6 PyPI miss.
    sites.append(
        Site(
            "packages/sdk-python/pyproject.toml",
            "pypi treeship-sdk (pyproject)",
            pyproject_version("packages/sdk-python/pyproject.toml"),
        )
    )
    sites.append(
        Site(
            "packages/sdk-python/treeship_sdk/__init__.py",
            "python treeship_sdk.__version__",
            py_dunder_version("packages/sdk-python/treeship_sdk/__init__.py"),
        )
    )

    return sites


# ---------- main ----------


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--consistency":
        # PR-time mode: there's no target version yet, but every site must agree
        # with each other. Anchor on packages/core/Cargo.toml (the foundational
        # crate every other package mirrors) and assert everyone else matches.
        # This catches drift weeks before a release tag would have caught it.
        sites = collect_sites()
        anchor = next(
            (s for s in sites if s.path == "packages/core/Cargo.toml" and s.label == "rust crate treeship-core"),
            None,
        )
        if anchor is None or anchor.found is None:
            print("::error::could not read anchor version from packages/core/Cargo.toml", file=sys.stderr)
            return 2
        target = anchor.found
        print(f"Consistency mode: anchoring on packages/core/Cargo.toml = {target}")
    elif len(argv) == 2:
        target = argv[1].lstrip("v")
        sites = collect_sites()
    else:
        print(f"usage: {argv[0]} <version>", file=sys.stderr)
        print(f"       {argv[0]} --consistency", file=sys.stderr)
        print(f"example: {argv[0]} 0.9.7", file=sys.stderr)
        return 2

    width = max(len(s.label) for s in sites) + 2
    rows: list[tuple[str, str, str, str]] = []
    bad = 0
    missing = 0
    for s in sites:
        if s.found is None:
            mark = "?"
            missing += 1
            shown = "(not found)"
        elif s.found == target:
            mark = "✓"
            shown = s.found
        else:
            mark = "✗"
            bad += 1
            shown = s.found
        rows.append((mark, s.label.ljust(width), shown, s.path))

    print(f"Checking every release-version site against {target}")
    print()
    for mark, label, found, path in rows:
        print(f"  {mark} {label} {found:<10}  {path}")
    print()
    print(f"  total: {len(sites)}   ok: {len(sites) - bad - missing}   wrong: {bad}   not-found: {missing}")

    if missing > 0:
        print(f"\n::error::{missing} site(s) could not be read. Investigate before releasing.", file=sys.stderr)
    if bad > 0:
        print(
            f"\n::error::{bad} site(s) disagree with target version {target}. "
            "Run scripts/release.sh to bump every site, or fix the script if a "
            "new version-bearing file was added.",
            file=sys.stderr,
        )

    return 0 if (bad == 0 and missing == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
