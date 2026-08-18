#!/usr/bin/env python3
"""Fail when the docs name an install route that does not exist.

Three separate cases produced this file:

  * `first-run.mdx` offered "Homebrew, Cargo, or the binary download". There is
    no Homebrew formula -- `brew info treeship` returns "No available formula"
    -- and the quickstart it linked to never mentioned Homebrew either.
  * `cargo install treeship-cli` was described as "orphaned at v0.4.0", which
    implies you would get 0.4.0. All seven published versions are yanked, so
    crates.io reports `max_version: 0.0.0` and cargo fails outright.
  * A Kimi skill shipped `cargo install treeship-cli` as its install line and
    had to be corrected in a previous release.

Naming a route that does not exist costs more than listing one fewer option:
the reader tries it, it fails, and they cannot tell whether they mistyped it or
it was never real.

Network checks are opt-in via --online, because CI should not fail on a
registry outage. Offline it enforces the prose rules, which is where every one
of the three cases actually lived.
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "content" / "docs"

# Routes that do not exist. Each entry is a pattern plus why it is banned, so a
# failure explains itself rather than pointing at a list.
BANNED = [
    (
        re.compile(r"\bbrew install treeship\b|\bvia Homebrew\b|\bHomebrew,", re.I),
        "there is no Homebrew formula; `brew info treeship` returns 'No available formula'",
    ),
    (
        re.compile(r"cargo install\s+treeship-cli(?!\s*(--git|\s*`?\s*from\s+crates))", re.I),
        "every published treeship-cli version is yanked; cargo fails with "
        "'could not find treeship-cli in registry'",
    ),
]

# Lines that discuss the banned route rather than recommending it. Kept
# explicit: a heuristic would eventually hide a real recommendation.
DISCUSSION = re.compile(
    r"do not use|don't use|does not install|fails outright|used to offer|previously said|"
    r"no Homebrew formula|not on crates\.io|orphaned|yanked|would take several minutes",
    re.I,
)


def offenders():
    found = []
    for mdx in sorted(DOCS.rglob("*.mdx")):
        # The changelog records past mistakes verbatim; rewriting history to
        # satisfy a lint would defeat the point of having one.
        if mdx.name == "changelog.mdx":
            continue
        for n, line in enumerate(mdx.read_text(encoding="utf-8").splitlines(), 1):
            if DISCUSSION.search(line):
                continue
            for pat, why in BANNED:
                if pat.search(line):
                    found.append((mdx.relative_to(ROOT), n, why, line.strip()[:88]))
    return found


def crates_io_still_yanked():
    """Confirm the premise. If the crate is ever un-yanked, this check is wrong."""
    url = "https://crates.io/api/v1/crates/treeship-cli"
    req = urllib.request.Request(url, headers={"User-Agent": "treeship-docs-check"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    versions = data.get("versions", [])
    if not versions:
        return None, "no versions returned; cannot confirm"
    all_yanked = all(v.get("yanked") for v in versions)
    return all_yanked, f"{len(versions)} version(s), all yanked={all_yanked}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true", help="also verify the premise against crates.io")
    args = ap.parse_args()

    docs = list(DOCS.rglob("*.mdx"))
    if not docs:
        print("  err   no docs found; this check would pass vacuously")
        return 1

    if args.online:
        try:
            yanked, detail = crates_io_still_yanked()
        except Exception as e:  # noqa: BLE001 - a registry outage must not fail CI
            print(f"  note  could not reach crates.io ({e}); skipping premise check")
        else:
            if yanked is False:
                print("  err   treeship-cli is no longer fully yanked on crates.io "
                      f"({detail}). This check's premise changed -- revisit the docs "
                      "and this file together.")
                return 1
            print(f"  note  crates.io premise holds: {detail}")

    found = offenders()
    if found:
        for path, line, why, text in found:
            print(f"  err   {path}:{line}: names an install route that does not exist")
            print(f"        {text}")
            print(f"        why: {why}")
        print()
        print(f"{len(found)} nonexistent install route(s). A reader who tries one cannot "
              "tell whether they mistyped it or it was never real.")
        return 1

    print(f"  ✓ no nonexistent install routes in {len(docs)} docs pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
