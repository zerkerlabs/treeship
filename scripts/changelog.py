#!/usr/bin/env python3
"""Changelog fragments: one file per change, folded into CHANGELOG.md at release.

Every PR used to add its bullet at the top of CHANGELOG.md's "## Unreleased"
section, so any two open PRs conflicted and every merge forced the rest to
rebase. A PR now adds one file under changelog.d/ instead; nothing else edits
the Unreleased section until a release folds the fragments in.

  changelog.py check [--base <ref>]   validate fragments; with --base, fail if
                                      the PR grew CHANGELOG.md's Unreleased
                                      section instead of adding a fragment
  changelog.py assemble <version>     move Unreleased bullets and all fragments
                                      under "## <version> (<date>)", delete the
                                      fragments (run by scripts/release.sh)
  changelog.py unreleased             print the Unreleased bullets plus the
                                      fragments (used by the docs changelog)
"""

import datetime
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"
FRAGMENTS = REPO / "changelog.d"
UNRELEASED = "## Unreleased"
FRAGMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.md$")


def fragment_files():
    if not FRAGMENTS.is_dir():
        return []
    return sorted(
        p for p in FRAGMENTS.iterdir()
        if p.is_file() and p.suffix == ".md" and p.name != "README.md"
    )


def read_fragment(path):
    return path.read_text(encoding="utf-8").strip("\n")


def split_unreleased(text):
    """Return (head, unreleased_body, tail) around the Unreleased section."""
    lines = text.split("\n")
    try:
        start = lines.index(UNRELEASED)
    except ValueError:
        sys.exit(f"CHANGELOG.md has no '{UNRELEASED}' heading")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    head = "\n".join(lines[: start + 1])
    body = "\n".join(lines[start + 1 : end]).strip("\n")
    tail = "\n".join(lines[end:])
    return head, body, tail


def count_bullets(body):
    return sum(1 for line in body.split("\n") if line.startswith("- "))


def cmd_check(args):
    problems = []
    for path in fragment_files():
        if not FRAGMENT_NAME.match(path.name):
            problems.append(f"{path.name}: name must be letters, digits, '.', '_' or '-', ending in .md")
        body = read_fragment(path)
        if not body.strip():
            problems.append(f"{path.name}: empty fragment")
        elif not body.lstrip().startswith("- "):
            problems.append(f"{path.name}: must start with a '- ' bullet")
        if re.search(r"^#", body, re.M):
            problems.append(f"{path.name}: no headings in a fragment; the release adds them")

    if "--base" in args:
        base = args[args.index("--base") + 1]
        try:
            base_text = subprocess.run(
                ["git", "show", f"{base}:CHANGELOG.md"],
                cwd=REPO, check=True, capture_output=True, text=True,
            ).stdout
        except subprocess.CalledProcessError as e:
            sys.exit(f"cannot read CHANGELOG.md at {base}: {e.stderr.strip()}")
        _, base_body, _ = split_unreleased(base_text)
        _, head_body, _ = split_unreleased(CHANGELOG.read_text(encoding="utf-8"))
        if count_bullets(head_body) > count_bullets(base_body):
            problems.append(
                "CHANGELOG.md: this PR adds bullets to '## Unreleased'. Put the entry in "
                "changelog.d/<task-or-topic>.md instead (see changelog.d/README.md); "
                "the release folds fragments in, so parallel PRs stop conflicting."
            )

    for p in problems:
        print(f"::error::{p}")
    if problems:
        sys.exit(1)
    print(f"changelog: {len(fragment_files())} fragment(s) ok")


def cmd_unreleased(_args):
    _, body, _ = split_unreleased(CHANGELOG.read_text(encoding="utf-8"))
    parts = [read_fragment(p) for p in fragment_files()]
    if body:
        parts.append(body)
    print("\n".join(parts))


def cmd_assemble(args):
    if not args:
        sys.exit("usage: changelog.py assemble <version>")
    version = args[0].lstrip("v")
    text = CHANGELOG.read_text(encoding="utf-8")
    if re.search(rf"^## {re.escape(version)}\b", text, re.M):
        sys.exit(f"CHANGELOG.md already has a '## {version}' section")
    head, body, tail = split_unreleased(text)
    frags = fragment_files()
    entries = [read_fragment(p) for p in frags]
    if body:
        entries.append(body)
    if not entries:
        sys.exit("nothing to release: no fragments and an empty Unreleased section")
    today = datetime.date.today().isoformat()
    section = f"## {version} ({today})\n\n" + "\n".join(entries)
    new = f"{head}\n\n{section}\n\n{tail.lstrip(chr(10))}"
    CHANGELOG.write_text(new.rstrip("\n") + "\n", encoding="utf-8")
    for p in frags:
        p.unlink()
    print(f"changelog: folded {len(frags)} fragment(s) into ## {version}")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"check", "assemble", "unreleased"}:
        sys.exit(__doc__)
    {"check": cmd_check, "assemble": cmd_assemble, "unreleased": cmd_unreleased}[
        sys.argv[1]
    ](sys.argv[2:])


if __name__ == "__main__":
    main()
