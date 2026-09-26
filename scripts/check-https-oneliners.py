#!/usr/bin/env python3
"""Every advertised `curl … treeship.dev/setup` or `/install` one-liner names
the https scheme.

This used to be a `git grep -E '…\\b'` in the workflow. `\\b` after a group is
not portable: BSD grep on macOS does not treat it the way GNU grep does, so
the step passed locally on a line CI would fail, and nobody could reproduce
a red run. The check is plain Python now, with the boundary written out, and
it has a test with a known-bad line.

Usage: check-https-oneliners.py [--strict] [file ...]
Without files it scans the tracked sources CI scanned (*.md, *.mdx, *.ts,
*.tsx, *.mjs, *.sh, *.py). Exit 1 on a finding.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GLOBS = ["*.md", "*.mdx", "*.ts", "*.tsx", "*.mjs", "*.sh", "*.py"]
# A curl invocation whose target is treeship.dev/setup or /install, the path
# ending there (not /setup-foo, not /installer): the boundary is explicit.
ONE_LINER = re.compile(r"curl[^|\n]*treeship\.dev/(?:setup|install)(?![A-Za-z0-9_.-])")


def findings_in(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every one-liner whose target has no https://."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = ONE_LINER.search(line)
        if not m:
            continue
        # The workflow's rule: a line that names https:// anywhere is fine
        # (a changelog entry quoting the old scheme-less form next to the
        # fix is the legitimate case); the boundary on the path is what
        # was not portable.
        if "https://" not in line:
            out.append((i, line.strip()))
    return out


# The checker's own source and its test carry the bad form on purpose (the
# pattern, and the fixture lines); nothing a reader could copy lives there.
SELF = {"scripts/check-https-oneliners.py", "scripts/tests/test_check_https_oneliners.py"}


def tracked_files() -> list[Path]:
    r = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--", *GLOBS],
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / p for p in r.stdout.split() if p not in SELF]


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv if not a.startswith("--")]
    if not files:
        files = tracked_files()
    bad = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, line in findings_in(text):
            rel = path.relative_to(ROOT) if path.is_absolute() and str(path).startswith(str(ROOT)) else path
            bad.append(f"{rel}:{n}: {line[:160]}")
    if bad:
        for b in bad:
            print(f"  err   {b}")
        print(f"\n{len(bad)} curl one-liner(s) on treeship.dev with no https:// scheme")
        return 1
    print(f"  ✓ every advertised treeship.dev one-liner is https ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
