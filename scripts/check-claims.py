#!/usr/bin/env python3
"""
check-claims.py -- linter for docs/claims.yml and the security-sensitive
docs it registers.

Checks (errors):
  - claims.yml is well-formed YAML
  - every claim has a unique `id`, a `status` in the taxonomy, and a `says`
  - every `proof` path exists on disk
  - every phrase in the banned list (passphrase, machine-bound, tamper-proof,
    immutable, anchored, witnessed, air-gapped) that appears in one of
    `scanned_files` sits in a paragraph that also carries a claims marker --
    `<!-- claims:some-id -->` or `{/* claims:some-id */}` -- naming a real
    claims.yml id. A banned phrase with no marker in its paragraph is an
    error: either the wording needs a marker (it's a real, backed claim) or
    it needs rewriting (it isn't).
  - SECURITY.md's supported-versions table names the same minor as
    CHANGELOG.md's latest released version heading

Exit 0 with no errors, 1 otherwise.

Scope (docs re-test, 2026-09-27): the files claims.yml lists are checked as
before, and every page under docs/content, every root *.md and everything
under skills/ is scanned too. A marker covers only the line it sits on (or,
when it sits alone on a line, the next non-empty line); a banned phrase
elsewhere in the same paragraph is unbacked. Findings from the wider scan
and the finer marker rule are WARNINGS until `--strict` (the drift they
surface is being fixed separately); findings under the original rule on the
registered files stay errors either way.

Both scans look at prose only: fenced code blocks and inline `code spans`
are stripped before matching. A flag literally named `--max-unwitnessed`,
a JSON field named `anchored`, or a curl one-liner is a real identifier or
a code sample, not an unbacked claim about what Treeship does -- of the
124 wider-scope findings the 2026-09-27 retest turned up, 27 were this:
the banned word appeared only inside backticks or a fence, never in a
sentence making a claim.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CLAIMS_PATH = ROOT / "docs" / "claims.yml"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
SECURITY_PATH = ROOT / "SECURITY.md"

TAXONOMY = {"shipped", "next", "designed", "retired"}
BANNED_PHRASES = [
    "passphrase",
    "machine-bound",
    "tamper-proof",
    "immutable",
    "anchored",
    "witnessed",
    "air-gapped",
]
# `<!-- claims:some-id -->` (markdown) or `{/* claims:some-id */}` (mdx).
MARKER = re.compile(r"(?:<!--\s*claims:([a-z0-9-]+)\s*-->|\{/\*\s*claims:([a-z0-9-]+)\s*\*/\})")
INLINE_CODE = re.compile(r"`[^`]*`")
FENCE_LINE = re.compile(r"^\s*```")


def prose_only(text: str) -> str:
    """Drop fenced code blocks and inline code spans before a banned-phrase
    scan. A flag literally named `--max-unwitnessed`, a JSON field named
    `anchored`, or a curl one-liner is a real identifier or a code sample,
    not an unbacked prose claim about what Treeship does -- the registry
    exists to catch sentences, not to force a marker onto every doc page
    that names a real flag or field."""
    out_lines = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_LINE.match(line):
            in_fence = not in_fence
            out_lines.append("")
            continue
        out_lines.append("" if in_fence else INLINE_CODE.sub("", line))
    return "\n".join(out_lines)


SCAN_ROOTS = [ROOT / "docs" / "content", ROOT / "skills"]
ROOT_MD = sorted(ROOT.glob("*.md"))


def wider_files() -> list[str]:
    """Every doc the finer rule scans, as repo-relative paths."""
    out = []
    for root in SCAN_ROOTS:
        for p in sorted(root.rglob("*")):
            if p.suffix in (".md", ".mdx") and "node_modules" not in p.parts:
                out.append(str(p.relative_to(ROOT)))
    out.extend(str(p.relative_to(ROOT)) for p in ROOT_MD)
    return out


def covered_lines(lines: list[str]) -> dict[int, set[str]]:
    """Line index -> the marker ids that cover it. A marker covers its own
    line; a marker alone on its line also covers the next non-empty line
    (the way `<!-- claims:x -->` is written above a paragraph)."""
    cover: dict[int, set[str]] = {}
    for i, line in enumerate(lines):
        ids = {a or b for (a, b) in MARKER.findall(line)}
        if not ids:
            continue
        cover.setdefault(i, set()).update(ids)
        if MARKER.sub("", line).strip() == "":
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines):
                cover.setdefault(j, set()).update(ids)
    return cover


def line_findings(rel: str, text: str, valid_ids: set[str]) -> list[str]:
    """The finer rule: each banned phrase must sit on a covered line."""
    out = []
    lines = text.splitlines()
    cover = covered_lines(lines)
    clean_lines = prose_only(text).splitlines()
    for i, line in enumerate(lines):
        low = clean_lines[i].lower() if i < len(clean_lines) else line.lower()
        hits = [p for p in BANNED_PHRASES if p in low]
        if not hits:
            continue
        ids = cover.get(i, set())
        unknown = ids - valid_ids
        for u in sorted(unknown):
            out.append(f"{rel}:{i + 1}: claims marker '{u}' is not a known claims.yml id")
        if not ids:
            out.append(
                f"{rel}:{i + 1}: banned phrase(s) {hits} with no claims marker on this "
                f"line (or alone on the line above). Add `<!-- claims:id -->` for the "
                f"claims.yml entry that backs this sentence, or rewrite it."
            )
    return out


def paragraphs(text: str) -> list[tuple[int, str]]:
    """Split into (start_offset, paragraph_text) on blank lines."""
    out = []
    pos = 0
    for block in re.split(r"\n\s*\n", text):
        out.append((pos, block))
        pos += len(block) + 2
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    strict = "--strict" in argv
    errors: list[str] = []
    warnings: list[str] = []

    if not CLAIMS_PATH.exists():
        print(f"::error::{CLAIMS_PATH} not found", file=sys.stderr)
        return 1

    try:
        data = yaml.safe_load(CLAIMS_PATH.read_text())
    except yaml.YAMLError as e:
        print(f"::error::{CLAIMS_PATH}: malformed YAML: {e}", file=sys.stderr)
        return 1

    claims = data.get("claims", [])
    scanned_files = data.get("scanned_files", [])

    seen_ids: set[str] = set()
    valid_ids: set[str] = set()
    for c in claims:
        cid = c.get("id")
        if not cid:
            errors.append("a claim entry is missing `id`")
            continue
        if cid in seen_ids:
            errors.append(f"claim '{cid}': duplicate id")
        seen_ids.add(cid)
        valid_ids.add(cid)

        status = c.get("status")
        if status not in TAXONOMY:
            errors.append(f"claim '{cid}': status '{status}' not in {sorted(TAXONOMY)}")

        if not c.get("says"):
            errors.append(f"claim '{cid}': missing `says`")

        proof = c.get("proof")
        if not proof:
            errors.append(f"claim '{cid}': missing `proof`")
        elif not (ROOT / proof).exists():
            errors.append(f"claim '{cid}': proof path '{proof}' does not exist")

    # Banned-phrase scan, scoped to the registered files only. A banned
    # phrase is fine if its paragraph carries a claims marker for a real id;
    # otherwise it's an error.
    for rel in scanned_files:
        path = ROOT / rel
        if not path.exists():
            errors.append(f"scanned_files entry '{rel}' does not exist")
            continue
        text = path.read_text()
        lower = text.lower()
        for start, para in paragraphs(text):
            para_lower = prose_only(para).lower()
            hits = [p for p in BANNED_PHRASES if p in para_lower]
            if not hits:
                continue
            markers = MARKER.findall(para)
            marker_ids = {a or b for (a, b) in markers}
            unknown = marker_ids - valid_ids
            for u in unknown:
                line_no = text.count("\n", 0, start) + 1
                errors.append(f"{rel}:~{line_no}: claims marker '{u}' is not a known claims.yml id")
            if not marker_ids:
                line_no = text.count("\n", 0, start) + 1
                errors.append(
                    f"{rel}:~{line_no}: paragraph uses banned phrase(s) "
                    f"{hits} with no `<!-- claims:id -->` marker. Add a "
                    f"marker naming the claims.yml entry that backs this "
                    f"wording, or rewrite the paragraph."
                )

    # The finer rule over the wider scope: warnings until --strict.
    finer: list[str] = []
    for rel in wider_files():
        path = ROOT / rel
        try:
            finer.extend(line_findings(rel, path.read_text(encoding="utf-8"), valid_ids))
        except OSError:
            continue
    if finer:
        (errors if strict else warnings).extend(finer)

    # SECURITY.md supported-versions vs. CHANGELOG.md's latest release.
    if CHANGELOG_PATH.exists() and SECURITY_PATH.exists():
        changelog = CHANGELOG_PATH.read_text()
        version_heading = re.search(r"^## (\d+)\.(\d+)\.\d+ \(", changelog, re.MULTILINE)
        if version_heading:
            current_minor = f"{version_heading.group(1)}.{version_heading.group(2)}"
            security = SECURITY_PATH.read_text()
            if f"{current_minor}.x" not in security:
                warnings.append(
                    f"SECURITY.md's supported-versions table does not mention "
                    f"'{current_minor}.x', but CHANGELOG.md's latest release is "
                    f"{current_minor}.x"
                )
        else:
            warnings.append("CHANGELOG.md: no '## X.Y.Z (date)' heading found to check SECURITY.md against")

    for w in warnings:
        print(f"::warning::{w}")

    if errors:
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        print(f"\n{len(errors)} error(s), {len(warnings)} warning(s)", file=sys.stderr)
        return 1

    print(
        f"claims: {len(claims)} entries, {len(scanned_files)} registered file(s) plus "
        f"{len(wider_files())} scanned under the line rule"
        f"{'' if strict else ' (warn-only)'}, 0 errors, {len(warnings)} warning(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
