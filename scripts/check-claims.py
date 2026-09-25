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

Exit 0 with no errors, 1 otherwise. This is deliberately narrow: it only
scans the files claims.yml lists (the ones DSEC-1/DSEC-2/DSEC-3/DOC-8 named),
not every doc in the repo -- the same English words are used correctly
elsewhere (HTTP cache headers, workflow-declaration immutability) for
properties that have nothing to do with the keystore or the verifier.
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


def paragraphs(text: str) -> list[tuple[int, str]]:
    """Split into (start_offset, paragraph_text) on blank lines."""
    out = []
    pos = 0
    for block in re.split(r"\n\s*\n", text):
        out.append((pos, block))
        pos += len(block) + 2
    return out


def main() -> int:
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
            para_lower = para.lower()
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

    print(f"claims: {len(claims)} entries, {len(scanned_files)} files scanned, 0 errors, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
