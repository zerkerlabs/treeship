#!/usr/bin/env python3
"""Static route-health check for the Treeship docs site.

Walks every `meta.json` under `docs/content/docs/` and asserts:

  1. Every page listed in a section's `pages` array resolves to a real
     `.mdx` file in the same folder, or to a sub-folder with its own
     `meta.json`. Catches the failure mode where a sidebar entry points
     at a renamed/deleted file -- the page 404s the moment a user clicks
     it.

  2. Every section root (the URL `/<section>` without a page slug) has
     a way to resolve. Either:
       - the folder contains an `index.mdx` (fumadocs treats this as the
         section's root page), OR
       - `docs/next.config.mjs` declares a redirect from `/<section>` to
         a real first page.
     Catches the failure mode where typing `/cli` directly returns 404
     because no index page exists and no redirect was wired.

  3. Every redirect in `docs/next.config.mjs` points at a destination
     that exists on disk. A redirect to a deleted page is a hidden
     404 -- the redirect itself returns 308, but the user lands on
     a missing page.

Exits non-zero on any failure. Designed to run in CI on every PR; see
`.github/workflows/ci.yml` for the wiring.

Run locally:
    python3 scripts/check-docs-routes.py

Run with extra detail:
    python3 scripts/check-docs-routes.py --verbose
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT       = Path(__file__).resolve().parents[1]
DOCS_CONTENT    = REPO_ROOT / "docs" / "content" / "docs"
NEXT_CONFIG     = REPO_ROOT / "docs" / "next.config.mjs"


class Failure:
    __slots__ = ("kind", "where", "detail")

    def __init__(self, kind: str, where: str, detail: str) -> None:
        self.kind   = kind
        self.where  = where
        self.detail = detail

    def __str__(self) -> str:
        return f"  ✗ [{self.kind}] {self.where}\n      {self.detail}"


def load_meta(meta_path: Path) -> dict:
    with meta_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_redirects(config_path: Path) -> list[tuple[str, str]]:
    """Pull `(source, destination)` pairs out of next.config.mjs.

    The config is JS, not JSON, so we use a regex tolerant of the
    file's known shape (object literal entries inside the redirects()
    return). Each pair is recorded; flags like `permanent` are
    ignored. If the parser misses a redirect it surfaces as a
    "destination not found" failure during the section-root check,
    which is loud enough to debug.
    """
    text = config_path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"\{\s*source:\s*'([^']+)'\s*,\s*destination:\s*'([^']+)'",
        re.MULTILINE,
    )
    return [(m.group(1), m.group(2)) for m in pattern.finditer(text)]


def page_resolves(folder: Path, page: str) -> bool:
    """A page name listed in meta.json resolves when:

      - `<folder>/<page>.mdx` exists (a leaf doc), OR
      - `<folder>/<page>/meta.json` exists (a sub-section).
    """
    if (folder / f"{page}.mdx").is_file():
        return True
    if (folder / page / "meta.json").is_file():
        return True
    return False


def section_path_from_meta(meta_path: Path) -> str:
    """Convert a meta.json path on disk into the URL-style section
    path (e.g. `docs/content/docs/cli/meta.json` -> `cli`,
    `docs/content/docs/meta.json` -> `` (root)).
    """
    rel = meta_path.parent.relative_to(DOCS_CONTENT)
    return str(rel) if str(rel) != "." else ""


def collect_failures() -> list[Failure]:
    failures: list[Failure] = []

    # Walk every meta.json in content/docs.
    metas = sorted(DOCS_CONTENT.rglob("meta.json"))
    if not metas:
        failures.append(Failure(
            "structure", str(DOCS_CONTENT),
            "no meta.json files found -- docs content directory missing or empty",
        ))
        return failures

    redirects = parse_redirects(NEXT_CONFIG) if NEXT_CONFIG.is_file() else []
    redirect_sources = {src.lstrip("/") for src, _ in redirects}

    for meta_path in metas:
        folder = meta_path.parent
        try:
            meta = load_meta(meta_path)
        except json.JSONDecodeError as e:
            failures.append(Failure(
                "json", str(meta_path.relative_to(REPO_ROOT)),
                f"invalid JSON: {e}",
            ))
            continue

        pages = meta.get("pages", [])
        if not isinstance(pages, list):
            failures.append(Failure(
                "schema", str(meta_path.relative_to(REPO_ROOT)),
                "`pages` is not an array",
            ))
            continue

        # 1. Every listed page resolves to a real file or sub-section.
        for page in pages:
            if not isinstance(page, str):
                failures.append(Failure(
                    "schema", str(meta_path.relative_to(REPO_ROOT)),
                    f"page entry is not a string: {page!r}",
                ))
                continue
            if not page_resolves(folder, page):
                section = section_path_from_meta(meta_path)
                full = f"/{section}/{page}".replace("//", "/").rstrip("/") or "/"
                failures.append(Failure(
                    "missing-page", str(meta_path.relative_to(REPO_ROOT)),
                    f"page '{page}' listed in meta.json has no .mdx file or sub-meta -- {full} would 404",
                ))

        # 2. Section root resolution. Skip the top-level meta (the docs
        #    landing redirects to /guides/introduction in
        #    `app/[[...slug]]/page.tsx`, which is correct).
        section = section_path_from_meta(meta_path)
        if section == "":
            continue

        has_index   = (folder / "index.mdx").is_file()
        has_redirect = section in redirect_sources or f"{section}/" in redirect_sources

        # First page in `pages` -- if it resolves to an .mdx in this
        # folder, the user could have intended it as the implicit
        # section root.
        first_page  = pages[0] if pages else None
        first_resolves = bool(first_page and (folder / f"{first_page}.mdx").is_file())

        if not has_index and not has_redirect:
            if first_resolves:
                detail = (
                    f"section /{section} has no index.mdx and no "
                    f"redirect in next.config.mjs. Add: "
                    f"{{ source: '/{section}', destination: '/{section}/{first_page}', permanent: false }}"
                )
            else:
                detail = (
                    f"section /{section} has no index.mdx and no "
                    f"redirect in next.config.mjs (and the first page "
                    f"in meta.json does not resolve either)"
                )
            failures.append(Failure(
                "section-root", str(meta_path.relative_to(REPO_ROOT)),
                detail,
            ))

    # 3. Every redirect destination resolves to a real page.
    for src, dst in redirects:
        # Skip the broad `/docs/:path*` rewrite (path-passthrough).
        if ":path" in dst or ":path" in src:
            continue
        rel = dst.lstrip("/")
        # The destination is a URL; map it back to a file. URL "cli/overview"
        # -> docs/content/docs/cli/overview.mdx.
        target_mdx  = DOCS_CONTENT / f"{rel}.mdx"
        target_meta = DOCS_CONTENT / rel / "meta.json"
        if not target_mdx.is_file() and not target_meta.is_file():
            failures.append(Failure(
                "broken-redirect", str(NEXT_CONFIG.relative_to(REPO_ROOT)),
                f"redirect {src} -> {dst} but neither {target_mdx.relative_to(REPO_ROOT)} "
                f"nor {target_meta.relative_to(REPO_ROOT)} exists",
            ))

    return failures


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print every section/page checked, not just failures.",
    )
    args = parser.parse_args(list(argv))

    if not DOCS_CONTENT.is_dir():
        print(f"::error::{DOCS_CONTENT} not found", file=sys.stderr)
        return 2

    failures = collect_failures()

    if args.verbose:
        metas = sorted(DOCS_CONTENT.rglob("meta.json"))
        print(f"checked {len(metas)} meta.json file(s)")

    if failures:
        print(f"\nDocs route health: {len(failures)} failure(s)\n", file=sys.stderr)
        for f in failures:
            print(str(f), file=sys.stderr)
        print("\nFix these before merging. Each failure represents a route a", file=sys.stderr)
        print("user (or AI agent) hitting the docs site would see as a 404.\n", file=sys.stderr)
        return 1

    metas = sorted(DOCS_CONTENT.rglob("meta.json"))
    print(f"  ✓ docs route health: {len(metas)} meta.json file(s) checked, all routes resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
