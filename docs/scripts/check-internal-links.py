#!/usr/bin/env python3
"""Resolve every internal link -- root-relative or page-relative -- against
the content tree, using the same resolution a browser applies.

Usage: check-internal-links.py <content-dir>
Exit 1 if any link points at a page that does not exist.

Page-relative links (`./foo`, `foo`, `../foo`) resolve against the LINKING
PAGE'S OWN RENDERED URL, not its filesystem path, and a browser's rule for
that is stricter than it looks: the URL's last path segment is a directory
only if the URL ends in `/`. An index page renders at a URL with no trailing
slash (`/integrations`, not `/integrations/`), so `./foo` on that page
resolves to `/foo`, sibling to `/integrations`, not `/integrations/foo` --
every such link 404'd live before this checker learned the rule (2026-09-27).
"""
import re, sys, json
from pathlib import Path
from urllib.parse import urljoin

CONTENT = Path(sys.argv[1])          # docs/content
docs_root = CONTENT / "docs"
blog_root = CONTENT / "blog"

def slugs(root, prefix):
    out = set()
    for f in root.rglob("*.mdx"):
        rel = f.relative_to(root).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "index":
            parts = parts[:-1]
        out.add(prefix + "/".join(parts) if parts else prefix.rstrip("/"))
    return out

known = slugs(docs_root, "/docs/") | slugs(blog_root, "/blog/")
known |= {"/docs", "/blog", "/"}
# fumadocs folder index pages
for m in docs_root.rglob("meta.json"):
    known.add("/docs/" + str(m.parent.relative_to(docs_root)).strip("."))


def page_url(f: Path) -> str:
    """The rendered URL a source .mdx file's own links resolve relative to.
    Mirrors `slugs()`'s file->URL mapping so both stay consistent."""
    for root, prefix in ((docs_root, "/docs/"), (blog_root, "/blog/")):
        try:
            rel = f.relative_to(root).with_suffix("")
        except ValueError:
            continue
        parts = list(rel.parts)
        if parts and parts[-1] == "index":
            parts = parts[:-1]
        return prefix + "/".join(parts) if parts else prefix.rstrip("/")
    return "/"


# Any markdown link target that isn't an external URL, a bare anchor, or a
# mailto -- root-relative (`/foo`), page-relative (`./foo`, `foo`), or
# parent-relative (`../foo`) all match here; resolution tells them apart.
LINK = re.compile(r'\]\(([^)\s#]+)(#[^)\s]*)?\)')
EXTERNAL = re.compile(r'^([a-z][a-z0-9+.-]*:|#)', re.I)  # scheme: or mailto: or bare #
ASSET = re.compile(r'\.(png|jpg|jpeg|svg|gif|webp|yaml|yml|json|txt|ico|pdf)$')
bad = []
for f in sorted(CONTENT.rglob("*.mdx")):
    base = page_url(f)
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        for m in LINK.finditer(line):
            raw = m.group(1)
            if EXTERNAL.match(raw) or ASSET.search(raw):
                continue
            # Resolve exactly as a browser would: page-relative links use the
            # linking page's own URL as base, root-relative links ignore it.
            # Do NOT add a trailing slash to `base` -- fumadocs page URLs
            # normally have none, and adding one would silently "fix" the
            # exact resolution bug this checker exists to catch (an index
            # page's own URL has no trailing slash, so "./x" resolves
            # against its PARENT, not against it).
            target = urljoin(base, raw).rstrip("/") or "/"
            # fumadocs serves docs under /docs; a bare /cli/x means /docs/cli/x
            cands = {target}
            if not target.startswith(("/docs", "/blog")):
                cands.add("/docs" + target)
            if any(c in known or c + "/" in known for c in cands):
                continue
            bad.append({
                "file": str(f.relative_to(CONTENT.parent)),
                "line": i,
                "target": raw,
                "resolved": target,
                "relative": not raw.startswith("/"),
            })
print(json.dumps(bad, indent=2))
print(f"{len(bad)} broken internal links", file=sys.stderr)
sys.exit(1 if bad else 0)
