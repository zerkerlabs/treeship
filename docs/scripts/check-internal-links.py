#!/usr/bin/env python3
"""Resolve every root-relative internal link against the content tree.

Usage: check-internal-links.py <content-dir>
Exit 1 if any link points at a page that does not exist.
"""
import re, sys, json
from pathlib import Path

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

# any root-relative markdown link that is not an asset or an external URL
LINK = re.compile(r'\]\((/[^)\s#]*)(#[^)\s]*)?\)')
ASSET = re.compile(r'\.(png|jpg|jpeg|svg|gif|webp|yaml|yml|json|txt|ico|pdf)$')
bad = []
for f in sorted(CONTENT.rglob("*.mdx")):
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        for m in LINK.finditer(line):
            target = m.group(1).rstrip("/")
            if ASSET.search(target):
                continue
            # fumadocs serves docs under /docs; a bare /cli/x means /docs/cli/x
            cands = {target}
            if not target.startswith(("/docs", "/blog")):
                cands.add("/docs" + target)
            if any(c in known or c + "/" in known for c in cands):
                continue
            bad.append({
                "file": str(f.relative_to(CONTENT.parent)),
                "line": i,
                "target": m.group(1),
                "needs_docs_prefix": not m.group(1).startswith(("/docs", "/blog")),
            })
print(json.dumps(bad, indent=2))
print(f"{len(bad)} broken internal links", file=sys.stderr)
sys.exit(1 if bad else 0)
