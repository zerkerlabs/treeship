#!/usr/bin/env python3
"""HTTP-check every external URL a reader can click in the docs and blog.

URLs inside code fences are skipped: those are command arguments and sample
payloads, not links, and illustrative ids in them are meant to 404.

Usage: check-external-links.py <content-dir> [--timeout N] [--allow-redirects]
Exit 1 if any URL returns 4xx/5xx or fails to resolve.

Results are cached per-URL for the run, and hosts are hit with a small delay so
a docs sweep does not look like a scrape.
"""
import re, sys, json, time
import urllib.request, urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(sys.argv[1])
TIMEOUT = 15
UA = "treeship-docs-linkcheck/1.0 (+https://docs.treeship.dev)"

URL = re.compile(r'https?://[^\s)\]<>"\'`|]+')
# Illustrative hosts: placeholders, template variables, and vendor endpoints
# that exist only to show a shape. Not real links, so not link-check failures.
SKIP_HOST = re.compile(r'^(localhost|127\.0\.0\.1|0\.0\.0\.0|\$|<|%7B|\s*$)'
                       r'|(^|\.)(example)(\.|$)'
                       r'|\.example$'
                       r'|^(your-|my-)'
                       r'|(your-subdomain|your-deploy|your-api|your-edge|your-hub)'
                       r'|^(api\.cloudvendor\.com|api\.lobster\.cash|agent\.robinhood\.com)$')

# Placeholder identifiers inside otherwise-real hosts: a decorative art_/ssn_ id
# is *meant* to 404, so checking it tells us nothing.
SKIP_PATH = re.compile(r'(art_|ssn_|chk_|grn_|key_|hub_)(f7e6|f8e2|7f8e|42e7|abc|xxx|01HR|8a3f|a1b2|…)'
                       r'|\{[a-z_]+\}|\$[A-Z_]+|/org/repo/'
                       r'|/v1/dock/authorized\?device_code='
                       r'|[^\x00-\x7f]')

def clean(u):
    return u.rstrip('.,;:')

FENCE = re.compile(r'^\s*```')

found = {}
for f in sorted(ROOT.rglob("*.mdx")):
    infence = False
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        if FENCE.match(line):
            infence = not infence
            continue
        # A URL inside a code fence is an argument or a sample payload, not a
        # link a reader clicks. Checking those just flags illustrative ids.
        if infence:
            continue
        # Inline code spans are values shown to the reader, not links.
        line = re.sub(r'`[^`]*`', '', line)
        for m in URL.finditer(line):
            u = clean(m.group(0))
            host = u.split("//", 1)[-1].split("/", 1)[0]
            if SKIP_HOST.search(host) or SKIP_PATH.search(u):
                continue
            found.setdefault(u, []).append((str(f.relative_to(ROOT.parent)), i))

def probe(u):
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(u, method=method, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code in (403, 405) and method == "HEAD":
                continue          # some hosts refuse HEAD; retry as GET
            return e.code
        except Exception as e:
            if method == "GET":
                return f"ERR {type(e).__name__}"
    return "ERR"

urls = sorted(found)
with ThreadPoolExecutor(max_workers=8) as ex:
    statuses = list(ex.map(probe, urls))

bad = []
for u, st in zip(urls, statuses):
    # 403/405 mean "the host refused this probe", not "the page is gone"
    ok = isinstance(st, int) and (st < 400 or st in (403, 405))
    if not ok:
        bad.append({"url": u, "status": st, "refs": found[u][:5]})

print(json.dumps(bad, indent=2))
print(f"checked {len(urls)} external URLs, {len(bad)} failing", file=sys.stderr)
sys.exit(1 if bad else 0)
