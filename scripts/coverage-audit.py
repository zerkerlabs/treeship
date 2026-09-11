#!/usr/bin/env python3
"""What shipped versus what is documented, per system and per release.

Buzz built Trusted Rooms in August 2026 and nothing public ever said so: the
changelog credited nobody and named no platform, so a log-only scan could not
find it. This script crosses four sources so that cannot happen quietly again:

  1. merged pull requests (title, branch, merge date)  -> what actually landed
  2. CHANGELOG.md sections                             -> what we told users
  3. docs (integration pages) and blog (systems axis)  -> what is explained
  4. the ecosystem card data on treeship.dev           -> what is presented

Usage:
  scripts/coverage-audit.py --prs <prs.tsv> [--site ../treeship.dev-repo]

  <prs.tsv> is `gh pr list --state merged --limit 500 --json
  number,title,mergedAt,headRefName --jq '.[] | "\\(.mergedAt[:10])\\t#\\(.number)
  \\t\\(.headRefName)\\t\\(.title)"'` (an author column between branch and title
  is tolerated). Tags come from git.

Output 1, the systems matrix: for every named system in VOCAB, how many PRs
name it, which release first mentioned it in the changelog, whether a docs
integration page, blog system id and ecosystem card exist. A system with PRs
and no changelog mention, or with a changelog mention and no page, is a gap.

Output 2, the release ledger: for every tag, the PRs merged in its window that
its changelog section does not reflect (no PR number, and fewer than two of
the title's distinctive words). Heuristic, so read it as a list to check, not
a verdict.

Exit code is 0; this is a report, not a gate. Add `--strict` to exit 1 when a
system has PRs but no changelog mention at all.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# id -> (label, regex over PR title+branch and changelog text, docs page slug or None)
VOCAB: dict[str, tuple[str, str, str | None]] = {
    "claude-code": ("Claude Code", r"claude[ -]?code|claude plugin", "claude-code"),
    "codex": ("Codex", r"\bcodex\b", "codex"),
    "cursor": ("Cursor", r"\bcursor\b", "cursor"),
    "hermes": ("Hermes", r"\bhermes\b", "hermes"),
    "openclaw": ("OpenClaw", r"openclaw", "openclaw"),
    "kimi": ("Kimi", r"\bkimi\b", "agent-skills"),
    "cline": ("Cline", r"\bcline\b", None),
    "goose": ("Goose", r"\bgoose\b", None),
    "perplexity": ("Perplexity", r"perplexity", None),
    "grok-bot": ("Grok Bot", r"\bgrok\b", None),
    "buzz": ("Buzz", r"\bbuzz\b", "buzz"),
    "mcp": ("MCP bridge", r"\bmcp\b", "mcp"),
    "a2a": ("A2A bridge", r"\ba2a\b|agent2agent", "a2a"),
    "commerce-agents": ("Claude Commerce Agents", r"commerce[- ]agents|treeship-commerce|treeship_commerce", "commerce-agents"),
    "langchain": ("LangChain", r"langchain", "langchain"),
    "rig": ("Rig", r"\brig\b|rig-treeship", None),
    "prime": ("Prime Agent / pi", r"\bprime\b|prime-treeship|\bpi agent\b", None),
    "verifiable-intent": ("Verifiable Intent", r"verifiable intent|\bvi\b|mastercard", "verifiable-intent"),
    "lobster-cash": ("Lobster Cash", r"lobster", "lobster-cash"),
    "robinhood": ("Robinhood", r"robinhood", "robinhood-agentic-trading"),
    "ninjatech": ("NinjaTech", r"ninjatech|superninja|ninja dev", "ninjatech"),
    "zerker-reason": ("Zerker Reason", r"\breason\b", "zerker-reason"),
    "zerker-gateway": ("Zerker Gateway", r"\bgateway\b|farcaster", None),
    "zmem": ("ZMem / memory", r"\bzmem\b|memory[- ]prov|memory proofs", "memory-proofs"),
    "slancha": ("Slancha", r"slancha|\breplay\.", None),
    "proofmark": ("Proofmark / X", r"proofmark|\bexhibit\b|x api|twitter", None),
    "moltbook": ("Moltbook", r"moltbook", None),
    "witness-ios": ("Witness iOS", r"\bwitness\b", None),
    "nostr": ("Nostr", r"\bnostr\b", None),
    "rekor": ("Rekor / Sigstore", r"\brekor\b|sigstore", None),
    "hub": ("Treeship Hub", r"\bhub\b|\bdock\b", None),
    "wasm": ("WASM verifier", r"\bwasm\b|core-wasm|@treeship/verify", None),
    "python-sdk": ("Python SDK", r"python sdk|treeship-sdk|treeship_sdk|pypi", None),
    "typescript-sdk": ("TypeScript SDK", r"typescript sdk|@treeship/sdk|sdk-ts", None),
    "go-client": ("Go hub client", r"\bgo client\b|pkg/hubclient|pkg/dpop", None),
}

STOP = set("""a an the and or of to for in on at by with from into over under as is are was were be been
add adds added fix fixes fixed feat chore docs doc refactor test tests ci release bump make makes
now no not new every each per one two v0 treeship cli core hub sdk when where which that this it its
""".split())


def load_tags() -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "for-each-ref", "--sort=creatordate", "--format=%(creatordate:short)\t%(refname:short)", "refs/tags"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    tags = []
    for line in out.splitlines():
        date, name = line.split("\t")
        if re.fullmatch(r"v\d+\.\d+\.\d+", name):
            tags.append((date, name[1:]))
    return tags


def load_prs(path: Path) -> list[dict]:
    prs = []
    for line in path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        date, num, branch = parts[0], parts[1].lstrip("#"), parts[2]
        title = parts[-1]
        prs.append({"date": date, "num": int(num), "branch": branch, "title": title})
    return sorted(prs, key=lambda p: (p["date"], p["num"]))


def changelog_sections() -> dict[str, str]:
    text = (REPO / "CHANGELOG.md").read_text()
    sections: dict[str, str] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^## (\d+\.\d+\.\d+|Unreleased)", line)
        if m:
            cur = m.group(1)
            sections[cur] = ""
        elif cur:
            sections[cur] += line + "\n"
    return sections


def release_for(date: str, tags: list[tuple[str, str]]) -> str:
    for tdate, ver in tags:
        if tdate >= date:
            return ver
    return "Unreleased"


def blog_systems() -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in (REPO / "docs/content/blog").glob("*.mdx"):
        m = re.search(r"^systems: \[(.*?)\]", f.read_text(), re.M)
        if not m:
            continue
        for s in m.group(1).split(","):
            s = s.strip().strip('"').strip("'")
            if s:
                counts[s] += 1
    return counts


def site_cards(site: Path | None) -> set[str]:
    if not site:
        return set()
    p = site / "data/integrations.json"
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return {i["id"] for g in data["groups"] for i in g["items"]}


def words(title: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_./-]{3,}", title.lower()) if w not in STOP}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prs", required=True, type=Path)
    ap.add_argument("--site", type=Path, default=REPO.parent / "treeship.dev-repo")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    tags = load_tags()
    prs = load_prs(args.prs)
    sections = changelog_sections()
    versions_desc = [v for _, v in reversed(tags)]
    blog = blog_systems()
    cards = site_cards(args.site if args.site.exists() else None)
    docs_pages = {p.stem for p in (REPO / "docs/content/docs/integrations").glob("*.mdx")}

    for pr in prs:
        pr["release"] = release_for(pr["date"], tags)

    # ---- systems matrix -------------------------------------------------
    print("SYSTEMS MATRIX  (prs | first changelog release | changelog mentions | docs page | blog posts | site card)")
    print("-" * 110)
    gaps = 0
    for sid, (label, rx, page) in VOCAB.items():
        pat = re.compile(rx, re.I)
        pr_hits = [p for p in prs if pat.search(p["title"] + " " + p["branch"])]
        first = None
        mentions = 0
        for ver in versions_desc:
            n = len(pat.findall(sections.get(ver, "")))
            if n:
                mentions += n
                first = ver
        has_page = bool(page and page in docs_pages)
        posts = blog.get(sid, 0)
        card = sid in cards
        flags = []
        if pr_hits and mentions == 0:
            flags.append("PRs but never in changelog")
        if (pr_hits or mentions) and not has_page and page is not None:
            flags.append("no docs page")
        if (pr_hits or mentions) and posts == 0:
            flags.append("no blog posts")
        if (pr_hits or mentions) and not card and sid not in {"hub", "wasm", "rekor", "nostr", "moltbook", "proofmark"}:
            flags.append("no site card")
        if flags:
            gaps += 1
        print(f"{label:24} {len(pr_hits):3}  {first or '-':8} {mentions:4}   {'page' if has_page else '-':5} {posts:3}   {'card' if card else '-':5}  {'; '.join(flags)}")
        if pr_hits and (mentions == 0 or not has_page):
            for p in pr_hits[:6]:
                print(f"{'':24}   #{p['num']} {p['date']} {p['title'][:70]}")

    # ---- release ledger -------------------------------------------------
    print()
    print("RELEASE LEDGER  (PRs merged in each release window that the changelog section does not reflect)")
    print("-" * 110)
    by_rel: dict[str, list[dict]] = defaultdict(list)
    for p in prs:
        by_rel[p["release"]].append(p)
    for _, ver in reversed(tags):
        sec = sections.get(ver, "")
        window = by_rel.get(ver, [])
        if not window:
            continue
        low = sec.lower()
        missing = []
        for p in window:
            if f"#{p['num']}" in sec:
                continue
            w = words(p["title"])
            hit = sum(1 for x in w if x in low)
            if hit < 2:
                missing.append(p)
        print(f"{ver:8} {len(window):3} PRs, {len(missing):3} not reflected")
        for p in missing:
            print(f"           #{p['num']} {p['date']} {p['title'][:80]}")

    if args.strict and gaps:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
