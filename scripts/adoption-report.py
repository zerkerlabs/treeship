#!/usr/bin/env python3
"""Adoption, from signals Treeship already owns. Nothing phones home.

Treeship sends no telemetry, so "how many people use it" is answered from
public and server-side signals only, each printed with its basis: what it
counts, what inflates it, and what it cannot see. Run it weekly with
--snapshot to build a history; the number that matters is the trend.

    python3 scripts/adoption-report.py             # one screen
    python3 scripts/adoption-report.py --json      # machine-readable
    python3 scripts/adoption-report.py --snapshot  # append to the history

Needs `gh` (logged in with push access, for GitHub traffic) and network for
npm, PyPI, crates.io and the hub. Anything unreachable is reported as
unavailable, never as zero.
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import urllib.request

REPO = "zerkerlabs/treeship"
HUB = "https://api.treeship.dev/v1/stats"
NPM = ["treeship", "@treeship/mcp", "@treeship/sdk", "@treeship/verify", "@treeship/a2a"]
PYPI = ["treeship-sdk"]
CRATES = ["treeship-core", "treeship-cli"]
HISTORY = os.environ.get("TREESHIP_ADOPTION_HISTORY", os.path.expanduser("~/.treeship-ops/adoption.jsonl"))


def gh(path):
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "treeship-adoption-report (github.com/zerkerlabs/treeship)"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def collect():
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    r = {"generated_at": now.isoformat(), "signals": {}}
    S = r["signals"]

    # --- humans, as close as public signals get ------------------------------
    views = gh(f"repos/{REPO}/traffic/views")
    S["github_views_14d"] = {
        "uniques": views and views.get("uniques"),
        "count": views and views.get("count"),
        "basis": "unique visitors to the repository page over the last 14 days, GitHub's own dedup. Humans, plus a few crawlers. The cleanest 'people looked' number there is.",
    }
    clones = gh(f"repos/{REPO}/traffic/clones")
    S["github_clones_14d"] = {
        "uniques": clones and clones.get("uniques"),
        "count": clones and clones.get("count"),
        "basis": "unique cloners over 14 days. Includes this repository's own CI runners on every workflow run, so read it as a ceiling; the trend is meaningful, the level is not.",
    }
    repo = gh(f"repos/{REPO}")
    S["github_social"] = {
        "stars": repo and repo.get("stargazers_count"),
        "forks": repo and repo.get("forks_count"),
        "basis": "cumulative. Slow, public, comparable across projects.",
    }

    # --- installs, from what people fetched on purpose -----------------------
    rel = gh(f"repos/{REPO}/releases?per_page=6")
    by_version = {}
    if rel:
        for rr in rel:
            by_version[rr.get("tag_name")] = sum(a.get("download_count", 0) for a in rr.get("assets", []))
    S["release_asset_downloads"] = {
        "by_version": by_version,
        "basis": "GitHub Releases asset downloads, cumulative per tag. The npm wrapper and the install script fetch these, so this is installs plus mirrors plus CI installs of the CLI.",
    }
    npm = {}
    for pkg in NPM:
        d = get(f"https://api.npmjs.org/downloads/point/last-week/{pkg}")
        npm[pkg] = d and d.get("downloads")
    S["npm_last_week"] = {"by_package": npm, "basis": "npm downloads in the last 7 days. Mirrors, CI and bots dominate; only the week-over-week direction is worth reading."}
    pypi = {}
    for pkg in PYPI:
        d = get(f"https://pypistats.org/api/packages/{pkg}/recent")
        pypi[pkg] = (d or {}).get("data")
    S["pypi_recent"] = {"by_package": pypi, "basis": "pypistats last day/week/month. Same caveat as npm."}
    crates = {}
    for c in CRATES:
        d = get(f"https://crates.io/api/v1/crates/{c}")
        crates[c] = d and {"total": d["crate"].get("downloads"), "recent_90d": d["crate"].get("recent_downloads")}
    S["crates"] = {"by_crate": crates, "basis": "crates.io totals and last-90-day downloads. Mostly CI and dependency resolution."}

    # --- use, from the hub: opt-in by nature ---------------------------------
    hub = get(HUB)
    S["hub"] = {
        "docks_total": hub and hub.get("docks", {}).get("total"),
        "docks_active_7d": hub and hub.get("docks", {}).get("active_last_7d"),
        "sessions_reported_total": hub and hub.get("sessions", {}).get("receipts_uploaded"),
        "sessions_reported_7d": hub and hub.get("sessions", {}).get("uploaded_last_7d"),
        "artifacts_total": hub and hub.get("artifacts", {}).get("total"),
        "artifacts_7d": hub and hub.get("artifacts", {}).get("last_7d"),
        "basis": "workspaces that chose to attach a dock and publish. The only signal here that measures use rather than installs, and a floor: local-only workspaces never appear.",
    }
    return r


def line(label, value, note=""):
    v = "unavailable" if value is None else value
    print(f"  {label:<34} {v!s:<12} {note}")


def report(r):
    S = r["signals"]
    print(f"\nTreeship adoption, {r['generated_at']}  (no telemetry; every number below has a basis)\n")
    print("people")
    line("repo visitors, unique, 14d", S["github_views_14d"]["uniques"], "humans plus a few crawlers")
    line("stars / forks", f"{S['github_social']['stars']} / {S['github_social']['forks']}", "cumulative")
    print("\nuse (hub, opt-in by nature)")
    line("docks total / active 7d", f"{S['hub']['docks_total']} / {S['hub']['docks_active_7d']}", "workspaces that attached")
    line("sessions reported total / 7d", f"{S['hub']['sessions_reported_total']} / {S['hub']['sessions_reported_7d']}")
    line("artifacts total / 7d", f"{S['hub']['artifacts_total']} / {S['hub']['artifacts_7d']}")
    print("\ninstalls (fetched on purpose; mirrors and CI included)")
    bv = S["release_asset_downloads"]["by_version"]
    for tag, n in list(bv.items())[:4]:
        line(f"release {tag} asset downloads", n)
    for pkg, n in S["npm_last_week"]["by_package"].items():
        line(f"npm {pkg} last week", n)
    for c, d in S["crates"]["by_crate"].items():
        line(f"crates {c} 90d / total", d and f"{d['recent_90d']} / {d['total']}")
    line("unique cloners 14d", S["github_clones_14d"]["uniques"], "ceiling: includes our own CI runners")
    print("\nread it as: visitors and hub activity are people; downloads are a ceiling; the trend across snapshots is the number.\n")


def snapshot(r):
    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    with open(HISTORY, "a") as f:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")
    n = sum(1 for _ in open(HISTORY))
    print(f"snapshot appended to {HISTORY} ({n} total)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true", help="print the collected signals as JSON")
    ap.add_argument("--snapshot", action="store_true", help=f"append this run to {HISTORY}")
    a = ap.parse_args()
    r = collect()
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        report(r)
    if a.snapshot:
        snapshot(r)
    sys.exit(0)
