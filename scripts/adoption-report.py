#!/usr/bin/env python3
"""Print Treeship's adoption numbers, humans first, bots labelled.

    python3 scripts/adoption-report.py            # text
    python3 scripts/adoption-report.py --json     # machine-readable

Sources, in order of how much they mean:

1. Hub telemetry (`GET /v1/stats` → `installs`): machines that ran the CLI
   with telemetry on. The only number on this page that counts users.
2. Hub activity (docks, sessions, artifacts): machines that attached.
3. GitHub: stars, forks, unique visitors (needs `gh` with push access).
4. PyPI without mirrors (pypistats): still includes CI and scanners.
5. npm: reported per platform binary, because a human installs exactly one
   platform and mirrors download all of them. The spread between the most-
   and least-downloaded platform package is the most a human residual can
   be; the rest is mirror traffic and is labelled as such.

Read-only, no auth beyond an optional `gh`, and every network failure prints
`n/a` for that block rather than a zero: a zero here reads as "no adoption",
which is the wrong direction to be wrong in.
"""

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

HUB = "https://api.treeship.dev"
REPO = "zerkerlabs/treeship"
NPM_PLATFORMS = [
    "@treeship/cli-darwin-arm64",
    "@treeship/cli-darwin-x64",
    "@treeship/cli-linux-x64",
    "@treeship/cli-linux-arm64",
]
UA = "treeship-adoption-report (hello@treeship.dev)"


def get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def gh_json(path):
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return None


def hub():
    s = get_json(f"{HUB}/v1/stats")
    if not s:
        return None
    return {
        "installs": s.get("installs"),
        "docks": s.get("docks"),
        "sessions": s.get("sessions"),
        "artifacts": s.get("artifacts"),
        "generated_at": s.get("generated_at"),
    }


def github():
    repo = gh_json(f"repos/{REPO}")
    if not repo:
        return None
    views = gh_json(f"repos/{REPO}/traffic/views") or {}
    clones = gh_json(f"repos/{REPO}/traffic/clones") or {}
    return {
        "stars": repo.get("stargazers_count"),
        "forks": repo.get("forks_count"),
        "unique_visitors_14d": views.get("uniques"),
        "views_14d": views.get("count"),
        "unique_cloners_14d": clones.get("uniques"),
        "clones_14d": clones.get("count"),
    }


def pypi():
    d = get_json("https://pypistats.org/api/packages/treeship-sdk/overall")
    if not d or "data" not in d:
        return None
    rows = d["data"]
    if not rows:
        return None
    days = sorted({r["date"] for r in rows})
    last30 = days[-30:]
    out = {"window_days": len(last30), "from": last30[0], "to": last30[-1]}
    for cat in ("with_mirrors", "without_mirrors"):
        out[cat] = sum(r["downloads"] for r in rows if r["category"] == cat and r["date"] in last30)
    return out


def npm():
    out = {"last_month": {}}
    for pkg in ["treeship"] + NPM_PLATFORMS:
        d = get_json(f"https://api.npmjs.org/downloads/point/last-month/{urllib.parse.quote(pkg, safe='@')}")
        out["last_month"][pkg] = d.get("downloads") if d else None
    plat = [v for k, v in out["last_month"].items() if k in NPM_PLATFORMS and v is not None]
    if plat:
        out["platform_min"] = min(plat)
        out["platform_max"] = max(plat)
        # Mirrors fetch every platform; a human fetches one. The floor across
        # platforms is the mirror baseline; the spread is the most that could
        # be humans (it also contains CI on that platform).
        out["human_residual_upper_bound"] = out["platform_max"] - out["platform_min"]
    return out


def n(v):
    return "n/a" if v is None else f"{v:,}"


def text(report):
    h = report["hub"]
    print("TREESHIP ADOPTION")
    print()
    print("Users (hub telemetry: machines that ran the CLI, opt-out)")
    if h and h.get("installs"):
        i = h["installs"]
        print(f"  installs total   {n(i.get('total'))}")
        print(f"  new    7d / 30d  {n(i.get('new_7d'))} / {n(i.get('new_30d'))}")
        print(f"  active 7d / 30d  {n(i.get('active_7d'))} / {n(i.get('active_30d'))}")
        for k in ("by_harness_30d", "by_os_30d", "by_version_30d"):
            if i.get(k):
                items = sorted(i[k].items(), key=lambda kv: -kv[1])[:6]
                print(f"  {k[:-4]:15s}  " + ", ".join(f"{a} {b}" for a, b in items))
        print("  basis: floor; opted-out machines are not counted")
    elif h:
        print("  hub is up but reports no installs block yet (deploy pending)")
    else:
        print("  n/a (hub unreachable)")
    print()
    print("Hub activity (machines that attached a dock)")
    if h:
        d, s, a = h.get("docks") or {}, h.get("sessions") or {}, h.get("artifacts") or {}
        print(f"  docks total / attached 7d / active 7d   {n(d.get('total'))} / {n(d.get('attached_last_7d'))} / {n(d.get('active_last_7d'))}")
        print(f"  sessions uploaded total / 7d            {n(s.get('receipts_uploaded'))} / {n(s.get('uploaded_last_7d'))}")
        print(f"  artifacts total / 7d                    {n(a.get('total'))} / {n(a.get('last_7d'))}")
    else:
        print("  n/a")
    print()
    g = report["github"]
    print("GitHub (people)")
    if g:
        print(f"  stars {n(g['stars'])}   forks {n(g['forks'])}   unique visitors 14d {n(g['unique_visitors_14d'])} ({n(g['views_14d'])} views)")
        print(f"  clones 14d {n(g['clones_14d'])} from {n(g['unique_cloners_14d'])} sources: CI and scanners, not people")
    else:
        print("  n/a (gh not available or no push access)")
    print()
    p = report["pypi"]
    print("PyPI treeship-sdk, last 30 days (pypistats)")
    if p:
        print(f"  without mirrors {n(p.get('without_mirrors'))}   with mirrors {n(p.get('with_mirrors'))}   ({p['from']} → {p['to']})")
        print("  'without mirrors' still counts CI and security scanners")
    else:
        print("  n/a")
    print()
    m = report["npm"]
    print("npm, last 30 days")
    for pkg, v in m["last_month"].items():
        print(f"  {pkg:30s} {n(v)}")
    if "human_residual_upper_bound" in m:
        print(f"  mirror baseline (min across platforms)  {n(m['platform_min'])}")
        print(f"  human installs, upper bound (spread)     {n(m['human_residual_upper_bound'])}")
        print("  a human installs one platform; mirrors fetch all four")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = {"hub": hub(), "github": github(), "pypi": pypi(), "npm": npm()}
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        text(report)


if __name__ == "__main__":
    main()
