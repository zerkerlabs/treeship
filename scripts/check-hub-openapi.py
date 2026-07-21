#!/usr/bin/env python3
"""Fail if the documented Hub OpenAPI spec drifts from the router.

Extracts METHOD+path pairs from the chi route registrations in
packages/hub/main.go and compares them against the paths documented in
docs/content/docs/api/hub-openapi.yaml. This is the gate that would have
caught the /v1/hub/* -> /v1/dock/* drift the 2026-07 docs audit found in
production.

No dependencies: the YAML is parsed structurally (path keys at 2-space
indent under `paths:`, method keys at 4-space indent), which is exactly the
shape this spec file uses.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_GO = os.path.join(REPO, "packages", "hub", "main.go")
OPENAPI = os.path.join(REPO, "docs", "content", "docs", "api", "hub-openapi.yaml")


def routes_from_router():
    routes = set()
    with open(MAIN_GO) as f:
        src = f.read()
    for method, path in re.findall(r'^\s*r\.(Get|Post|Put|Delete|Patch)\("(/[^"]*)"', src, re.MULTILINE):
        # normalize chi {param} names -> {param} placeholder-insensitive form
        norm = re.sub(r"\{[^}]+\}", "{}", path)
        routes.add((method.upper(), norm))
    return routes


def routes_from_openapi():
    routes = set()
    path = None
    in_paths = False
    with open(OPENAPI) as f:
        for line in f:
            if line.rstrip() == "paths:":
                in_paths = True
                continue
            if in_paths:
                if line.strip() and not line.startswith(" "):
                    break  # left the paths block
                m = re.match(r"^  (/\S+):\s*$", line)
                if m:
                    path = re.sub(r"\{[^}]+\}", "{}", m.group(1))
                    continue
                m = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
                if m and path:
                    routes.add((m.group(1).upper(), path))
    return routes


def main():
    code = routes_from_router()
    spec = routes_from_openapi()

    missing = sorted(code - spec)   # shipped but undocumented
    stale = sorted(spec - code)     # documented but not in the router

    ok = True
    for method, path in missing:
        print(f"  err   route in main.go but not in hub-openapi.yaml: {method} {path}")
        ok = False
    for method, path in stale:
        print(f"  err   route in hub-openapi.yaml but not in main.go: {method} {path}")
        ok = False

    if ok:
        print(f"  ✓ hub-openapi.yaml matches the router ({len(code)} routes)")
        return 0
    print(f"\n{len(missing)} undocumented, {len(stale)} stale. "
          "Fix docs/content/docs/api/hub-openapi.yaml (and the reference pages).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
