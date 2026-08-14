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

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_GO = os.path.join(REPO, "packages", "hub", "main.go")
OPENAPI = os.path.join(REPO, "docs", "content", "docs", "api", "hub-openapi.yaml")


def routes_from_router():
    routes = set()
    with open(MAIN_GO) as f:
        src = f.read()
    # Any receiver, not just `r`. chi's `Route`/`Group` hand you a fresh
    # router under whatever name the closure picks -- `r.Group(func(pub
    # chi.Router) { pub.Get(...) })` is idiomatic and the routes inside are
    # just as real. Hardcoding `r.` silently dropped five endpoints the moment
    # they were grouped to share a rate limit, and reported them as *stale
    # documentation* rather than as a parser that could not see them.
    for _recv, method, path in re.findall(
        r'^\s*(\w+)\.(Get|Post|Put|Delete|Patch)\("(/[^"]*)"', src, re.MULTILINE
    ):
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


class _NoDuplicatesLoader(yaml.SafeLoader):
    """A loader that refuses duplicate mapping keys.

    PyYAML silently keeps the last of a duplicated key. The JS YAML parser the
    docs build uses rejects the file outright -- so a hand-edit that inserted a
    block beside an existing one parsed fine here, passed this check, and then
    failed the production build with an error pointing at an unrelated line.

    Subclassing the loader rather than scanning lines because YAML sequences
    legitimately repeat keys across items (`- name: / in: / required:`), and a
    line-based scan flags every one of them.
    """


def _no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            mark = key_node.start_mark
            raise yaml.constructor.ConstructorError(
                None, None,
                f"duplicate key {key!r} (line {mark.line + 1})", mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_NoDuplicatesLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates
)


def main():
    try:
        with open(OPENAPI) as f:
            yaml.load(f, Loader=_NoDuplicatesLoader)
    except yaml.YAMLError as e:
        print(f"  err   {OPENAPI} is not valid YAML for the docs build: {e}")
        print()
        print(
            "PyYAML keeps a duplicated key silently and the JS parser the docs "
            "build uses rejects the file, so this passed here and failed there. "
            "Caught before CI now."
        )
        return 1

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
