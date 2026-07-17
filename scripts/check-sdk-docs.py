#!/usr/bin/env python3
"""Fail if docs reference SDK methods or @treeship/verify exports that don't exist.

The 2026-07 README audit found a TypeScript example whose every call threw
(Ship.init, attestAction, createCheckpoint, ...) and docs advertising SDK
modules/methods that were never implemented. This gate extracts the real
surface from the TypeScript sources and scans every docs page, blog post,
and README for references to methods outside it.

Checked patterns:
  - `s.attest.X(` / `ship.attest.X(` etc.  -> X must exist on AttestModule
    (same for .verify. / .hub.)
  - import { A, B } from '@treeship/verify' -> names must be exported
  - the wrong package name '@treeship/verify-js' anywhere
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_SRC = os.path.join(REPO, "packages", "sdk-ts", "src")
VERIFY_SRC = os.path.join(REPO, "packages", "verify-js", "src", "index.ts")

SCAN_ROOTS = [
    os.path.join(REPO, "docs", "content"),
    os.path.join(REPO, "README.md"),
    os.path.join(REPO, "npm", "treeship", "README.md"),
]


def module_methods(filename):
    with open(os.path.join(SDK_SRC, filename)) as f:
        src = f.read()
    return set(re.findall(r"^\s+(?:async\s+)?(\w+)\s*[(<]", src, re.MULTILINE))


def verify_exports():
    with open(VERIFY_SRC) as f:
        src = f.read()
    names = set(re.findall(r"^export\s+(?:async\s+)?function\s+(\w+)", src, re.MULTILINE))
    names |= set(re.findall(r"^export\s+(?:interface|type|const)\s+(\w+)", src, re.MULTILINE))
    return names


def iter_files():
    for root in SCAN_ROOTS:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, _, files in os.walk(root):
            for name in files:
                if name.endswith((".mdx", ".md")):
                    yield os.path.join(dirpath, name)


def main():
    surface = {
        "attest": module_methods("attest.ts"),
        "verify": module_methods("verify.ts"),
        "hub": module_methods("hub.ts"),
    }
    v_exports = verify_exports()

    errors = []
    for path in iter_files():
        rel = os.path.relpath(path, REPO)
        with open(path) as f:
            text = f.read()

        # generated pages document CLI, not SDK; still scanned — no exemption

        for lineno, line in enumerate(text.splitlines(), 1):
            if "@treeship/verify-js" in line:
                errors.append(f"{rel}:{lineno}: package '@treeship/verify-js' does not exist (it is '@treeship/verify')")

            for module, methods in surface.items():
                for m in re.findall(rf"\w+\.{module}\.(\w+)\(", line):
                    if m not in methods:
                        errors.append(
                            f"{rel}:{lineno}: {module}.{m}() is not a real @treeship/sdk method "
                            f"(has: {', '.join(sorted(methods))})"
                        )

        for imports in re.findall(
            r"import\s*\{([^}]*)\}\s*from\s*['\"]@treeship/verify['\"]", text
        ):
            for name in [n.strip().split(" as ")[0] for n in imports.split(",") if n.strip()]:
                if name and name not in v_exports:
                    errors.append(f"{rel}: '{name}' is not exported by @treeship/verify")

    if errors:
        for e in errors:
            print(f"  err   {e}")
        print(f"\n{len(errors)} phantom SDK reference(s). Docs must only show APIs that exist.")
        return 1
    print("  ✓ every documented SDK method and @treeship/verify import exists in source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
