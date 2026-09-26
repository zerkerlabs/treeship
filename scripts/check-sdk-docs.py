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

Docs re-test (2026-09-27): the resolver is complete now. Every `<var>.<module>.<method>(`
call is resolved against the modules the TypeScript `Ship` class exposes
(read from ship.ts, not a hand list), a `<var>.<module>(` call against those
module names, and `<var>.<method>(` in Python fences (or on `ts`/`client`
variables) against the Python client's real methods. skills/ and
integrations/ are scanned too. Findings from the new patterns and roots are
WARNINGS until `--strict`; the original checks stay errors.
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
WIDER_ROOTS = [
    os.path.join(REPO, "skills"),
    os.path.join(REPO, "integrations"),
]
SHIP_SRC = os.path.join(REPO, "packages", "sdk-ts", "src", "ship.ts")
PY_CLIENT = os.path.join(REPO, "packages", "sdk-python", "treeship_sdk", "client.py")

# Variables docs use for a TypeScript client (`const s = ship()`), and for
# the Python client (`ts = Treeship()`). `client` and `t` are common names
# for other libraries' clients (the MCP SDK's `client.callTool(`), so they
# are resolved only for module-shaped calls (`client.attest.action(`).
TS_VARS = r"(?:s|ship|sdk|client|treeship|t)"
TS_VARS_OWN = r"(?:s|ship|sdk|treeship)"
PY_VARS = r"(?:ts|treeship|sdk)"


def ship_modules():
    """Module name -> source file, from the fields the Ship class declares
    (`readonly attest = new AttestModule();`)."""
    with open(SHIP_SRC) as f:
        src = f.read()
    mods = {}
    for name, cls in re.findall(r"^\s+readonly\s+(\w+)\s*=\s*new\s+(\w+)\(", src, re.MULTILINE):
        mods[name] = cls
    files = {}
    for name in mods:
        candidate = f"{name}.ts"
        if os.path.exists(os.path.join(SDK_SRC, candidate)):
            files[name] = candidate
    return files


def python_methods():
    """Public method names of the Python client's `Treeship` class, plus its
    module-level functions."""
    with open(PY_CLIENT) as f:
        src = f.read()
    return set(re.findall(r"^\s+def\s+([a-z]\w*)\s*\(", src, re.MULTILINE)) | set(
        re.findall(r"^def\s+([a-z]\w*)\s*\(", src, re.MULTILINE)
    )


def fences(text):
    """(line number, language, line) for every line inside a code fence."""
    lang = None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*```(\w*)", line)
        if m:
            lang = None if lang is not None else m.group(1).lower()
            continue
        if lang is not None:
            yield lineno, lang, line


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


def iter_files(roots=SCAN_ROOTS):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "node_modules"]
            for name in files:
                if name.endswith((".mdx", ".md")):
                    yield os.path.join(dirpath, name)


def resolve_calls(path, surface, py_methods):
    """The complete resolver: every documented call on a client variable."""
    out = []
    rel = os.path.relpath(path, REPO)
    with open(path) as f:
        text = f.read()
    modules = set(surface)
    for lineno, lang, line in fences(text):
        if lang in ("python", "py"):
            for m in re.findall(rf"\b{PY_VARS}\.(\w+)\(", line):
                if m not in py_methods:
                    out.append(
                        f"{rel}:{lineno}: Python client has no method {m}() "
                        f"(has: {', '.join(sorted(py_methods))})"
                    )
            continue
        # TypeScript / JavaScript / untagged: <var>.<module>.<method>( and <var>.<module>(
        for mod, meth in re.findall(rf"\b{TS_VARS}\.(\w+)\.(\w+)\(", line):
            if mod not in modules:
                out.append(f"{rel}:{lineno}: {mod}.{meth}() -- the SDK client has no module '{mod}' (has: {', '.join(sorted(modules))})")
            elif meth not in surface[mod]:
                out.append(f"{rel}:{lineno}: {mod}.{meth}() is not a real @treeship/sdk method (has: {', '.join(sorted(surface[mod]))})")
        for name in re.findall(rf"\b{TS_VARS_OWN}\.(\w+)\(", line):
            if name in modules or name in ("then", "catch"):
                continue
            # `sdk.attest_action(` in an untagged fence is the Python client.
            if name in py_methods:
                continue
            out.append(f"{rel}:{lineno}: {name}() is neither an SDK module nor a Python client method")
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    strict = "--strict" in argv
    modules = ship_modules()
    surface = {name: module_methods(filename) for name, filename in modules.items()}
    v_exports = verify_exports()
    py_methods = python_methods()

    errors = []
    warnings = []
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

    # The complete resolver over the original roots and the wider ones.
    for path in list(iter_files()) + list(iter_files(WIDER_ROOTS)):
        (errors if strict else warnings).extend(resolve_calls(path, surface, py_methods))

    for w in warnings:
        print(f"  warn  {w}")
    if errors:
        for e in errors:
            print(f"  err   {e}")
        print(f"\n{len(errors)} phantom SDK reference(s). Docs must only show APIs that exist.")
        return 1
    print(
        f"  ✓ every documented SDK method and @treeship/verify import exists in source; "
        f"modules {', '.join(sorted(modules))}, {len(py_methods)} Python methods"
        f"{f'; {len(warnings)} warning(s) from the full resolver (warn-only)' if warnings else ''}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
