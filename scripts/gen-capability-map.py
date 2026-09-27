#!/usr/bin/env python3
"""Generate the capability map from source. Nothing here is hand-maintained.

`docs/feature-inventory.yml` is curated: a human decides which features exist
and what they mean. This is the complement -- a mechanical inventory of every
surface a consumer can actually reach, derived only from the code:

    CLI commands      packages/cli/src        (clap subcommand registrations)
    Hub routes        packages/hub            (chi route registrations)
    Wire types        packages/core/src       (types deriving Serialize)

Curation and derivation answer different questions. The inventory says "what do
we ship, and is it stable." This says "what is actually there, right now, to the
byte." Drift between them is the interesting signal, so `--check` reports it.

# Why "derives Serialize" is the right cut for types

`packages/core/src` has 172 public structs and enums. Most are internal:
public because Rust needs cross-module visibility, not because anyone outside
programs against them. Listing all 172 would bury the ~100 that matter.

A type that derives `Serialize` crosses a process boundary. It appears in a
signed artifact, an API response, or a config file -- so renaming a field is a
breaking change for somebody, whether or not we meant it to be. That makes
serializability a mechanical, judgment-free definition of the public surface,
and it is why this can be generated rather than argued about.

Usage:
    python3 scripts/gen-capability-map.py            # write the map
    python3 scripts/gen-capability-map.py --check    # fail if stale
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "capability-map.json"

HUB = ROOT / "packages" / "hub"
CORE = ROOT / "packages" / "core" / "src"
CLI = ROOT / "packages" / "cli" / "src"

ROUTE_RE = re.compile(r'\.(Get|Post|Put|Patch|Delete|Handle)\(\s*"(/v1/[^"]*)"')

# A derive block, then any further attributes, then the item. Attributes
# between the derive and the item (`#[serde(...)]`, docs) are common and must
# not break the match.
SERDE_RE = re.compile(
    r"#\[derive\([^)]*Serialize[^)]*\)\]\s*(?:#\[[^\]]*\]\s*)*"
    r"pub\s+(struct|enum)\s+([A-Z]\w+)"
)

MAIN_RS = CLI / "main.rs"

# A `#[command(...hide = true...)]` attribute directly above a variant of the
# top-level `Command` enum. The variant may carry its own doc comments, but
# clap requires the `#[command(...)]` attribute to sit immediately above the
# variant itself (no attributes in between), so the variant name is always
# the identifier on the very next non-blank line.
HIDE_ATTR_RE = re.compile(
    r'#\[command\(([^)]*\bhide\s*=\s*true\b[^)]*)\)\]\s*\n\s*(\w+)'
)
NAME_OVERRIDE_RE = re.compile(r'name\s*=\s*"([^"]+)"')

# Hand-maintained: every top-level CLI command hidden from --help, as of the
# last time someone looked. `parse_hidden_from_source()` re-derives this set
# from the clap attributes at build time; the two are compared in `main()`,
# and a source command missing from this list fails the run rather than
# silently updating it -- a new hidden command needs a person to decide it
# belongs here (and, ideally, ship a docs page for it), not just a script.
HIDDEN_CLI_COMMANDS: list[str] = [
    "bundle",
    "install",
    "uninstall",
    "hook",
    "declare",
    "agent",
    "harness",
    "approval",
    "daemon",
    "checkpoint",
    "merkle",
    "ui",
    "dashboard",
    "otel",
    "templates",
    "template",
    "prove",
    "prove-chain",
    "verify-proof",
    "zk-setup",
    "zk-tls-setup",
    "__dump-cli",
]


def _kebab(rust_ident: str) -> str:
    """`ProveChain` -> `prove-chain`, clap's default Subcommand rename."""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", rust_ident).lower()


def parse_hidden_from_source() -> set[str]:
    """Every top-level `Command` variant carrying `hide = true`, derived from
    the clap attributes themselves -- not from HIDDEN_CLI_COMMANDS above, so
    the two can be compared for drift.
    """
    if not MAIN_RS.is_file():
        return set()
    text = MAIN_RS.read_text(encoding="utf-8", errors="replace")
    # Scope to the top-level `enum Command { ... }` block only: a brace-depth
    # walk from its opening `{`, so a `hide = true` inside some other enum
    # (an individual subcommand's own flag, say) is never picked up here --
    # this list is specifically the top-level names capability-map.json's
    # `cli_commands` would otherwise miss.
    m = re.search(r"\benum Command\s*\{", text)
    if not m:
        return set()
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    body = text[start : i - 1]

    hidden: set[str] = set()
    for attr_body, ident in HIDE_ATTR_RE.findall(body):
        override = NAME_OVERRIDE_RE.search(attr_body)
        hidden.add(override.group(1) if override else _kebab(ident))
    return hidden


def hub_routes() -> list[dict]:
    """Every /v1 route registered in the Go source, with its verbs."""
    found: dict[str, set[str]] = {}
    if not HUB.is_dir():
        return []
    for go in HUB.rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        for verb, path in ROUTE_RE.findall(go.read_text(encoding="utf-8", errors="replace")):
            found.setdefault(path, set()).add(verb.upper())
    return [
        {"path": p, "methods": sorted(v)}
        for p, v in sorted(found.items())
    ]


def wire_types() -> list[dict]:
    """Types that cross a process boundary, with the module that owns them."""
    out: list[dict] = []
    if not CORE.is_dir():
        return out
    for rs in sorted(CORE.rglob("*.rs")):
        text = rs.read_text(encoding="utf-8", errors="replace")
        rel = rs.relative_to(ROOT).as_posix()
        for kind, name in SERDE_RE.findall(text):
            out.append({"name": name, "kind": kind, "source": rel})
    out.sort(key=lambda t: t["name"])
    return out


def cli_commands() -> list[str]:
    """Top-level subcommands, read from the built binary when available.

    The binary is the truth -- parsing clap attributes out of source misses
    conditionally-registered commands and feature-gated ones. Falls back to an
    empty list rather than guessing, so a missing binary shows up as "not
    measured" instead of a confidently wrong zero.
    """
    binary = ROOT / "target" / "debug" / "treeship"
    if not binary.exists():
        return []
    try:
        out = subprocess.run(
            [str(binary), "--help"], capture_output=True, text=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    skip = {"help"}
    return sorted(
        c for c in re.findall(r"^  ([a-z][a-z-]+)\s{2,}", out, re.M) if c not in skip
    )


def cli_commands_hidden() -> list[dict]:
    """Every name in HIDDEN_CLI_COMMANDS, probed against the built binary.

    A name that no longer parses (renamed, removed) shows up as
    `"probed": false` rather than silently vanishing from the map, so
    `--check` catches it as a diff instead of a quiet shrink.
    """
    binary = ROOT / "target" / "debug" / "treeship"
    out: list[dict] = []
    for name in HIDDEN_CLI_COMMANDS:
        probed = False
        if binary.exists():
            try:
                result = subprocess.run(
                    [str(binary), name, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                probed = result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                probed = False
        out.append({"name": name, "hidden": True, "probed": probed})
    out.sort(key=lambda x: x["name"])
    return out


def build() -> dict:
    routes = hub_routes()
    types = wire_types()
    cli = cli_commands()
    hidden = cli_commands_hidden()
    return {
        "$comment": (
            "GENERATED by scripts/gen-capability-map.py -- do not edit. "
            "Mechanical inventory of every reachable surface, derived from "
            "source. For what each feature MEANS and how stable it is, see "
            "docs/feature-inventory.yml."
        ),
        "counts": {
            "cli_commands": len(cli),
            "cli_commands_hidden": len(hidden),
            "hub_routes": len(routes),
            "wire_types": len(types),
        },
        "cli_commands": cli,
        "cli_commands_hidden": hidden,
        "hub_routes": routes,
        "wire_types": types,
    }


def check_hidden_list_current() -> bool:
    """Fail loudly if the source has a hidden command HIDDEN_CLI_COMMANDS
    doesn't know about (or the reverse: a name in the list that no clap
    variant claims anymore). Runs unconditionally, not just under --check --
    this is a "a person needs to look at this" signal either way."""
    from_source = parse_hidden_from_source()
    from_list = set(HIDDEN_CLI_COMMANDS)
    missing = from_source - from_list
    extra = from_list - from_source
    if not missing and not extra:
        return True
    print(f"  err   HIDDEN_CLI_COMMANDS in {Path(__file__).name} is out of sync with "
          f"{MAIN_RS.relative_to(ROOT)}'s hide = true attributes:")
    for name in sorted(missing):
        print(f"        + {name} is hide = true in source but missing from HIDDEN_CLI_COMMANDS")
    for name in sorted(extra):
        print(f"        - {name} is in HIDDEN_CLI_COMMANDS but no longer hide = true in source")
    print()
    print(f"  A new hidden command needs a human decision (and ideally a docs page), "
          f"not a silent list update. Edit HIDDEN_CLI_COMMANDS in {Path(__file__).name}.")
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the map is stale")
    args = ap.parse_args()

    if not check_hidden_list_current():
        return 1

    current = build()
    rendered = json.dumps(current, indent=2) + "\n"

    if args.check:
        if not OUT.exists():
            print(f"  err   {OUT.relative_to(ROOT)} missing -- run gen-capability-map.py")
            return 1
        if OUT.read_text() != rendered:
            print(f"  err   {OUT.relative_to(ROOT)} is stale")
            # Say WHAT drifted. "regenerate it" without naming the delta means
            # a reviewer cannot tell an intended API change from an accident.
            try:
                old = json.loads(OUT.read_text())
            except json.JSONDecodeError:
                old = {}
            for key, label in (
                ("cli_commands", "CLI command"),
                ("cli_commands_hidden", "hidden CLI command"),
                ("hub_routes", "hub route"),
                ("wire_types", "wire type"),
            ):
                def ident(x):
                    return x if isinstance(x, str) else (x.get("path") or x.get("name"))

                before = {ident(x) for x in old.get(key, [])}
                after = {ident(x) for x in current.get(key, [])}
                for added in sorted(after - before):
                    print(f"        + {label} {added}")
                for gone in sorted(before - after):
                    print(f"        - {label} {gone}")
            print()
            print("  Run: python3 scripts/gen-capability-map.py")
            return 1
        c = current["counts"]
        print(
            f"  ✓ capability map current "
            f"({c['cli_commands']} commands, {c['cli_commands_hidden']} hidden, "
            f"{c['hub_routes']} routes, {c['wire_types']} wire types)"
        )
        unprobed = [x["name"] for x in current["cli_commands_hidden"] if not x["probed"]]
        if unprobed:
            print(f"  warn  hidden commands that did not probe cleanly: {', '.join(unprobed)}")
        return 0

    OUT.write_text(rendered)
    c = current["counts"]
    print(f"  ✓ wrote {OUT.relative_to(ROOT)}")
    print(
        f"    {c['cli_commands']} CLI commands, {c['cli_commands_hidden']} hidden, "
        f"{c['hub_routes']} hub routes, {c['wire_types']} wire types"
    )
    if c["cli_commands"] == 0:
        print("    note: no CLI commands found -- build the binary first "
              "(cargo build --bin treeship)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
