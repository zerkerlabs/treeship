#!/usr/bin/env python3
"""
check-feature-inventory.py -- permissive linter for docs/feature-inventory.yml.

Walks every entry and warns when:
  - a listed `treeship <subcommand>` is not visible in the CLI source
  - a `docs:` path does not exist on disk
  - a `tests:` path does not exist on disk
  - a `packages:` name has no matching manifest under packages/, bridges/, npm/

Errors (not warnings) when:
  - YAML is malformed
  - `status:` is missing or not in the taxonomy
  - `id:` is missing or not unique

Also runs a reverse drift check: top-level `treeship <subcommand>` names found
in packages/cli/src/main.rs that don't appear in any feature entry's `cli:`
list. Drift is a warning, not an error -- new commands are still allowed to
land without immediately editing the inventory.

Exit code is 0 unless --strict, in which case any warning exits 1.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "feature-inventory.yml"
CLI_MAIN = ROOT / "packages" / "cli" / "src" / "main.rs"
CLI_CMDS = ROOT / "packages" / "cli" / "src" / "commands"

STATUSES = {"stable", "beta", "experimental", "quarantined", "roadmap", "internal", "deprecated"}

PACKAGE_ROOTS = [
    ROOT / "packages",
    ROOT / "bridges",
    ROOT / "npm",
    ROOT / "npm" / "@treeship",
]


def load_yaml(path: Path):
    try:
        import yaml  # type: ignore
        with path.open() as fh:
            return yaml.safe_load(fh)
    except ImportError:
        sys.stderr.write(
            "error: pyyaml not installed. `pip install pyyaml` (or `pip install --user pyyaml`).\n"
        )
        sys.exit(2)


def cli_source_text() -> str:
    parts = [CLI_MAIN.read_text()]
    if CLI_CMDS.is_dir():
        for p in sorted(CLI_CMDS.glob("*.rs")):
            parts.append(p.read_text())
    return "\n".join(parts)


def collect_top_subcommands() -> set[str]:
    """Extract top-level `Command::X(...)` enum variants from main.rs."""
    text = CLI_MAIN.read_text()
    m = re.search(r"enum\s+Command\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        return set()
    body = m.group(1)
    names = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#["):
            continue
        match = re.match(r"([A-Z][A-Za-z0-9]*)\s*[\({]?", line)
        if match:
            # CamelCase -> kebab-case
            name = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", match.group(1)).lower()
            # Common alias: ProveChain -> prove-chain, ZkSetup -> zk-setup
            names.add(name)
    # filter out non-commands (private types caught by the regex)
    return names


def package_has_manifest(name: str) -> bool:
    """Resolve a package name to a manifest on disk."""
    targets: list[Path] = []
    if name.startswith("@treeship/"):
        suffix = name.split("/", 1)[1]
        # Strip optional cli- prefix used by npm wrapper packages
        short = suffix.removeprefix("cli-")
        targets += [
            ROOT / "bridges" / suffix,
            ROOT / "bridges" / short,
            ROOT / "packages" / suffix,
            ROOT / "packages" / short,
            ROOT / "npm" / "@treeship" / suffix,
            ROOT / "integrations" / suffix,
        ]
    else:
        for root in PACKAGE_ROOTS:
            targets.append(root / name)
            targets.append(root / name.replace("-", "_"))
    # Also accept crate-style names: treeship-core -> packages/core
    if name.startswith("treeship-"):
        short = name[len("treeship-"):]
        targets.append(ROOT / "packages" / short)
    if name == "treeship":
        targets.append(ROOT / "npm" / "treeship")
    # Walk every package manifest and match by `name` field directly.
    # This covers npm scoped packages that live in non-obvious directories.
    for t in targets:
        if t.is_dir():
            for manifest in ("package.json", "Cargo.toml", "pyproject.toml"):
                if (t / manifest).exists():
                    return True
    # Fallback: grep package.json `name` field across the relevant roots.
    for root in [ROOT / "packages", ROOT / "bridges", ROOT / "integrations", ROOT / "npm"]:
        if not root.is_dir():
            continue
        for pkg in root.rglob("package.json"):
            if "node_modules" in pkg.parts:
                continue
            try:
                import json
                if json.loads(pkg.read_text()).get("name") == name:
                    return True
            except Exception:
                continue
    return False



# ── Hub API surface ────────────────────────────────────────────────────────
#
# Routes live as chi registrations in the Go source. Scanning them means an
# `api:` entry cannot name an endpoint that was renamed or deleted, and the
# reverse check catches a live endpoint nobody wrote down -- which is how
# /v1/artifacts/{id} ended up serving full DSSE envelopes while appearing in
# no spec, and two separate integrations were scoped without knowing it.

HUB_ROOT = ROOT / "packages" / "hub"

# Verbs chi uses; `Handle` covers method-agnostic mounts.
_ROUTE_RE = re.compile(
    r'\.(Get|Post|Put|Patch|Delete|Handle)\(\s*"(/v1/[^"]*)"'
)


def collect_hub_routes() -> set[str]:
    """Every /v1 route registered anywhere in the Go source."""
    routes: set[str] = set()
    if not HUB_ROOT.is_dir():
        return routes
    for go in HUB_ROOT.rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        try:
            text = go.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for _verb, path in _ROUTE_RE.findall(text):
            routes.add(path)
    return routes


def normalize_route(spec: str) -> str:
    """`GET /v1/receipt/{session_id}` -> `/v1/receipt/{session_id}`."""
    parts = spec.split(None, 1)
    return (parts[1] if len(parts) == 2 else parts[0]).strip()


# ── Core types ─────────────────────────────────────────────────────────────
#
# A `types:` entry names a Rust type a consumer can rely on. Checking it
# against source stops the inventory promising a struct that was renamed --
# the failure that makes an index worse than no index, because it is trusted.

CORE_SRC = ROOT / "packages" / "core" / "src"


def core_type_exists(name: str) -> bool:
    if not CORE_SRC.is_dir():
        return False
    pat = re.compile(rf"\bpub\s+(?:struct|enum|type|fn|const)\s+{re.escape(name)}\b")
    for rs in CORE_SRC.rglob("*.rs"):
        try:
            if pat.search(rs.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="exit 1 on any warning")
    args = ap.parse_args()

    if not INVENTORY.exists():
        sys.stderr.write(f"error: {INVENTORY} not found\n")
        return 2

    print(f"Checking {INVENTORY.relative_to(ROOT)}...\n")

    data = load_yaml(INVENTORY)
    if not isinstance(data, list):
        sys.stderr.write("error: top-level YAML must be a list\n")
        return 2

    cli_text = cli_source_text()
    warnings: list[str] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    cli_in_inventory: set[str] = set()
    api_in_inventory: set[str] = set()
    hub_routes = collect_hub_routes()

    for entry in data:
        fid = entry.get("id", "<no id>")
        if not entry.get("id"):
            errors.append("entry missing required `id`")
            continue
        if fid in seen_ids:
            errors.append(f"duplicate id '{fid}'")
        seen_ids.add(fid)

        status = entry.get("status")
        if status not in STATUSES:
            errors.append(f"feature '{fid}' has invalid status '{status}' (valid: {sorted(STATUSES)})")

        for inv in entry.get("cli", []) or []:
            tokens = inv.split()
            if not tokens or tokens[0] != "treeship":
                warnings.append(f"feature '{fid}' cli '{inv}' does not start with 'treeship'")
                continue
            if len(tokens) < 2:
                warnings.append(f"feature '{fid}' cli '{inv}' has no subcommand")
                continue
            sub = tokens[1]
            cli_in_inventory.add(sub)
            # Loose grep: subcommand should appear in CLI source (doc comment, variant, or handler).
            if sub not in cli_text:
                warnings.append(f"feature '{fid}' cli '{inv}' -- subcommand '{sub}' not found in CLI source")

        # `api:` entries name Hub endpoints, e.g. "GET /v1/artifacts/{id}".
        # Verified against the routes actually registered in the Go source, so
        # an endpoint cannot be documented into existence or silently renamed.
        for spec in entry.get("api", []) or []:
            route = normalize_route(spec)
            api_in_inventory.add(route)
            if not route.startswith("/v1/"):
                warnings.append(f"feature '{fid}' api '{spec}' -- expected a /v1/... path")
            elif hub_routes and route not in hub_routes:
                warnings.append(f"feature '{fid}' api '{spec}' -- route not registered in packages/hub")

        # `types:` entries name public Rust types a consumer can rely on.
        for ty in entry.get("types", []) or []:
            if not core_type_exists(ty):
                warnings.append(f"feature '{fid}' type '{ty}' -- no `pub struct/enum/type/fn/const` in packages/core/src")

        for d in entry.get("docs", []) or []:
            if not (ROOT / d).exists():
                warnings.append(f"feature '{fid}' docs path '{d}' -- file not found")

        for t in entry.get("tests", []) or []:
            if not (ROOT / t).exists():
                warnings.append(f"feature '{fid}' tests path '{t}' -- file not found")

        for pkg in entry.get("packages", []) or []:
            if not package_has_manifest(pkg):
                warnings.append(f"feature '{fid}' package '{pkg}' -- no manifest under packages/, bridges/, npm/")

        if status == "stable" and not (entry.get("tests") or entry.get("docs")):
            warnings.append(f"feature '{fid}' status=stable but no tests or docs listed")

    # Reverse drift: top-level CLI subcommands not represented in any feature entry.
    top = collect_top_subcommands()
    # ignore implementation details / hidden / utility commands
    ignore = {"version", "ui", "hook", "templates", "template", "install", "uninstall",
              "doctor", "pending", "approve", "deny", "log", "status", "wrap", "add",
              "quickstart", "init", "verify", "attest", "bundle", "keys", "trust", "hub",
              "merkle", "session", "package", "declare", "agent", "agents", "setup",
              "harness", "approval", "daemon", "checkpoint", "otel", "prove",
              "prove-chain", "verify-proof", "zk-setup", "zk-tls-setup"}
    # Anything in `top` we don't already cover via cli_in_inventory AND isn't ignored is drift.
    drift = sorted(top - cli_in_inventory - ignore)
    for d in drift:
        warnings.append(f"drift: top-level CLI command 'treeship {d}' not in any feature entry")

    # Reverse drift: a live Hub endpoint no feature entry claims. This is the
    # direction that actually bit us -- /v1/artifacts/{id} served full DSSE
    # envelopes for months while two integrations were scoped around the
    # assumption that it did not.
    for route in sorted(hub_routes - api_in_inventory):
        warnings.append(f"drift: hub endpoint '{route}' not in any feature entry")

    print(f"  ok  {len(data)} feature entries parsed")
    if hub_routes:
        print(f"  ok  {len(hub_routes)} hub routes found in source, "
              f"{len(api_in_inventory & hub_routes)} claimed by an entry")
    for w in warnings:
        print(f"  warn  {w}")
    for e in errors:
        print(f"  err   {e}")

    print()
    print(f"{len(warnings)} warning{'s' if len(warnings) != 1 else ''}, "
          f"{len(errors)} error{'s' if len(errors) != 1 else ''}. "
          f"Run with --strict to fail on warnings.")

    if errors:
        return 1
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
