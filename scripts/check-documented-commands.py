#!/usr/bin/env python3
"""Fail when the docs tell a reader to run a command that does not exist.

The 2026-08-18 docs QA found 17 of 134 documented CLI targets missing. Two
examples show why this matters more than a typo:

  * `treeship hub sync-trust` appears in cli/verify.mdx directly beneath
    "trust pinning is mandatory and fail-closed", offered as the easy way out.
    It has never existed. A reader hits the fail-closed error, follows the
    suggestion, gets "unrecognized subcommand", and now has no path forward.

  * `treeship grant revoke` is real -- but landed after the v0.24.0 tag, so
    nobody running the released binary can use it. Documenting main while
    users run the release is its own kind of wrong.

# What this checks

Every `treeship <sub> [<sub>]` invocation in a fenced code block, against the
built binary's own `--help` tree. The binary is the authority: a hand-kept list
of valid commands would drift exactly like the docs did.

# What it deliberately does not check

Flags. Verifying those means parsing every help page and would fail on
legitimate prose. Missing *commands* is the failure that leaves a reader
stuck; a wrong flag at least produces a usable error naming the right ones.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "content" / "docs"
BIN = ROOT / "target" / "debug" / "treeship"

# Words that follow `treeship` but are not subcommands.
NOT_COMMANDS = {
    "--help", "-h", "--version", "-V", "--config", "--format", "--quiet",
    "help", "<command>", "[command]", "...", "|",
}


_probe_cache: dict[tuple[str, ...], bool] = {}


def exists(path: list[str]) -> bool:
    """Does the binary accept this command path?

    Probes with `--help` and reads the exit code, rather than parsing the
    `Commands:` section of the parent's help.

    That distinction is the whole correctness of this check. The first version
    parsed the listing and flagged `checkpoint`, `agent`, `agents`, `bundle`,
    `daemon`, `dashboard` and `approval` as nonexistent -- every one of them
    real, just hidden from the top-level listing. A gate that accuses the docs
    of documenting commands that do exist trains people to ignore it, which is
    worse than no gate.
    """
    key = tuple(path)
    if key in _probe_cache:
        return _probe_cache[key]
    try:
        out = subprocess.run(
            [str(BIN), *path, "--help"],
            capture_output=True, text=True, timeout=30,
        )
        ok = out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    _probe_cache[key] = ok
    return ok


# Headings that mark a block as not-yet-shipped. A doc that says "Proposed
# CLI" above a fence is being honest about the future, and flagging it would
# make this check cry wolf on exactly the pages that got it right.
#
# The separate problem -- that a fenced block under such a heading still looks
# copy-pasteable -- is a presentation fix, not a missing-command bug.
FORWARD_LOOKING = re.compile(
    r"^#+\s.*\b(proposed|planned|future|not yet|unbuilt|design sketch|roadmap)\b",
    re.IGNORECASE,
)


def documented() -> tuple[dict, dict]:
    """Every `treeship ...` invocation inside a fenced block.

    Returns (shipped_context, proposed_context) so the caller can hold them to
    different standards.
    """
    seen: dict[tuple[str, ...], list[tuple[Path, int]]] = {}
    proposed: dict[tuple[str, ...], list[tuple[Path, int]]] = {}
    for mdx in sorted(DOCS.rglob("*.mdx")):
        fenced = False
        under_proposal = False
        proposal_level = 0
        for n, line in enumerate(mdx.read_text(encoding="utf-8").splitlines(), 1):
            if not fenced and line.startswith("#"):
                level = len(line) - len(line.lstrip("#"))
                if FORWARD_LOOKING.match(line):
                    under_proposal = True
                    proposal_level = level
                elif under_proposal and level <= proposal_level:
                    # A heading at or above the proposed one ends its scope.
                    # Deeper headings inherit it: `### Generate a key` under
                    # `## Proposed: key management` is still proposed, and
                    # resetting on every heading made the marker useless the
                    # moment a section had subsections.
                    under_proposal = False
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if not fenced:
                continue
            # Anchored to the start of the line, optionally after a shell
            # prompt or a pipe. Without this, prose inside a fenced block --
            # "the receipt file locally", "your treeship directory so ..." --
            # parses as a command and produces false accusations, which train
            # people to ignore the check.
            stripped = line.strip()
            for prefix in ("$ ", "> ", "% "):
                if stripped.startswith(prefix):
                    stripped = stripped[len(prefix):].lstrip()
                    break
            if not stripped.startswith("treeship"):
                continue
            for m in re.finditer(r"^treeship\s+([a-z][a-z0-9-]*)(?:\s+([a-z][a-z0-9-]*))?", stripped):
                first, second = m.group(1), m.group(2)
                if first in NOT_COMMANDS:
                    continue
                key = (first,) if not second or second in NOT_COMMANDS else (first, second)
                target = proposed if under_proposal else seen
                target.setdefault(key, []).append((mdx, n))
    return seen, proposed


def main() -> int:
    if not BIN.exists():
        print(f"  err   {BIN} not built; run: cargo build -p treeship-cli")
        print("        Without the binary this check would pass vacuously.")
        return 1

    # Sanity: a command everyone agrees exists. If this fails the probe itself
    # is broken and every result below would be a false accusation.
    if not exists(["verify"]):
        print("  err   probing the binary failed (`treeship verify --help` did not succeed)")
        print("        Refusing to report missing commands from a broken probe.")
        return 1

    invocations, proposed = documented()
    if not invocations:
        print("  err   no `treeship` invocations found in docs; the scan is broken")
        return 1

    missing: list[str] = []
    for key, sites in sorted(invocations.items()):
        if exists(list(key)):
            continue
        # Two tokens where the first is real: the second may be an argument
        # rather than a subcommand, so only report if the pair fails AND the
        # parent takes subcommands at all.
        if len(key) == 2 and exists([key[0]]):
            parent_help = subprocess.run(
                [str(BIN), key[0], "--help"], capture_output=True, text=True, timeout=30
            ).stdout
            if "Commands:" not in parent_help:
                continue  # takes arguments, not subcommands
        where = ", ".join(f"{p.relative_to(ROOT)}:{n}" for p, n in sites[:3])
        missing.append(f"treeship {' '.join(key)} -- not accepted by the CLI ({where})")

    if missing:
        for m in missing:
            print(f"  err   {m}")
        print()
        print(
            f"{len(missing)} documented command(s) the CLI does not accept. A reader who "
            "runs one gets `unrecognized subcommand` and no way forward -- worse when the "
            "line sits under a fail-closed error as the suggested fix."
        )
        return 1

    unbuilt = sorted(k for k in proposed if not exists(list(k)))
    if unbuilt:
        # Reported, never failed. These pages said "proposed" and meant it.
        print(f"  note  {len(unbuilt)} command(s) documented under a proposed/planned heading "
              "and not yet built:")
        for k in unbuilt[:8]:
            print(f"        treeship {' '.join(k)}")
    print(f"  ✓ every documented treeship command is accepted ({len(invocations)} distinct invocations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
