#!/usr/bin/env python3
"""Generate the CLI command matrix docs page from the binary's own --help.

The clap definitions are the contract; this walks `treeship --help` and every
visible subcommand's help, and emits a generated MDX page. Hand-written pages
stay hand-written — this is the complete, code-derived surface next to them.

Usage:
    python3 scripts/gen-cli-reference.py --bin target/debug/treeship          # write
    python3 scripts/gen-cli-reference.py --bin target/debug/treeship --check  # CI diff gate

--check regenerates to memory and exits 1 if the committed page differs, so
a CLI surface change without a docs regen (or a hand-edit of the generated
page) fails CI instead of drifting.
"""

import argparse
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "docs", "content", "docs", "cli", "command-matrix.mdx")

HEADER = """---
title: Command matrix (generated)
description: Every visible treeship command, argument, and flag — generated from the binary's own help output.
---

{/* GENERATED FILE — DO NOT EDIT.
    Generator: scripts/gen-cli-reference.py (CI regenerates and diffs it).
    Regenerate: cargo build -p treeship-cli && python3 scripts/gen-cli-reference.py --bin target/debug/treeship */}

This page is generated from the CLI's own `--help` output, so it cannot drift from the binary. For narrative documentation and examples, use the hand-written pages in this section; when they disagree with this page, this page is right and the other page has a bug.

"""


def run_help(bin_path, cmd_path):
    """Return SHORT help (`-h`) for `treeship <cmd_path...>` — one line per entry."""
    result = subprocess.run(
        [bin_path, *cmd_path, "-h"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "NO_COLOR": "1"},
    )
    return result.stdout or result.stderr


def parse_commands(help_text):
    """Extract (name, one-line description) pairs from a Commands: block."""
    commands = []
    in_block = False
    for line in help_text.splitlines():
        if line.strip() == "Commands:":
            in_block = True
            continue
        if in_block:
            if line and not line.startswith(" "):
                break  # next top-level section (Options:, Arguments:, ...)
            m = re.match(r"^  (\S+)\s+(.*)$", line)
            if m and m.group(1) != "help":
                commands.append((m.group(1), m.group(2).strip()))
            elif line.strip() and not re.match(r"^  \S", line):
                # continuation line of the previous description — ignore
                continue
    return commands


def parse_section(help_text, section):
    """Extract entries from an Arguments:/Options: block as (lhs, description).

    Short-help format: each entry is one indented line, the left-hand side
    (flag/arg spec) separated from the description by 2+ spaces.
    """
    entries = []
    in_block = False
    for line in help_text.splitlines():
        if line.strip() == f"{section}:":
            in_block = True
            continue
        if in_block:
            if line and not line.startswith(" "):
                break  # next top-level section
            m = re.match(r"^\s+((?:-{1,2}|<|\[)\S(?:.*?))(?:\s{2,}(.*))?$", line)
            if m:
                entries.append([m.group(1).strip(), (m.group(2) or "").strip()])
            elif entries and line.strip():
                # rare wrapped description line
                entries[-1][1] = (entries[-1][1] + " " + line.strip()).strip()
    return entries


GLOBAL_FLAGS = {"--config", "--format", "--quiet", "--no-color", "-h, --help", "--help"}


def esc(text):
    """Escape MDX-hostile characters in prose (JSX braces/tags, table pipes)."""
    return (
        text.replace("{", "&#123;")
        .replace("}", "&#125;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
    )


def fmt_command(bin_path, cmd_path, description, depth):
    help_text = run_help(bin_path, cmd_path)
    name = "treeship " + " ".join(cmd_path)
    lines = [f"{'#' * min(depth + 1, 4)} `{name}`", ""]
    if description:
        lines += [esc(description), ""]

    usage = next(
        (l.replace("Usage:", "").strip() for l in help_text.splitlines() if l.strip().startswith("Usage:")),
        None,
    )
    if usage:
        lines += ["```", usage, "```", ""]

    args = parse_section(help_text, "Arguments")
    opts = [
        (lhs, desc)
        for lhs, desc in parse_section(help_text, "Options")
        if lhs.split("<")[0].strip().rstrip() not in GLOBAL_FLAGS
        and not lhs.startswith("-h")
    ]
    if args:
        lines += ["| Argument | Description |", "|---|---|"]
        lines += [f"| `{a.replace('|', chr(92) + '|')}` | {esc(d) if d else '--'} |" for a, d in args]
        lines.append("")
    if opts:
        lines += ["| Option | Description |", "|---|---|"]
        lines += [f"| `{o.replace('|', chr(92) + '|')}` | {esc(d) if d else '--'} |" for o, d in opts]
        lines.append("")

    # Recurse into visible subcommands (one level of nesting is enough for clap).
    for sub, sub_desc in parse_commands(help_text):
        lines.append(fmt_command(bin_path, [*cmd_path, sub], sub_desc, depth + 1))
    return "\n".join(lines)


def generate(bin_path):
    top = run_help(bin_path, [])
    body = [HEADER]
    body.append(
        "Global flags on every command: `--config <PATH>`, `--format <text|json>`, `--quiet`, `--no-color`.\n"
    )
    for cmd, desc in parse_commands(top):
        body.append(fmt_command(bin_path, [cmd], desc, 1))
    return "\n".join(body).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(REPO, "target", "debug", "treeship"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.bin):
        print(f"error: binary not found at {args.bin} (cargo build -p treeship-cli first)", file=sys.stderr)
        return 2

    page = generate(args.bin)

    if args.check:
        try:
            with open(OUT) as f:
                current = f.read()
        except FileNotFoundError:
            current = ""
        if current != page:
            print(
                "command-matrix.mdx is out of date with the CLI surface.\n"
                "Run: python3 scripts/gen-cli-reference.py --bin target/debug/treeship",
                file=sys.stderr,
            )
            return 1
        print("  ✓ command-matrix.mdx matches the CLI surface")
        return 0

    with open(OUT, "w") as f:
        f.write(page)
    print(f"  ✓ wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
