#!/usr/bin/env python3
"""Check option tables on the CLI pages against the binary's real --help.

The flag checker only reads code fences, so a wrong flag in a markdown table
went unnoticed. This walks each CLI page, tracks which command the nearest
heading is talking about, and validates every `--flag` row in an Options table
under it.

Usage: check-cli-option-tables.py <treeship-binary> <content-dir>
Exit 1 if a documented option does not exist on that command.
"""
import re, subprocess, sys, json
from pathlib import Path

TS = sys.argv[1]
ROOT = Path(sys.argv[2])
CLI_DIR = ROOT / "docs" / "cli"

UNKNOWN = re.compile(r"unrecognized subcommand|invalid subcommand|unexpected argument")
FLAG = re.compile(r'(?<![\w-])(--[a-z][a-z0-9-]*)')
HEADING = re.compile(r'^#{2,4}\s+`?(?:treeship\s+)?([a-z][a-z0-9 -]*?)`?\s*$')
ROW = re.compile(r'^\|\s*`([^`]+)`\s*\|')
TABLE_HDR = re.compile(r'^\|\s*(Option|Flag)s?\s*\|', re.I)

# Pages that are generated from --help, or narrative pages with no single subject.
SKIP_FILES = {"command-matrix.mdx", "overview.mdx", "meta.json"}

_cache = {}
def help_text(path):
    key = tuple(path)
    if key not in _cache:
        r = subprocess.run([TS, *path, "--help"], capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        _cache[key] = None if (r.returncode != 0 and UNKNOWN.search(out)) else out
    return _cache[key]

def resolve(words):
    """Longest prefix of words that names a real command."""
    path = []
    for w in words:
        if help_text(path + [w]) is not None:
            path.append(w)
        else:
            break
    return path

GLOBAL = {"--config", "--format", "--quiet", "--no-color", "--help", "--version"}

results = []
checked_rows = 0
commands_seen = set()
for f in sorted(CLI_DIR.glob("*.mdx")):
    if f.name in SKIP_FILES:
        continue
    # Default subject is the page's own name: cli/verify.mdx -> `treeship verify`
    page_cmd = resolve(f.stem.replace("-cmd", "").split("-"))
    current = page_cmd
    in_table = False
    for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        h = HEADING.match(line)
        if h:
            words = h.group(1).strip().split()
            got = resolve(words)
            # Only retarget when the heading actually names a command; headings
            # like "Options" or "Exit codes" must not reset the subject.
            current = got if got else current
            in_table = False
            continue
        if TABLE_HDR.match(line):
            in_table = True
            continue
        if in_table and not line.startswith("|"):
            in_table = False
        if not in_table or not current:
            continue
        m = ROW.match(line)
        if not m:
            continue
        checked_rows += 1
        commands_seen.add(" ".join(current))
        known = set(FLAG.findall(help_text(current) or "")) | GLOBAL
        for fl in FLAG.findall(m.group(1)):
            if fl not in known:
                results.append({
                    "file": str(f.relative_to(ROOT.parent)), "line": i,
                    "command": " ".join(["treeship"] + current),
                    "unknown_flag": fl, "row": line.strip()[:100],
                })

print(json.dumps(results, indent=2))
print(f"checked {checked_rows} option rows across {len(commands_seen)} commands; "
      f"{len(results)} name a flag the command does not have", file=sys.stderr)
if checked_rows == 0:
    print("no option rows matched — the parser found nothing to check", file=sys.stderr)
    sys.exit(1)
sys.exit(1 if results else 0)
