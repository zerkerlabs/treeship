#!/usr/bin/env python3
"""Check that every runnable docs example would actually run.

Covers unknown long flags plus a few combinations clap accepts but the command
rejects at runtime (unscoped approvals, duration expiries, target-less verify).

Walks each ```bash fence, finds `treeship <subcommand path> --flag ...`, and asks
the binary's own --help whether each `--flag` is real. Fences marked NOT
IMPLEMENTED / NEVER SHIPPED are skipped, same as check-cli-commands.py.

Usage: check-cli-flags.py <path-to-treeship-binary> <content-dir>
Exit 1 if any documented flag is unknown to the command it is shown under.
"""
import re, subprocess, sys, json
from pathlib import Path

TS = sys.argv[1]
ROOT = Path(sys.argv[2])

UNKNOWN = re.compile(r"unrecognized subcommand|invalid subcommand|unexpected argument")
RUNNABLE_LANG = {"bash", "sh", "shell", "console", "zsh", ""}
SKIP_MARKER = re.compile(r"NOT IMPLEMENTED|NEVER SHIPPED|DOES NOT EXIST", re.I)
PLACEHOLDER = re.compile(r'^[\[<{$]|^[A-Z_]{3,}$|^(?:art_|ssn_|grn_|agent_|key_|ship_|hub_|trj_)')
FENCE = re.compile(r'^\s*```(\w*)')
FLAG = re.compile(r'(?<![\w-])(--[a-z][a-z0-9-]*)')

# Rules the flag table alone cannot express: combinations the CLI rejects at
# runtime, so a doc example that omits them fails for the reader.
ISO = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}')

def _approval_needs_scope(path, cmd):
    if path[:2] != ["attest", "approval"]:
        return None
    if re.search(r'--allowed-\w+|--max-uses|--unscoped', cmd):
        return None
    return "attest approval with no --allowed-* / --max-uses / --unscoped is refused: 'approval has no scope'"

def _expiry_must_be_rfc3339(path, cmd):
    if path[:2] != ["attest", "approval"]:
        return None
    m = re.search(r'--expires\s+(\S+)', cmd)
    if not m or m.group(1).startswith(("<", "$", "[")):
        return None
    if ISO.match(m.group(1)):
        return None
    return (f"--expires {m.group(1)} is not RFC 3339; it is stored verbatim and "
            "compared as a string, so the grant reads as already expired")

def _verify_needs_target(path, cmd):
    if path != ["verify"]:
        return None
    rest = cmd.split()[2:]
    if any(not t.startswith("-") for t in rest):
        return None
    return "treeship verify requires a <TARGET> (e.g. `verify last`); flags alone error"

SEMANTIC = [_approval_needs_scope, _expiry_must_be_rfc3339, _verify_needs_target]

_help = {}
def help_text(path):
    key = tuple(path)
    if key not in _help:
        r = subprocess.run([TS, *path, "--help"], capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        _help[key] = None if (r.returncode != 0 and UNKNOWN.search(out)) else out
    return _help[key]

def resolve(tokens):
    """Longest prefix of tokens that is a real command path."""
    path = []
    for t in tokens:
        if help_text(path + [t]) is not None:
            path.append(t)
        else:
            break
    return path

def flags_of(path):
    h = help_text(path) or ""
    return set(FLAG.findall(h)) | {"--help", "--version"}

def blocks(lines):
    lang, start, buf = None, None, None
    for i, line in enumerate(lines, 1):
        m = FENCE.match(line)
        if m and buf is None:
            lang, start, buf = m.group(1).lower(), i, []
        elif m and buf is not None:
            yield lang, buf
            lang, start, buf = None, None, None
        elif buf is not None:
            buf.append((i, line))

results = []
for f in sorted(ROOT.rglob("*.mdx")):
    lines = f.read_text(errors="replace").splitlines()
    for lang, body in blocks(lines):
        if lang not in RUNNABLE_LANG:
            continue
        if any(SKIP_MARKER.search(l) for _, l in body):
            continue
        # join continuation lines so multi-line invocations are seen whole
        joined, pending, pend_line = [], "", None
        for i, line in body:
            t = line.rstrip()
            if pending:
                pending += " " + t.strip().rstrip("\\").strip()
            elif t.strip().lstrip('$').strip().startswith("treeship "):
                pending, pend_line = t.strip().lstrip('$').strip().rstrip("\\").strip(), i
            else:
                continue
            if not t.endswith("\\"):
                joined.append((pend_line, pending)); pending, pend_line = "", None
        if pending:
            joined.append((pend_line, pending))

        for i, cmd in joined:
            cmd = re.split(r'\s{2,}', cmd)[0]
            cmd = re.split(r'\s+(?:#|\||>|&&|│)', cmd)[0]
            toks = cmd.split()[1:]
            sub = []
            for t in toks:
                if t.startswith('-') or PLACEHOLDER.match(t) or '/' in t or '.' in t or ':' in t:
                    break
                sub.append(t)
            path = resolve(sub)
            if not path:
                continue
            # everything after `--` is the wrapped command's own args, not ours
            cmd_own = cmd.split(" -- ")[0]
            known = flags_of(path)
            here = str(f.relative_to(ROOT.parent))
            synopsis = "[OPTIONS]" in cmd_own
            for fl in FLAG.findall(cmd_own):
                if fl not in known:
                    results.append({
                        "file": here, "line": i,
                        "command": " ".join(["treeship"] + path),
                        "problem": f"unknown flag {fl}",
                        "raw": cmd.strip(),
                    })
            for rule in ([] if synopsis else SEMANTIC):
                msg = rule(path, cmd_own)
                if msg:
                    results.append({
                        "file": here, "line": i,
                        "command": " ".join(["treeship"] + path),
                        "problem": msg,
                        "raw": cmd.strip(),
                    })

print(json.dumps(results, indent=2))
print(f"{len(results)} documented invocations would fail as written", file=sys.stderr)
sys.exit(1 if results else 0)
