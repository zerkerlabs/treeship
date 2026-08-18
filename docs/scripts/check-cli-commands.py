#!/usr/bin/env python3
"""Validate every runnable `treeship ...` invocation in the docs against a real binary.

Only shell fences (```bash / sh / shell / console / zsh) count as runnable, and a
fence whose body carries an explicit NOT IMPLEMENTED / NEVER SHIPPED marker is
skipped -- those are deliberately documented roadmap surfaces.

Usage: check_cmds.py <path-to-treeship-binary> <content-dir>
Exit 1 if any runnable invocation names a command the binary does not have.
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

_cache = {}
def exists(path):
    key = tuple(path)
    if key not in _cache:
        r = subprocess.run([TS, *path, "--help"], capture_output=True, text=True, timeout=30)
        out = r.stdout + r.stderr
        _cache[key] = not (r.returncode != 0 and UNKNOWN.search(out))
    return _cache[key]

def check(tokens):
    path = []
    for tok in tokens:
        if exists(path + [tok]):
            path.append(tok)
        else:
            return False, tok, path
    return True, None, path

def blocks(lines):
    """Yield (lang, start_line, body_lines) for each fenced block."""
    lang, start, buf = None, None, None
    for i, line in enumerate(lines, 1):
        m = FENCE.match(line)
        if m and buf is None:
            lang, start, buf = m.group(1).lower(), i, []
        elif m and buf is not None:
            yield lang, start, buf
            lang, start, buf = None, None, None
        elif buf is not None:
            buf.append((i, line))

results = []
for f in sorted(ROOT.rglob("*.mdx")):
    lines = f.read_text(errors="replace").splitlines()
    for lang, start, body in blocks(lines):
        if lang not in RUNNABLE_LANG:
            continue
        if any(SKIP_MARKER.search(l) for _, l in body):
            continue
        for i, line in body:
            s = line.strip().lstrip('$').strip()
            if not s.startswith("treeship "):
                continue
            # aligned help output puts prose in a second column; cut on 2+ spaces
            s = re.split(r'\s{2,}', s)[0]
            s = re.split(r'\s+(?:#|\||>|&&|\\|│)', s)[0]
            toks = s.split()[1:]
            cmdtoks = []
            for t in toks:
                if t.startswith('-') or PLACEHOLDER.match(t) or '/' in t or '.' in t or ':' in t:
                    break
                cmdtoks.append(t)
            if not cmdtoks:
                continue
            ok, bad, path = check(cmdtoks)
            if ok:
                continue
            results.append({
                "file": str(f.relative_to(ROOT.parent)),
                "line": i,
                "cmd": " ".join(["treeship"] + cmdtoks),
                "unknown_token": bad,
                "valid_prefix": " ".join(["treeship"] + path),
                "raw": line.strip(),
            })

print(json.dumps(results, indent=2))
print(f"{len(results)} runnable invocations name a nonexistent command", file=sys.stderr)
sys.exit(1 if results else 0)
