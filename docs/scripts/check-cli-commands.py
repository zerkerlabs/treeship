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
# Docs re-test (2026-09-27): skills/, integrations/ and the root *.md carry
# runnable fences too. `--warn-root PATH` (a directory, or a file, repeatable)
# scans them and reports findings without failing, until the drift they
# surface is fixed and the roots move to the failing set.
_rest = sys.argv[3:]
WARN_ROOTS = [Path(_rest[i + 1]) for i, a in enumerate(_rest) if a == "--warn-root" and i + 1 < len(_rest)]


def doc_files(root: Path):
    """*.mdx and *.md under a directory (node_modules skipped), or the file itself."""
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.suffix in (".mdx", ".md") and "node_modules" not in p.parts)

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
for f, warn_only in [(p, False) for p in doc_files(ROOT)] + [(p, True) for r in WARN_ROOTS for p in doc_files(r)]:
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
                "warn_only": warn_only,
                "file": (str(f.relative_to(ROOT.parent)) if str(f).startswith(str(ROOT.parent)) else str(f)),
                "line": i,
                "cmd": " ".join(["treeship"] + cmdtoks),
                "unknown_token": bad,
                "valid_prefix": " ".join(["treeship"] + path),
                "raw": line.strip(),
            })

_files = [(p, False) for p in doc_files(ROOT)] + [(p, True) for r in WARN_ROOTS for p in doc_files(r)]
print(f"scanned {len(_files)} file(s), {sum(1 for _, w in _files if w)} under --warn-root", file=sys.stderr)
hard = [r for r in results if not r.get("warn_only")]
soft = [r for r in results if r.get("warn_only")]
print(json.dumps(results, indent=2))
if soft:
    print(f"{len(soft)} finding(s) under --warn-root paths (reported, not failing)", file=sys.stderr)
print(f"{len(hard)} runnable invocations name a nonexistent command", file=sys.stderr)
sys.exit(1 if hard else 0)
