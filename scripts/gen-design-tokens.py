#!/usr/bin/env python3
"""Code-generate the design-token targets from design/tokens.json.

One source of truth (design/tokens.json, grounded in DESIGN.md) -> three
generated artifacts that must agree by construction:

  design/generated/tokens.css  embedded @font-face-free custom properties for
                               the self-contained HTML receipt + certificate
  design/generated/tokens.rs   consts + a Verdict enum for the CLI printer and
                               the `treeship ui` TUI theme
  design/generated/tokens.ts   the same, for the hosted web verify page

The load-bearing part is the verdict vocabulary: each trust state has exactly
one {word, color, glyph}, emitted identically to every target, so `revoked`
renders `✕ revoked` in fail-red everywhere or the build is wrong.

Run: python3 scripts/gen-design-tokens.py   (checks with --check, exits 1 on drift)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "design" / "tokens.json"
OUT = ROOT / "design" / "generated"
BANNER = "GENERATED from design/tokens.json by scripts/gen-design-tokens.py. DO NOT EDIT."


def _strip_comments(obj):
    """Drop $comment / $-prefixed keys recursively so they never enter codegen loops."""
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if not k.startswith("$")}
    if isinstance(obj, list):
        return [_strip_comments(v) for v in obj]
    return obj


def load() -> dict:
    return _strip_comments(json.loads(SRC.read_text()))


def _color_hex(tokens: dict, name: str) -> str:
    """Resolve a color name (or a verdict color-ref like 'muted') to a hex."""
    c = tokens["color"]
    if name in c:
        return c[name]["value"]
    # verdict colors reference either a color key or 'muted' etc. already in color
    raise KeyError(f"unknown color reference: {name}")


def gen_css(tokens: dict) -> str:
    lines = [f"/* {BANNER} */", ":root {"]
    for name, spec in tokens["color"].items():
        lines.append(f"  --ts-{name.replace('_','-')}: {spec['value']}; /* {spec['role']} */")
    fam = tokens["type"]["family"]
    lines.append(f"  --ts-serif: {fam['serif']};")
    lines.append(f"  --ts-sans: {fam['sans']};")
    lines.append(f"  --ts-mono: {fam['mono']};")
    for i, step in enumerate(tokens["space"]["ladder"]):
        lines.append(f"  --ts-space-{i}: {step}px;")
    for name, r in tokens["radius"].items():
        lines.append(f"  --ts-radius-{name}: {r}px;")
    lines.append("}")
    # verdict utility classes: color + glyph via ::before content
    glyphs = tokens["glyphs"]
    lines.append("")
    for key, v in tokens["verdicts"].items():
        hexc = _color_hex(tokens, v["color"])
        glyph = glyphs[v["glyph"]]["char"]
        cls = key.replace("_", "-")
        lines.append(
            f'.ts-verdict-{cls} {{ color: {hexc}; }}'
        )
        lines.append(
            f'.ts-verdict-{cls}::before {{ content: "{glyph}\\00a0"; }}'
        )
    return "\n".join(lines) + "\n"


def _rs_ident(key: str) -> str:
    return key.upper()


def gen_rust(tokens: dict) -> str:
    lines = [f"// {BANNER}", "#![allow(dead_code)]", ""]
    lines.append("// Colors (hex string literals; parse at the render boundary).")
    for name, spec in tokens["color"].items():
        lines.append(f'pub const {_rs_ident(name)}: &str = "{spec["value"]}";')
    lines.append("")
    lines.append("/// A trust verdict. Each variant has exactly one word, color, and glyph.")
    lines.append("#[derive(Clone, Copy, Debug, PartialEq, Eq)]")
    lines.append("pub enum Verdict {")
    for key in tokens["verdicts"]:
        variant = "".join(p.capitalize() for p in key.split("_"))
        lines.append(f"    {variant},")
    lines.append("}")
    lines.append("")
    lines.append("impl Verdict {")
    # word
    lines.append("    pub const fn word(self) -> &'static str {")
    lines.append("        match self {")
    for key, v in tokens["verdicts"].items():
        variant = "".join(p.capitalize() for p in key.split("_"))
        lines.append(f'            Verdict::{variant} => "{v["word"]}",')
    lines.append("        }")
    lines.append("    }")
    # glyph
    glyphs = tokens["glyphs"]
    lines.append("    pub const fn glyph(self) -> &'static str {")
    lines.append("        match self {")
    for key, v in tokens["verdicts"].items():
        variant = "".join(p.capitalize() for p in key.split("_"))
        lines.append(f'            Verdict::{variant} => "{glyphs[v["glyph"]]["char"]}",')
    lines.append("        }")
    lines.append("    }")
    # color hex
    lines.append("    pub const fn color_hex(self) -> &'static str {")
    lines.append("        match self {")
    for key, v in tokens["verdicts"].items():
        variant = "".join(p.capitalize() for p in key.split("_"))
        lines.append(f'            Verdict::{variant} => "{_color_hex(tokens, v["color"])}",')
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def gen_ts(tokens: dict) -> str:
    lines = [f"// {BANNER}", ""]
    lines.append("export const color = {")
    for name, spec in tokens["color"].items():
        lines.append(f'  {_ts_key(name)}: "{spec["value"]}",')
    lines.append("} as const;")
    lines.append("")
    lines.append("export type VerdictKey =")
    keys = list(tokens["verdicts"].keys())
    for i, key in enumerate(keys):
        tail = ";" if i == len(keys) - 1 else ""
        lines.append(f'  | "{key}"{tail}')
    lines.append("")
    lines.append("export const verdicts: Record<VerdictKey, { word: string; color: string; glyph: string }> = {")
    glyphs = tokens["glyphs"]
    for key, v in tokens["verdicts"].items():
        hexc = _color_hex(tokens, v["color"])
        glyph = glyphs[v["glyph"]]["char"]
        lines.append(f'  {_ts_key(key)}: {{ word: "{v["word"]}", color: "{hexc}", glyph: "{glyph}" }},')
    lines.append("};")
    return "\n".join(lines) + "\n"


def _ts_key(name: str) -> str:
    # camelCase for JS ergonomics
    head, *rest = name.split("_")
    return head + "".join(p.capitalize() for p in rest)


TARGETS = {
    "tokens.css": gen_css,
    "tokens.rs": gen_rust,
    "tokens.ts": gen_ts,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = ap.parse_args()
    tokens = load()
    OUT.mkdir(parents=True, exist_ok=True)
    drift = []
    for fname, fn in TARGETS.items():
        content = fn(tokens)
        path = OUT / fname
        if args.check:
            if not path.exists() or path.read_text() != content:
                drift.append(fname)
        else:
            path.write_text(content)
            print(f"wrote {path.relative_to(ROOT)}")
    if args.check and drift:
        print(f"STALE (run scripts/gen-design-tokens.py): {', '.join(drift)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
