#!/usr/bin/env node
// Generates docs/content/docs/about/changelog.mdx from CHANGELOG.md at the repo
// root. The repo-root CHANGELOG.md is the single source of truth — edit that
// file, not the generated MDX page.
//
// Run from anywhere — paths are resolved relative to this script.
// Hooked into `prebuild` so every Vercel deploy regenerates from the source.
//
// Why this exists: Fumadocs is strict MDX. A bare `<...>` is parsed as JSX and a
// bare `{...}` as a JS expression, so changelog prose like "returns <hex>" or a
// canonical string containing `{ fingerprint }` breaks `next build`. This script
// escapes `<`, `{`, and `}` everywhere EXCEPT inside inline code spans (backticks)
// and fenced code blocks, where MDX already treats content literally. `>` is left
// alone so Markdown blockquotes survive.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");
const SRC = join(REPO_ROOT, "CHANGELOG.md");
const OUT = join(REPO_ROOT, "docs", "content", "docs", "about", "changelog.mdx");

const FRONTMATTER = `---
title: Changelog
description: All notable changes to Treeship, newest first. The format follows Keep a Changelog and versioning follows Semantic Versioning.
---

{/* GENERATED FILE — do not edit. Source: CHANGELOG.md at the repo root.
    Regenerate with \`npm run sync:changelog\` (also runs on every build via prebuild). */}

All notable changes to Treeship are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The canonical source is [\`CHANGELOG.md\`](https://github.com/zerkerlabs/treeship/blob/main/CHANGELOG.md) at the repo root. Edit that file, not this page.
`;

// Escape MDX-significant characters in a prose segment (never called on code).
function escapeProse(seg) {
  return seg
    .replace(/</g, "&lt;")
    .replace(/\{/g, "&#123;")
    .replace(/\}/g, "&#125;");
}

// Escape a full line outside fenced code: split on inline code spans so the
// content inside backticks stays byte-for-byte literal.
function escapeLine(line) {
  // Even indices are prose, odd indices are `code spans` (kept verbatim).
  const parts = line.split(/(`[^`]*`)/g);
  return parts.map((seg, i) => (i % 2 === 1 ? seg : escapeProse(seg))).join("");
}

const src = await readFile(SRC, "utf8");
const out = [];
let inFence = false;
let droppedTitle = false;

for (const line of src.split("\n")) {
  if (/^\s*```/.test(line)) {
    inFence = !inFence;
    out.push(line);
    continue;
  }
  if (inFence) {
    out.push(line); // fenced code: literal
    continue;
  }
  // Drop the source's leading "# Changelog" H1 — the frontmatter title renders it.
  if (!droppedTitle && /^#\s+Changelog\s*$/.test(line)) {
    droppedTitle = true;
    continue;
  }
  out.push(escapeLine(line));
}

const body = out.join("\n").replace(/^\n+/, "").replace(/\n*$/, "");
await mkdir(dirname(OUT), { recursive: true });
await writeFile(OUT, FRONTMATTER + "\n" + body + "\n");
console.log(`sync-changelog: wrote ${OUT}`);
console.log(`  source: ${SRC}`);
