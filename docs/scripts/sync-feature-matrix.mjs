#!/usr/bin/env node
// Generates docs/content/docs/reference/feature-matrix.mdx from
// docs/feature-inventory.yml — the single source of truth for what ships.
//
// Run from anywhere — paths are resolved relative to this script.
// Hooked into `prebuild`/`predev` so every build regenerates from the YAML.
// CI runs this with --check (regenerate + diff) so a hand-edit of the MDX
// or a YAML change without a regen fails the build instead of drifting.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DOCS_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(DOCS_ROOT, "..");
const SRC = join(DOCS_ROOT, "feature-inventory.yml");
const OUT = join(DOCS_ROOT, "content", "docs", "reference", "feature-matrix.mdx");

const SECTIONS = [
  ["core", "Core protocol"],
  ["identity", "Identity, approval, attribution"],
  ["provenance", "Provenance & discovery"],
  ["capture", "Capture surfaces"],
  ["supply-chain", "Supply chain"],
  ["integrations", "Agent integrations"],
  ["zk", "Zero-knowledge proofs"],
];

const entries = parseYaml(await readFile(SRC, "utf8"));

async function docLink(path) {
  // docs/content/docs/x/y.mdx -> [title](/docs/x/y), title from frontmatter.
  const route = "/" + path.replace(/^docs\/content\//, "").replace(/\.mdx$/, "");
  const raw = await readFile(join(REPO_ROOT, path), "utf8");
  const m = raw.match(/^---\n[\s\S]*?^title:\s*['"]?(.+?)['"]?\s*$/m);
  const title = m ? m[1] : route;
  return `[${title}](${route})`;
}

function cliCell(entry) {
  if (!entry.cli?.length) return "--";
  return entry.cli.map((c) => `\`${c}\``).join(", ");
}

let tables = "";
for (const [key, title] of SECTIONS) {
  const rows = entries.filter((e) => e.section === key && e.status !== "internal");
  if (!rows.length) continue;
  tables += `\n## ${title}\n\n| Feature | Status | CLI | Docs |\n|---|---|---|---|\n`;
  for (const e of rows) {
    const docs = e.docs?.length
      ? (await Promise.all(e.docs.map(docLink))).join(", ")
      : "--";
    tables += `| ${e.name} | \`${e.status}\` | ${cliCell(e)} | ${docs} |\n`;
  }
}

const page = `---
title: Feature matrix
description: Every shipped Treeship capability, with status, CLI surface, and docs. Generated from feature-inventory.yml.
---

{/* GENERATED FILE — DO NOT EDIT.
    Source: docs/feature-inventory.yml
    Generator: docs/scripts/sync-feature-matrix.mjs (runs on prebuild; CI diffs it). */}

This page is the canonical list of what Treeship actually ships today. If a capability is described in a blog post or a CHANGELOG entry but does not appear here, treat it as not present.

## Source of truth

This page is **generated** from [\`docs/feature-inventory.yml\`](https://github.com/zerkerlabs/treeship/blob/main/docs/feature-inventory.yml) on every build — edit the YAML, never this file. A linter at [\`scripts/check-feature-inventory.py\`](https://github.com/zerkerlabs/treeship/blob/main/scripts/check-feature-inventory.py) validates every entry against the codebase (CLI commands, doc paths, test paths exist), and CI fails if this page and the YAML disagree.

## Status taxonomy

| Status | Meaning |
|---|---|
| \`stable\` | Shipped, documented, tested. No known gaps. Safe to depend on. |
| \`beta\` | Shipped and used in practice. Rough edges or thin docs. |
| \`experimental\` | Shipped behind a build flag or with explicit caveats. May change. |
| \`quarantined\` | Shipped code found unsound; fails closed and is non-authoritative. Kept as a marker, not a feature. |
| \`roadmap\` | Designed or specced. Not implemented. Listed here so you know it is on the radar. |
| \`deprecated\` | Still supported, but discouraged. A replacement exists. |

Pick \`stable\` only when the code, docs, and tests all line up. If the docs page is missing, the right status is \`beta\`, not \`stable\`.
${tables}
Both \`zk\` CLI paths require the \`--features zk\` build flag; the \`zk\` feature is pre-release and nothing in the default trust path depends on it.

## How to update this page

1. Edit \`docs/feature-inventory.yml\` (add \`section:\` so the entry lands in the right table).
2. Run \`python3 scripts/check-feature-inventory.py --strict\` — fix any warnings about your own entries.
3. \`npm run sync:feature-matrix\` in \`docs/\` (or just build — prebuild regenerates it).
4. If you are adding a new feature, surface it in the next CHANGELOG entry too.
`;

if (process.argv.includes("--check")) {
  const current = await readFile(OUT, "utf8").catch(() => "");
  if (current !== page) {
    console.error(
      "feature-matrix.mdx is out of date with feature-inventory.yml.\n" +
        "Run: cd docs && npm run sync:feature-matrix",
    );
    process.exit(1);
  }
  console.log("  ✓ feature-matrix.mdx matches feature-inventory.yml");
} else {
  await writeFile(OUT, page);
  console.log(`  ✓ wrote ${OUT}`);
}
