#!/usr/bin/env node
// Syncs integrations/agents.json into:
//   1. docs/public/.well-known/treeship-agents.json  (machine-readable, AI-agent native)
//   2. docs/content/docs/integrations/install.mdx    (human-readable matrix page)
//
// Run from anywhere — paths are resolved relative to this script.
// Hooked into `prebuild` so every Vercel deploy regenerates from the source of truth.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname  = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT  = resolve(__dirname, "..", "..");
const SRC        = join(REPO_ROOT, "integrations", "agents.json");
const WELL_KNOWN = join(REPO_ROOT, "docs", "public", ".well-known", "treeship-agents.json");
const MDX        = join(REPO_ROOT, "docs", "content", "docs", "integrations", "install.mdx");

const data = JSON.parse(await readFile(SRC, "utf8"));

// 1. Mirror raw JSON
await mkdir(dirname(WELL_KNOWN), { recursive: true });
await writeFile(WELL_KNOWN, JSON.stringify(data, null, 2) + "\n");

// 2. Generate MDX matrix
function badge(status) {
  switch (status) {
    case "shipped":     return "🟢 shipped";
    case "candidate":   return "🟡 candidate";
    case "unavailable": return "⚪ unavailable";
    default:            return status ?? "—";
  }
}

function row(agent) {
  const skillCmd  = agent.skill?.available  ? "`" + agent.skill.install  + "`" : "—";
  const mcpCmd    = agent.mcp?.available    ? "`" + agent.mcp.install    + "`" : "—";
  const pluginCmd = agent.plugin?.available ? (agent.plugin.install ? "`" + agent.plugin.install + "`" : "—") : "—";
  return `| **${agent.display_name}** | ${skillCmd} | ${mcpCmd} | ${pluginCmd} | ${badge(agent.plugin?.release_status)} |`;
}

const matrix = data.agents.map(row).join("\n");

const mdx = `---
title: Install matrix
description: One-liner install command per agent, plus the bypass-proof plugin where available.
---

import { Callout } from "fumadocs-ui/components/callout";

# Install matrix

This page is generated from [\`integrations/agents.json\`](https://github.com/zerkerlabs/treeship/blob/main/integrations/agents.json) — the single source of truth for every Treeship integration. Machine-readable mirror: [\`/.well-known/treeship-agents.json\`](/.well-known/treeship-agents.json).

<Callout type="info">
  Tier definitions (\`release_status\`):
  - **🟢 shipped** — installable and end-to-end verified today.
  - **🟡 candidate** — works via the documented install, vendor marketplace submission pending.
  - **⚪ unavailable** — this tier does not exist because the agent's runtime does not expose the required surface.
</Callout>

## The matrix

| Agent | Skill | MCP | Plugin (hook-based) | Plugin status |
|---|---|---|---|---|
${matrix}

## What each tier means

- **Skill** — drops a \`SKILL.md\` instruction file into the agent's skills directory. The agent reads it and follows the instructions to call \`treeship\` CLI commands. **Bypass-able by prompt injection** — the same agent being attested is the one deciding whether to attest.
- **MCP** — exposes Treeship as MCP tools the agent can call. Captures every MCP-routed tool call automatically. Stronger than skill alone (no agent discipline required for MCP-routed work) but doesn't cover the agent's built-in non-MCP tools.
- **Plugin (hook-based)** — runs *below* the agent in the host process. Pre/post-tool-call hooks fire regardless of what the agent says, remembers, or has been prompt-injected to do. **Bypass-proof.** This is the integrity gold standard.

## Run it from anywhere

\`\`\`bash
curl -fsSL treeship.dev/setup | sh
treeship init
treeship add       # detects and instruments every supported agent on this machine
\`\`\`

Or pick one:

${data.agents.filter(a => a.skill?.install?.startsWith("treeship add")).map(a => `- \`${a.skill.install}\``).join("\n")}

## Partnership track

Surfaces where the vendor controls the runtime and a third-party plugin is not currently possible:

${data.partnership_track.map(p => `- **${p.display_name}** (${p.vendor}) — *${p.status}*${p.notes ? ". " + p.notes : ""}`).join("\n")}
`;

await mkdir(dirname(MDX), { recursive: true });
await writeFile(MDX, mdx);

console.log("✓ wrote .well-known/treeship-agents.json (" + (await readFile(WELL_KNOWN, "utf8")).length + " bytes)");
console.log("✓ wrote integrations/install.mdx (" + mdx.length + " bytes)");
console.log("");
console.log("Agents shipped:    " + data.agents.length);
console.log("Partnership track: " + data.partnership_track.length);
