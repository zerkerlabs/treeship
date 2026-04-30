# feat: Add Treeship Agent Skills — One skill, every agent

Adds a single `SKILL.md` that teaches Kimi Code CLI, Claude Code, Codex, Cursor, OpenClaw, and Hermes how to use Treeship — CLI commands, both SDKs, MCP bridge wiring, approval-gated workflows, multi-agent handoffs, Hub API. The skill is declarative (just text); the agent decides when to apply it. One file, every supported agent.

The skill is the missing piece in the agent-native experience: pair it with the [v0.10.0 receipt-sharing release](https://github.com/zerkerlabs/treeship/releases) and an agent on a fresh machine can install Treeship, run a session, share a receipt, and hand the human a verifiable URL — all without re-explaining the API.

## What's Added

```
treeship/
├── skills/
│   └── treeship/
│       └── SKILL.md                         (new — the universal skill)
├── integrations/
│   └── agent-skills/
│       └── README.md                        (new — multi-agent setup guide)
└── docs/
    └── content/
        ├── docs/integrations/
        │   └── agent-skills.mdx             (new — docs page)
        └── blog/
            └── multi-agent-skills.mdx       (new — launch post)
```

Total: 4 new files (5 if you count this PR description).

## Supported Agents

| Agent | Install Command |
|---|---|
| Kimi Code CLI | `npx skills add zerkerlabs/treeship --skill treeship --agent kimi-cli -g -y` |
| Claude Code | `npx skills add zerkerlabs/treeship --skill treeship --agent claude-code -g -y` |
| Codex | `npx skills add zerkerlabs/treeship --skill treeship --agent codex -g -y` |
| Cursor | `npx skills add zerkerlabs/treeship --skill treeship --agent cursor -g -y` |
| OpenClaw | `npx skills add zerkerlabs/treeship --skill treeship --agent openclaw -g -y` |
| Hermes | `mkdir -p ~/.hermes/skills/treeship && curl -fsSL <SKILL.md raw url> -o ~/.hermes/skills/treeship/SKILL.md` |

`-g` installs globally (every project on the machine sees it). `-y` skips the confirm prompt — useful in CI / scripted setup.

## What the Skill Teaches

- **Every Treeship CLI command** — `wrap`, `verify`, `session report`, `approve`, `hub push`, plus the v0.9.x setup / harness / agents surface.
- **Python SDK shape** — `Treeship().attest_action()`, `attest_approval()`, `attest_decision()`, `verify()`, `dock_push()`, `session_report()`.
- **TypeScript SDK shape** — `Ship.init()`, `attestAction()`, `attestHandoff()`, `createCheckpoint()`, `createBundle()`.
- **Approval-gated workflows** — the create-approval / consume-with-nonce / verify-with-replay-checks pattern.
- **Chained workflows** — multi-agent handoffs linked by `parent_id`, the chain walk `treeship verify` runs.
- **MCP bridge wiring per agent** — `claude mcp add`, `kimi mcp add`, Cursor `mcp.json`, Codex `config.toml` snippets.
- **Hub API surface** — DPoP auth, public verification URLs, Merkle inclusion proofs.
- **Standards reference** — Ed25519 (RFC 8032), DSSE, SHA-256, RFC 8785 canonicalization.

The skill is **declarative, not procedural**: it doesn't run anything itself. It teaches the agent the API and the right shape for each use case. The agent decides when to call the CLI or SDK based on what the user actually asked for. That keeps the skill safe (it's just text) and portable (same file, every agent).

## MCP Bridge

The skill teaches the agent what to do. The optional MCP bridge ([`@treeship/mcp`](https://www.npmjs.com/package/@treeship/mcp)) captures whatever the agent does. Together they give High coverage without prompting — every Read, Write, Bash, and MCP tool call gets attested automatically.

```bash
claude mcp add --transport stdio treeship -- npx -y @treeship/mcp
kimi mcp add --transport stdio treeship -- npx -y @treeship/mcp
# Cursor / Codex / OpenClaw — add to their respective MCP config (see integration guide)
```

Hermes uses skill-driven `treeship wrap` calls (no MCP today); coverage stays Medium.

## Files to Review

- `skills/treeship/SKILL.md` — the skill content. The frontmatter `description` is what the agent matches against the user's intent; verify the trigger phrases cover the cases you care about.
- `integrations/agent-skills/README.md` — the per-agent setup guide. Verify the install path table and per-agent MCP wiring.
- `docs/content/docs/integrations/agent-skills.mdx` — the docs site page (Fumadocs format). Wired into `docs/content/docs/integrations/meta.json` as the first entry under "Integrations" so it surfaces ahead of the per-agent pages.
- `docs/content/blog/multi-agent-skills.mdx` — the launch post.

## After Merging

- The skill is publishable to the [`skills add`](https://github.com/anthropics/skills) registry under `zerkerlabs/treeship` so the install commands above resolve. Coordinate with the skills registry team or run the publish step out-of-band; this PR doesn't gate on it.
- Update [docs.treeship.dev](https://docs.treeship.dev/integrations/agent-skills) homepage / landing if you want to surface the skill as a top-level "first thing every agent should install" CTA.
- Announce on the Treeship blog (the launch post in this PR is ready to go live as soon as the merge lands — it's wired into `docs/content/blog/`).
- Consider versioning the skill content with each release: each `treeship` release that changes the CLI surface or SDK shape should push a matching `SKILL.md` update. The "Updating" section of the integration guide already tells users how to pin (`npx skills add zerkerlabs/treeship@v0.10.0 ...`).

## Testing Checklist

- [ ] `SKILL.md` frontmatter parses (YAML head + Markdown body)
- [ ] All install commands in the integration guide and docs page reference the right agent flag and path
- [ ] Every link in the docs page resolves to an existing route (`/integrations/claude-code`, `/guides/coverage-levels`, `/guides/install`)
- [ ] Blog post date is correct and `tags` field matches the existing blog format

## Related

- [v0.10.0 — Agent-Native Receipt Sharing](../../releases) — the receipt-side companion to this skill (server-rendered receipt pages, agent-native JSON contract, downloadable `.treeship` packages)
- [Coverage levels](https://docs.treeship.dev/guides/coverage-levels) — what High / Medium / Basic actually mean
- [Anthropic Skills docs](https://github.com/anthropics/skills) — the SKILL.md format spec
