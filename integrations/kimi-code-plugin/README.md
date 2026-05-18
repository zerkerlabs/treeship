# Treeship + Kimi Code CLI

This directory hosts Kimi-specific Treeship integrations. Today it ships
**one** artifact: the Kimi-format skill bundle.

## Skill bundle: [`treeship-user/`](./treeship-user/)

Kimi loads skills as **bundles** — a directory containing `SKILL.md` plus
optional executable scripts and reference docs that the agent can read or
run directly. The bundle in this directory includes:

- `treeship-user/SKILL.md` — the end-user skill content (CLI, SDKs, MCP
  bridge, Hub API, approvals, chained workflows, model provenance).
- `treeship-user/scripts/attest_action.py` — runnable example: sign a
  single agent action.
- `treeship-user/scripts/attest_workflow.py` — runnable example: chained
  multi-step workflow with verify.
- `treeship-user/scripts/verify_artifact.py` — runnable example: verify
  an artifact chain.
- `treeship-user/references/sdk_api.md` — full Python SDK + CLI reference.
- `treeship-user/references/typescript_sdk.md` — TypeScript SDK reference.
- `treeship-user/references/hub_api.md` — Hub API endpoints and DPoP auth.
- `treeship-user/references/mcp_bridge.md` — MCP bridge tools and config.

### Install

Point Kimi's skill loader at this directory, or copy the bundle into
Kimi's skills path (Kimi's skill mechanism documents the exact path; on
recent Kimi Code CLI it's typically under `~/.config/agents/skills/`).
The skill name (`treeship-user`) is taken from the `name` field in the
YAML frontmatter of `SKILL.md`.

Once installed, Kimi loads the skill on session start and can both read
the markdown context and execute the bundled Python scripts directly.

### Why a bundle and not just `SKILL.md`

Kimi's skill format supports shipping runnable code alongside the
instruction file, so the bundled scripts let the agent demonstrate or
execute attestation flows without re-deriving them from the docs. For
agents that only consume a single `SKILL.md` (Claude Code, Cursor,
Codex), use the canonical end-user skill at
[`../../skills/treeship/`](../../skills/treeship/) — same surface,
single-file format.

### Coverage

- **Skill bundle alone**: Medium. Kimi knows the API and runs `treeship
  wrap` when prompted to by the skill, but tool calls Kimi makes outside
  that flow aren't captured.
- **Skill bundle + `@treeship/mcp`**: High. Every MCP tool call routes
  through the bridge and emits a signed event regardless of whether the
  agent remembered to wrap it.

To attach the MCP bridge:

```bash
kimi mcp add --transport stdio treeship -- npx -y @treeship/mcp
```

## Related

- [`../../skills/treeship/SKILL.md`](../../skills/treeship/SKILL.md) —
  canonical end-user skill (single-file format), for agents that don't
  consume bundles.
- [`../../skills/README.md`](../../skills/README.md) — full skills library
  index across every supported agent.
- [`../agent-skills/README.md`](../agent-skills/README.md) — per-agent
  install commands.
