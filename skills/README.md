# Treeship Skills Library

This directory holds the per-agent skill files that teach AI coding agents how
to use Treeship. There is **no universal skill format** — every agent vendor
ships its own loader, format conventions, and discovery rules. We carry one
skill per agent (or per audience), in the shape that agent expects, and live
in the directory that agent looks in.

For per-agent install commands (the `npx skills add ...` recipes), see
[`../integrations/agent-skills/README.md`](../integrations/agent-skills/README.md).
That file maps each skill to the right install path on the user's machine.
This file is the **source-of-truth index** of what skills exist in this repo
and why.

## Skill index

| Skill | Audience | Format | Location in repo | Loads on |
|-------|----------|--------|------------------|----------|
| `treeship` | End user — any agent | Claude-style `SKILL.md` (YAML frontmatter + markdown) | `skills/treeship/` | Claude Code, Kimi Code, Cursor, Codex (via universal installer) |
| `treeship-dev` | Contributor working on the Treeship source repo | Claude-style + Codex plugin manifest | `skills/treeship-dev/` (also packaged at `plugins/treeship-dev/.codex-plugin/`) | Codex, any agent consuming the Codex plugin format |
| `treeship-perplexity` | End user on Perplexity Computer | Perplexity skill (`SKILL.md` + `api_credentials` gh recipes) | `skills/treeship-perplexity/` | Perplexity Computer |
| `treeship-user` (Kimi bundle) | End user on Kimi Code CLI | Kimi skill bundle (`SKILL.md` + executable scripts + references) | `integrations/kimi-code-plugin/treeship-user/` | Kimi Code CLI (skill mechanism) |
| OpenClaw skill | End user on OpenClaw | OpenClaw skill (`treeship.skill/SKILL.md`) | `integrations/openclaw/treeship.skill/` | OpenClaw |
| Hermes skill | End user on Hermes | Hermes skill (`treeship.skill/SKILL.md`) | `integrations/hermes/treeship.skill/` | Hermes |
| Claude Code plugin skills | End user inside the Claude Code plugin | Claude plugin sub-skills | `integrations/claude-code-plugin/skills/{treeship-session,treeship-verify,treeship-report}/` | Claude Code (when the plugin is installed) |

## When to load which skill

- **End user, generic coding agent (Claude Code / Cursor / Codex / Kimi via
  the universal installer):** `skills/treeship/`. Documents the full CLI,
  SDKs (Python + TypeScript), MCP bridge, Hub API, approvals, and chained
  handoffs. This is the canonical end-user skill.
- **Contributor modifying the Treeship source:** `skills/treeship-dev/`.
  Adds repo scope, required read order (`AGENTS.md`, `ONBOARDING.md`),
  crypto invariants that must not change (DSSE PAE, artifact-ID derivation,
  approval-nonce binding, DPoP), CLI UX rules, and validation commands.
  Pair with the end-user skill; the contributor skill assumes API familiarity.
- **End user on Perplexity Computer:** `skills/treeship-perplexity/`. Same
  surface as the canonical skill, plus a **GitHub Access** section with
  `gh api` recipes specific to Perplexity's tool environment (the model
  reaches the repo via `gh` rather than a filesystem checkout).
- **End user on Kimi Code CLI:** `integrations/kimi-code-plugin/treeship-user/`.
  Kimi loads a *bundle* (markdown + executable Python scripts + reference
  docs), not just an `.md` file, so the skill ships with runnable
  `attest_action.py`, `attest_workflow.py`, and `verify_artifact.py`
  examples Kimi can execute directly.
- **End user on OpenClaw or Hermes:** `integrations/<agent>/treeship.skill/`.
  Both runtimes load skills from their own config directories; the install
  command in `agent-skills/README.md` puts the file in the right place.
- **Inside the Claude Code plugin:** the plugin ships three narrowly-scoped
  sub-skills (`treeship-session`, `treeship-verify`, `treeship-report`) for
  the moments that need agent agency, on top of hook-based capture that
  doesn't need any skill to fire.

## How to add a new agent skill

1. Pick the agent and confirm its skill format. **Do not assume Claude's
   YAML frontmatter shape.** Read the agent's docs first; some load
   `SKILL.md`, some load `.skill/` directories, some load bundles with
   executable code alongside the markdown.
2. Pick the location:
   - For a **first-party end-user skill** (canonical agent supported by the
     `npx skills add` installer), it lives in `skills/treeship-<agent>/` if
     it diverges meaningfully from the canonical skill, or stays as
     `skills/treeship/` if the agent can consume the canonical format
     unchanged.
   - For a **plugin-bundled skill** (skill ships with a hook plugin, MCP
     wiring, or other integration assets), it lives under
     `integrations/<agent>(-plugin)/` next to the rest of the integration.
3. Copy the canonical `skills/treeship/SKILL.md` as the starting point. Keep
   the cryptographic invariants and the CLI surface accurate. Adapt the
   install snippet, the environment notes, and any platform-specific tool
   recipes.
4. Add an entry to:
   - The table above.
   - `integrations/agent-skills/README.md` (install command + path).
   - `integrations/agents.json` (the single source of truth that powers
     the docs site and the well-known endpoint).
5. Cross-check the drift items below against the new skill before merging.

## Cross-skill consistency

These facts are easy to drift across skills. Re-verify before adding a new
skill or editing an existing one:

- **npm CLI package is `treeship`** (not `@treeship/cli`). Install via
  `npm install -g treeship`.
- **crates.io publishes `treeship-core`, `treeship-cli`, and
  `treeship-core-wasm`.** Other crates in `packages/` are `publish = false`.
- **Model + provider attribution on the signed-artifact path landed in
  v0.10.2 (#75).** Pre-v0.10.2 the env vars were read but `--provider` was
  rejected by `treeship attest decision`. The env vars themselves
  (`TREESHIP_MODEL`, `TREESHIP_TOKENS_IN/OUT`) date back to v0.7.2;
  `TREESHIP_PROVIDER` to v0.8.0.
- **Pinned trust roots are required since v0.10.3.** Verifying
  hub-checkpoint and agent-certificate artifacts fails with "untrusted
  issuer" until the issuer's public key is registered via `treeship trust
  add`. Every skill should mention this so users hitting `treeship verify`
  on imported artifacts don't read the failure as a bug.

## Discovery

A canonical discovery surface at `treeship.dev/agents` (a public page that
lists every supported agent + the right install command) is on the roadmap
in a separate PR. Today, discovery flows through:

- `integrations/agent-skills/README.md` — human-readable index of install
  commands per agent.
- `integrations/agents.json` — machine-readable source of truth (JSON
  Schema published at `treeship.dev/schemas/agents.v1.json`).
- `/.well-known/treeship-agents.json` on the docs site — same content,
  served from the public domain so other tools can fetch it.

## See also

- [`../integrations/agent-skills/README.md`](../integrations/agent-skills/README.md)
  — per-agent install commands and coverage levels.
- [`../integrations/agents.json`](../integrations/agents.json) — machine-
  readable agent inventory.
- [`../CHANGELOG.md`](../CHANGELOG.md) — feature versions for the cross-
  skill consistency facts above.
