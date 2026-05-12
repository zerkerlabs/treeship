# Treeship — official OpenClaw plugin

Treeship turns every AI agent session into a portable, signed receipt. Local-first. Cryptographically verifiable. Works offline. Shareable with anyone. The receipt is yours, not ours.

This is the official Treeship plugin for OpenClaw. Install it once and every OpenClaw session becomes a portable, signed receipt — with zero configuration and **no dependency on agent discipline**.

## Why a plugin, not just a skill

Treeship has always shipped a universal SKILL.md (`integrations/openclaw/`) that teaches an agent to call Treeship MCP tools manually after each action. That works, but the integrity model is weak: the agent being attested is the same agent deciding whether to attest. Prompt injection can tell it to skip the call. A small model can forget. A bug in the SKILL.md can drift over a release.

This plugin moves attestation **below the agent**. The hook handlers run in the OpenClaw Gateway process, not the agent's tool-calling context. Every tool call fires `before_tool_call` and `after_tool_call` on the Gateway side regardless of what the agent says, remembers, or has been prompt-injected to do. The receipt is built by infrastructure, not instruction.

This is the same architecture used by the official Treeship plugin for Claude Code (`integrations/claude-code-plugin/`): `SessionStart` / `PostToolUse` / `SessionEnd` shell hooks that run *outside* the LLM context. The OpenClaw plugin is the TypeScript equivalent, and goes one step further by capturing `before_tool_call` too — Claude Code's hook system exposes only the after-the-fact `PostToolUse`.

## Install

```
openclaw plugins install @treeship/openclaw-plugin
```

After install, every OpenClaw session in a project that has a `.treeship/` directory is automatically a Treeship session. New sessions attach the plugin automatically; existing sessions need a restart.

**For local development** against a checked-out copy of this directory:

```
cd integrations/openclaw-plugin
npm install
npm run build
openclaw plugins install --local ./
```

The plugin requires the `treeship` CLI binary on your PATH and a `.treeship/` directory in your project (run `treeship init` once per project). Both are zero-noise: missing CLI or missing `.treeship/` makes the plugin a silent no-op so it never blocks OpenClaw from working.

**Platform support:** macOS and Linux. The plugin shells out to the `treeship` CLI via `child_process`, which is cross-platform; the underlying CLI's Windows support is the gating factor (Windows path is planned alongside the v0.10.x release train).

## What you get

- **Sessions start automatically.** The first event in any project with `.treeship/` triggers `session_start`, opening a Treeship session named after the project + timestamp. You don't run `treeship session start` yourself.
- **Every tool call is captured.** `before_tool_call` records the *intent* (what the agent tried to do, before any policy check) and `after_tool_call` records the *result* (the typed event with side-effect classification). Together they produce a paired timeline: every call is intent → result, not just result.
- **Built-in tools get typed events.** Read / Write / Edit / Bash / WebFetch each map to a specific Treeship event type (`agent.read_file`, `agent.wrote_file`, `agent.completed_process`, `agent.connected_network`). The receipt's side-effects buckets — `files_read[]`, `files_written[]`, `processes[]`, `network_connections[]` — populate correctly instead of every call landing in `agent.called_tool[]`. This is the difference between a thin receipt and a rich one.
- **MCP-routed tools captured too.** When `@treeship/mcp` is configured separately (via `mcporter` or OpenClaw's MCP config), MCP tool calls flow through the bridge automatically. The plugin's `after_tool_call` handler is idempotent against double-capture: the receipt's Merkle tree de-duplicates identical events.
- **Sessions seal automatically.** When the OpenClaw session ends, `session_end` closes the Treeship session with an auto-headline and triggers a hub publish. The shareable URL lands in the local receipt store; the agent can read it on its next status check.
- **Model attribution at session start.** The plugin emits a single `agent.decision` event with the model and provider so the receipt's `agent_graph` carries the right model pill. Detection priority: `TREESHIP_MODEL` env var → `~/.openclaw/config.json` → fallback to `"openclaw"`. Provider is inferred from the model name (claude → anthropic, gpt → openai, kimi → moonshot, etc.) or set via `TREESHIP_PROVIDER`.

## Design rationale

The brief was: zero configuration, sessions start and close themselves, the URL is available without being asked for, the plugin feels native to OpenClaw. Here's how each primitive maps to that goal.

**`before_tool_call` hook.** Records the *intent* — every tool the agent tried to call, before any policy layer can deny it. This is the unique capability the OpenClaw plugin SDK exposes that Claude Code does not: receipts can prove "the agent attempted X" not just "the agent successfully did X." For Approval Authority workflows (treeship.dev/docs/concepts/approval-authority) this is the right primitive to gate on, since the same hook can `return false` to block the call and emit `agent.blocked_request` to the receipt timeline. The current implementation only records intent; blocking semantics are an opt-in we can layer in once the recording path is stable in the wild.

**`after_tool_call` hook.** Records the *result* and dispatches on tool name to a typed event. The dispatch table mirrors the Claude Code plugin's `PostToolUse` shell script (`integrations/claude-code-plugin/scripts/post-tool-use.sh`) translated into TypeScript. The classification function reads the tool's actual fields (`file_path`, `command`, `url`, etc.) from a handful of common context shapes, with safe fall-through to the generic `agent.called_tool` so unknown tools still appear in the timeline.

**Session lifecycle hooks.** Treeship's session lifecycle is "one logical conversation = one receipt." The plugin registers handlers under several plausible OpenClaw hook names (`session_start`, `before_session_start`, `session_end`, `after_session_end`) because plugin SDK versions vary; only the names the runtime actually fires take effect. If your OpenClaw version uses a different name and sessions never open, add it to `src/index.ts`.

**Shelling out to `treeship`.** Same pattern as the Claude Code plugin: the CLI is authoritative, the plugin is a thin event emitter. This keeps the integration robust against `@treeship/sdk` version drift and lets a global `treeship` upgrade fix bugs without republishing the plugin. `runAsync` is used for hot-path events (tool calls) so OpenClaw's main loop is never blocked; `runSync` is used only for session lifecycle (low-frequency, blocking is fine).

**No `monitors.json` equivalent.** Claude Code exposes a "monitor" primitive that streams stdout lines back into the agent's context. OpenClaw's plugin SDK doesn't have a direct analog at v0.10.3. If/when it adds one, this plugin will pick it up — the same `treeship session status` polling logic from the Claude Code monitor will port directly.

**Why hooks instead of asking the model nicely.** Identical reasoning to the Claude Code plugin: hooks are deterministic — they fire on every session regardless of which model is running, what's in the system prompt, or what the user remembered to ask for. A skill-prompted approach drifts the moment someone forgets to mention Treeship, runs a small model that ignores the instruction, or is mid-session when behavior changes. Hooks are the right primitive for any guarantee that has to hold every time. The OpenClaw agent that surfaced this gap put it best: *"the agent being attested is the one deciding whether to attest. That's broken."*

## File tree

```
integrations/openclaw-plugin/
├── package.json                 # npm-installable plugin manifest
├── tsconfig.json                # TS compiler config
├── .gitignore                   # node_modules, dist
├── README.md                    # this file
└── src/
    └── index.ts                 # definePluginEntry + hook registration
```

## Event dispatch table

| OpenClaw tool name (lowercased) | Treeship event |
|---|---|
| `read` / `read_file` / `view` / `view_file` / `cat` / `open` | `agent.read_file --file <path>` |
| `write` / `write_file` / `edit` / `edit_file` / `create` / `create_file` / `patch` / `multi_edit` / `notebook_edit` | `agent.wrote_file --file <path>` |
| `bash` / `shell` / `exec` / `run` / `run_command` / `terminal` | `agent.completed_process --tool <cmd> --exit-code <N>` |
| `fetch` / `web_fetch` / `http` / `curl` / `request` | `agent.connected_network --destination <host>` |
| *(any other)* | `agent.called_tool --tool <name>` |

If your OpenClaw version uses a different tool taxonomy, add cases to the corresponding sets in `src/index.ts` (`READ_TOOLS`, `WRITE_TOOLS`, etc.). Without a typed mapping, the tool still lands in the receipt — just as a generic `agent.called_tool` — so the timeline stays complete but the side-effects buckets won't populate for that tool.

## Environment variables

| Variable | Effect |
|---|---|
| `TREESHIP_MODEL` | Override the model name emitted in the `agent.decision` event at session start. Default: `~/.openclaw/config.json` → `"openclaw"`. |
| `TREESHIP_PROVIDER` | Override the provider emitted in `agent.decision`. Default: inferred from model name (claude→anthropic, gpt→openai, kimi→moonshot, etc.) → `"openclaw"`. |
| `TREESHIP_ACTOR` | Picked up by the `treeship` CLI itself (not this plugin) — sets the actor URI on emitted events. Default for OpenClaw is `agent://openclaw`. |

## Verifying the integration works

After installing, run any OpenClaw session in a Treeship-initialized project, then:

```
treeship session status
# Should show receipts > 0 and events > 0 while the session is live.

treeship session report
# Surfaces the shareable URL after the session is sealed.

treeship verify last
# Offline verification of the local receipt -- proves the timeline,
# Merkle root, and signatures all hold without any network call.
```

A successful receipt should contain:

- `agent_graph.nodes[].model` and `.provider` populated (from the session-start `agent.decision`)
- `side_effects.files_read[]` and `.files_written[]` populated (from `after_tool_call` dispatch)
- `side_effects.processes[]` populated when the session used any shell tool
- `side_effects.tool_invocations[]` populated with `agent.requested_tool` events from `before_tool_call`
- `proofs.signatures_valid: true` and `proofs.merkle_root_valid: true`

If `agent_graph.nodes[].model` is null after a session, the plugin's `agent.decision` emit didn't run — check that `session_start` (or `before_session_start`) is the right hook name for your OpenClaw version.

## Relationship to the universal SKILL.md

The universal Treeship skill (`integrations/openclaw/treeship.skill` → `skills/treeship/SKILL.md`) is the **fallback** path: it teaches an agent to call Treeship MCP tools when the plugin isn't available. With this plugin installed, the skill becomes optional documentation rather than load-bearing infrastructure. The receipt is built by hooks; the skill is for moments when the agent wants to author a meaningful headline or explicitly publish a report.

## Resources

- Treeship docs: https://docs.treeship.dev
- Treeship source: https://github.com/zerkerlabs/treeship
- Claude Code plugin (the reference design): `integrations/claude-code-plugin/`
- Universal skill (fallback): `integrations/openclaw/`
- OpenClaw docs: https://docs.openclaw.ai
