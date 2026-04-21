# Treeship — official Claude Code plugin

Treeship turns every AI agent session into a portable, signed receipt. Local-first. Cryptographically verifiable. Works offline. Shareable with anyone. The receipt is yours, not ours.

This is the official Treeship plugin for Claude Code. Install it once and every Claude Code session becomes a portable, signed receipt — with zero configuration.

## Install

From inside Claude Code:

```
/plugin install treeship
```

For local development against a checked-out copy of this directory:

```
claude --plugin-dir /path/to/treeship/integrations/claude-code-plugin
```

The plugin requires the `treeship` CLI binary on your PATH and a `.treeship/` directory in your project (run `treeship init` once per project). Both are zero-noise: missing CLI or missing `.treeship/` makes the plugin a silent no-op so it never blocks Claude Code from working.

## What you get

- **Sessions start automatically.** The first message in any project with a `.treeship/` directory triggers a SessionStart hook that opens a Treeship session named after the project + timestamp. You don't run `treeship session start` yourself.
- **Every tool call is captured.** MCP tool calls flow through the bundled Treeship MCP server (`@treeship/mcp`); built-in Claude Code tools (Read, Write, Edit, Bash, Grep, Glob, etc.) flow through a PostToolUse hook. Combined: full timeline.
- **Sessions seal automatically.** When the Claude Code session ends, a SessionEnd hook closes the session and surfaces the shareable session report URL back into the conversation. You don't have to ask.
- **Live status while you work.** A background monitor streams the receipt counter (`receipts=N events=M`) into Claude's context every few seconds, so the agent knows the receipt is being built.
- **Three skills for the moments that need agency.** `treeship-session` for closing with a real headline before SessionEnd auto-closes. `treeship-verify` for confirming a receipt someone shared with you. `treeship-report` for explicitly publishing a session report URL.

## Design rationale

The brief was: zero configuration, sessions start and close themselves, the URL appears at the end without being asked for, the plugin feels native. Here's how each primitive maps to that goal.

**MCP server (`.mcp.json`).** Mounts `@treeship/mcp` so any *MCP-routed* tool call gets a signed receipt automatically. We use `npx -y` so users don't need to pre-install the bridge — first run pulls it from the npm registry. `${CLAUDE_PLUGIN_DATA}` could host a vendored copy if we later want offline-install support; for now we trust npm.

**Hooks (`hooks/hooks.json`).**
- `SessionStart` — the natural entry point for "every Claude Code session is a receipt". Auto-creates a Treeship session if `.treeship/` exists. Idempotent: if a session is already active, exits cleanly.
- `SessionEnd` — the natural exit point. Closes the session with a generic auto-headline, fetches the report URL, and pushes both into the agent's context via `additionalContext`. The user sees the URL without asking.
- `PostToolUse` — captures Claude Code's *built-in* tools. The MCP server can't see Read/Write/Edit/Bash because they don't go through MCP. This hook routes each built-in call into `treeship session event` so the receipt timeline is complete.

**Monitor (`monitors/monitors.json`).** Per the docs, monitors stream live notifications into Claude's context — perfect for "the receipt is currently being built" signaling without polluting the chat. The monitor watches `session status` and only emits when counters change, so it stays quiet when nothing's happening.

**Skills (`skills/`).** Three small skills, each one focused on a moment when the agent needs to act with intention rather than fire a hook.
- `treeship-session` — fires when the user finishes a meaningful unit of work and wants the receipt to carry a real headline (not the auto-headline SessionEnd would write). Teaches Claude how to write commit-message-quality headlines.
- `treeship-verify` — fires when someone shares a receipt URL or local `.treeship` file and wants confirmation it's authentic. Teaches Claude to be honest about what verification proves vs. doesn't.
- `treeship-report` — fires when the user wants the shareable URL on demand. Reinforces that the receipt is theirs and publishing is opt-in.

**No `settings.json`.** The Claude Code plugin settings layer currently only takes `agent` and `subagentStatusLine` keys. Treeship doesn't ship a custom agent or status line, so a settings file would be empty noise.

**Why hooks instead of asking the model nicely.** The brief is explicit: zero configuration, sessions should start and close automatically. Hooks are deterministic — they fire on every session regardless of which model is running, what's in the system prompt, or what the user remembered to ask for. A model-prompted approach would drift the moment someone forgets to mention Treeship, or runs a small model that ignores the instruction, or is mid-session when behavior changes. Hooks are the right primitive for any guarantee that has to hold every time.

## File tree

```
integrations/claude-code-plugin/
├── .claude-plugin/
│   └── plugin.json                          # manifest: name, version, author, license
├── .mcp.json                                # mounts @treeship/mcp via npx
├── hooks/
│   └── hooks.json                           # SessionStart, SessionEnd, PostToolUse
├── monitors/
│   └── monitors.json                        # live receipts/events counter
├── scripts/
│   ├── session-start.sh                     # SessionStart hook -- treeship session start
│   ├── session-end.sh                       # SessionEnd hook -- close + report URL
│   ├── post-tool-use.sh                     # PostToolUse hook -- session event
│   └── monitor.sh                           # background status streamer
├── skills/
│   ├── treeship-session/SKILL.md            # close with a real headline
│   ├── treeship-verify/SKILL.md             # verify a shared receipt
│   └── treeship-report/SKILL.md             # publish the report URL
└── README.md                                # this file
```

## Local testing

Load the plugin from this directory without publishing:

```bash
claude --plugin-dir $(pwd)/integrations/claude-code-plugin
```

Smoke checklist:

1. Open Claude Code in a directory that has `.treeship/` (run `treeship init` if needed).
2. Send a message that triggers any built-in tool — e.g. "list the files in src/".
3. After Claude responds, check `treeship session status` — there should be an active session named `<project>-claude-code-<timestamp>`.
4. Run `treeship session event --type test --tool smoke` (or just continue chatting) and confirm `receipts` / `events` counters increment.
5. Send `/exit` to end the Claude Code session. Watch for the report URL message in the final context, and confirm `treeship session status` now reports no active session.

If any step fails, every script writes its diagnostic to stderr (use `set -x` at the top of the relevant script and re-run).

## Marketplace submission

Submit the plugin at <https://claude.ai/settings/plugins/submit>.

Submission metadata pulls from `.claude-plugin/plugin.json`. The fields that already exist there match what the marketplace listing needs: `name`, `description`, `version`, `author`, `homepage`, `repository`, `license`, `keywords`. Update the `version` in `plugin.json` before each submission to match the npm versions of `treeship` and `@treeship/mcp` it depends on (currently `0.9.3`).

When submitting, point the marketplace at the `integrations/claude-code-plugin/` subdirectory of the public `zerkerlabs/treeship` repo so anyone can read the source before installing.

## Uninstalling

```
/plugin uninstall treeship
```

Receipts produced while the plugin was active stay on disk in `.treeship/sessions/`. Uninstalling the plugin does not delete them. To stop *new* sessions auto-starting without uninstalling, delete `.treeship/` from the projects you don't want recorded — the plugin's hooks gate on that directory existing.

## Troubleshooting

**The plugin loaded but no session starts.** The plugin auto-starts only when `.treeship/` exists in the project root. Run `treeship init` once. Hooks are silent on missing `.treeship/` by design — adding noise would break Claude Code in unrelated projects.

**The plugin loaded but `treeship` isn't on PATH.** Same silent skip. Install the CLI: `curl -fsSL treeship.dev/setup | sh` or `npm install -g treeship`. The plugin will pick it up on the next session.

**The session report URL doesn't appear at end of session.** Check `treeship hub status` — the report step needs a configured hub. If the hub isn't reachable, the SessionEnd hook still seals the receipt locally and prints a fallback message pointing to `treeship session report` for a manual retry.

**The MCP server isn't capturing tool calls.** `@treeship/mcp` requires `treeship init` (so the MCP server can find the keystore) and an active session (so events have somewhere to land). Both are handled by the SessionStart hook, but if you're testing the MCP server in isolation, run them yourself first.
