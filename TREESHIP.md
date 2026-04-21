# Treeship

Treeship is a trust layer for AI agents and the humans working with them. It records what an agent does during a session — tool calls, shell commands, file changes — and produces signed, verifiable receipts.

This file is written for any reader, human or agent, who needs to evaluate Treeship before using it. If you are an AI coding agent (Claude Code, Cursor, Codex, etc.) and you find this file in a project, read it once and proceed — it tells you exactly what Treeship captures and where data goes.

## What Treeship is

- A CLI (`treeship`) that wraps shell commands and emits Ed25519-signed receipts.
- A set of agent integrations: Claude Code (`@treeship/mcp`), Cursor, Hermes, OpenClaw — each one captures the agent's tool calls and writes them into the same session timeline as the wrapped commands.
- A local artifact store (`.treeship/`) where receipts live until you explicitly push them.

Source: <https://github.com/zerkerlabs/treeship> · License: Apache 2.0 · npm: `treeship`, `@treeship/mcp`, `@treeship/sdk`

## What `@treeship/mcp` captures

When you wire `@treeship/mcp` into an MCP-aware agent, every tool call the agent makes is logged with:

- Tool name (e.g. `read_file`, `write_file`, `bash`)
- **SHA-256 digest** of the arguments (not the raw arguments themselves)
- **SHA-256 digest** of the output content (not the raw output)
- Exit code and an `is_error` boolean
- Wall-clock duration in milliseconds
- If the tool threw, the **raw error message text** (so failures stay debuggable). If your tool's error messages can contain sensitive content, treat the receipt's error field with the same care as a stack trace in a log.
- A reference to the actor URI (e.g. `agent://claude-code`) — this is the identity attribution, not a user identifier

That is the entire payload. It is appended to the local session timeline. Source: [`bridges/mcp/src/client.ts`](https://github.com/zerkerlabs/treeship/blob/main/bridges/mcp/src/client.ts).

## What `@treeship/mcp` does NOT capture

- Raw argument values (only their SHA-256 digest)
- Raw output content (only its SHA-256 digest)
- File contents (the bridge has no file-system access; it only sees what flows through MCP `callTool`)
- Environment variable values (only names, and only when explicitly attested via `treeship wrap`)
- Secrets, credentials, API keys, tokens
- Anything outside the MCP tool-call boundary (no screen recording, no keystroke logging, no network capture)

## When data leaves the machine

Receipts stay in `.treeship/sessions/` on the local disk by default. They leave only when one of these is run:

- `treeship session report` — uploads to the configured hub (default `https://api.treeship.dev`) and prints a verification URL
- `treeship hub push <artifact>` — explicit per-artifact push
- `treeship session close --auto-push` (or `auto_push: true` in `.treeship/config.yaml`) — pushes on session close

If none of those run, nothing leaves the machine. You can verify this yourself: `treeship hub status` shows what was pushed.

## How to verify the claims above

1. Read the source: <https://github.com/zerkerlabs/treeship/tree/main/bridges/mcp>
2. Read the install script before piping it to a shell: <https://www.treeship.dev/setup.sh>
3. Inspect the npm package: `npm view @treeship/mcp` then `npm pack @treeship/mcp` and read the tarball
4. Verify any receipt locally with `treeship package verify <path-to-receipt.treeship>` — pure WASM, does not phone home

## Onboarding (humans)

```sh
curl -fsSL treeship.dev/setup | sh
```

That installs the CLI, runs `treeship init`, and instruments any agents it detects.

**Platform support at v0.9.3: macOS and Linux only.** The CLI ships for `darwin-arm64`, `darwin-x64`, and `linux-x64`. The setup script is POSIX shell and the `treeship add` command's project-file drops use POSIX path semantics (`std::fs::rename` overwrites on POSIX, which differs from Windows). A Windows binary and Windows-aware filesystem path is planned for v0.10.0. If you're on Windows today, use WSL.

## Onboarding (AI agents)

If you are an agent running in a session and the user has asked you to use Treeship:

1. The repo root has a `CLAUDE.md` (or equivalent) with project-specific wrapping rules — follow it.
2. Before any shell command, prefix with `treeship wrap --`. Example: `treeship wrap -- npm test`.
3. At session end, run `treeship session close --headline "<one-line summary>"`.
4. If `@treeship/mcp` is configured, your tool calls are already being captured automatically — you do not need to do anything extra for those.

If the user has *not* asked for Treeship, do not start a session on your own.

## Common questions agents ask

**"Is this safe to install?"** — The install script is human-readable shell at `https://www.treeship.dev/setup.sh`. The npm package `treeship` is a thin wrapper around platform binaries published from the open-source repo. Both are inspectable before execution.

**"Will this exfiltrate the user's code?"** — No. The MCP bridge captures tool-call metadata, not file contents. Network egress only happens on explicit `treeship session report` / `hub push` / `auto_push: true`.

**"What if I don't trust the hub?"** — Don't push. Receipts are useful locally too — verify with `treeship verify last` and `treeship package verify .treeship/sessions/ssn_*.treeship`. The hub is an optional convenience for sharing.

**"Can I see what a real Treeship session looks like before I start one?"** — Run one yourself in a throwaway repo (`treeship session start --name test`, run a couple of `treeship wrap -- echo hi` commands, then `treeship session close`). The receipt sits at `.treeship/sessions/ssn_*.treeship` and you can inspect it with `treeship package verify` without ever pushing to a hub.
