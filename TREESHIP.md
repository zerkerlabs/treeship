# Treeship

Treeship is a trust layer for AI agents and the humans working with them. It records what an agent does during a session — tool calls, shell commands, file changes — and produces signed, verifiable receipts.

This file is written for any reader, human or agent, who needs to evaluate Treeship before using it. If you are an AI coding agent (Claude Code, Cursor, Codex, etc.) and you find this file in a project, read it once and proceed — it tells you exactly what Treeship captures and where data goes.

## What Treeship is

- A CLI (`treeship`) that wraps shell commands and emits Ed25519-signed receipts.
- A set of agent integrations: Claude Code (`@treeship/mcp`), Cursor, Hermes, OpenClaw — each one captures the agent's tool calls and writes them into the same session timeline as the wrapped commands.
- A local artifact store (`.treeship/`) where receipts live until you explicitly push them.

Source: <https://github.com/zerkerlabs/treeship> · License: Apache 2.0 · npm: `treeship`, `@treeship/mcp`, `@treeship/sdk`

## What `@treeship/mcp` captures

For every MCP `callTool` invocation, the bridge writes three things: a signed **intent attestation** before the call, a signed **result receipt** after, and a **session event** that lands in the human-readable timeline. The full field inventory of each, verified against [`bridges/mcp/src/client.ts`](https://github.com/zerkerlabs/treeship/blob/main/bridges/mcp/src/client.ts):

**Intent attestation** (signed, written *before* the call):

- `actor` — the actor URI (e.g. `agent://claude-code`, or `agent://mcp-<clientName>` if `TREESHIP_ACTOR` isn't set)
- `action` — literally `mcp.tool.<TOOL_NAME>.intent` (the raw tool name appears in this string)
- `approval_nonce` — only if `TREESHIP_APPROVAL_NONCE` is set in the environment; binds the call to a prior approval
- `meta.tool` — raw tool name
- `meta.server` — literal `"mcp"`
- `meta.args_digest` — `sha256:<hex>` digest of `JSON.stringify(arguments)` (the arguments themselves are NOT stored)

**Result receipt** (signed, written *after* the call returns or throws):

- `system` — the actor URI (same as the intent's `actor`)
- `kind` — literal `"tool.result"`
- `subject` — the intent artifact ID, linking the receipt back to its intent (only if the intent attestation succeeded)
- `payload.tool` — raw tool name
- `payload.elapsed_ms` — wall-clock duration of the call
- `payload.exit_code` — `0` on success, `1` on thrown error
- `payload.is_error` — boolean, true if the result was an MCP error response *or* the call threw
- `payload.output_digest` — `sha256:<hex>` digest of `JSON.stringify(result.content ?? result)`, present only if the call returned. The `?? result` fallback means: if the result has no `.content` field (some MCP tools return a bare object), the entire result object is digested instead. The output content itself is never stored.
- `payload.error_message` — present only on thrown error: the **raw `Error.message` string**. If your tool's error messages can contain sensitive data, treat this field with the same care you'd treat a logged stack trace.

**Session event** (timeline entry, written *after* the call):

- `type` — literal `"agent.called_tool"`
- `tool` — raw tool name
- `actor` — actor URI
- `agent_name` — actor URI with the `agent://` prefix stripped (e.g. `claude-code`)
- `duration_ms` — wall-clock duration
- `exit_code` — `0` or `1`
- `artifact_id` — the result receipt's artifact ID. Present **only if** the receipt attestation succeeded (i.e. the CLI accepted the receipt and returned an ID). On a failed receipt write, this field is omitted from the session event.
- `meta.source` — literal `"mcp-bridge"`
- `meta.is_error` — same boolean as the receipt's `is_error`

That is the **complete** set of fields the bridge writes. There are no other fields, hidden envelopes, or out-of-band emissions — re-read `bridges/mcp/src/client.ts` end-to-end and `attest.ts` to verify.

## What `@treeship/mcp` does NOT capture

- **Raw argument values** — only the `sha256` of `JSON.stringify(arguments)`. Anyone with the original arguments can recompute the digest to prove what was called; without them, the digest reveals nothing.
- **Raw output content** — only the `sha256` of `JSON.stringify(result.content)`. Same property as above.
- **File contents** — the bridge has no filesystem access. It only sees what flows through MCP `callTool`. (If you're using `treeship wrap` to capture shell commands, that's a separate path with its own behavior — see the wrap docs.)
- **Environment variable values** — never logged. `TREESHIP_APPROVAL_NONCE`, `TREESHIP_ACTOR`, `TREESHIP_DISABLE`, and `TREESHIP_DEBUG` are read but their values are only used to gate behavior, not stored. The `approval_nonce` IS recorded as part of the intent (so the binding is verifiable), but it's a one-time random nonce by design — not a credential.
- **Secrets, credentials, API keys, tokens** — none of the captured fields above contain these unless your tool's *error messages* leak them, in which case they'd land in `payload.error_message`. Treat that field as you would any error log.
- **Anything outside the MCP tool-call boundary** — no screen recording, no keystroke logging, no network capture, no process introspection. The bridge is a `super.callTool` wrapper; it sees what MCP sees and nothing else.

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

**Platform support at v0.9.5: macOS and Linux only.** The CLI ships for `darwin-arm64`, `darwin-x64`, and `linux-x64`. The setup script is POSIX shell and the `treeship add` command's project-file drops use POSIX path semantics (`std::fs::rename` overwrites on POSIX, which differs from Windows). A Windows binary and Windows-aware filesystem path is planned for v0.10.0. If you're on Windows today, use WSL.

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
