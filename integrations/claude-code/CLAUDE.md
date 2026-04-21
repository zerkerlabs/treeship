# Treeship

This project uses Treeship for signed, verifiable session receipts. Treeship records what AI agents do during a coding session and produces cryptographic proofs you can verify offline.

Source: <https://github.com/zerkerlabs/treeship> · Apache 2.0 · npm: `treeship`, `@treeship/mcp`

## What `@treeship/mcp` captures

For each MCP `callTool`, the bridge writes three things. The complete field inventory, verified against `bridges/mcp/src/client.ts`:

**Intent attestation** (signed, before the call):
- `actor` (URI like `agent://claude-code`)
- `action` (literally `mcp.tool.<TOOL_NAME>.intent`)
- `approval_nonce` (only if `TREESHIP_APPROVAL_NONCE` is set)
- `meta.tool` (raw tool name), `meta.server` (literal `"mcp"`), `meta.args_digest` (sha256 of arguments JSON — NOT the raw arguments)

**Result receipt** (signed, after the call):
- `system` (actor URI), `kind` (literal `"tool.result"`), `subject` (intent ID)
- `payload.tool`, `payload.elapsed_ms`, `payload.exit_code`, `payload.is_error`
- `payload.output_digest` (sha256 of output JSON — NOT the raw output)
- `payload.error_message` (raw `Error.message` text on thrown errors only — treat like a logged stack trace if your tools can leak in error messages)

**Session event** (timeline entry):
- `type` (`agent.called_tool`), `tool`, `actor`, `agent_name`
- `duration_ms`, `exit_code`, `artifact_id` (the receipt ID)
- `meta.source` (literal `"mcp-bridge"`), `meta.is_error`

That is the complete set. No other fields are emitted.

## What it does NOT capture

- Raw argument values or raw output content (digests only)
- File contents (the bridge has no FS access; it only wraps MCP `callTool`)
- Environment variable values or secrets (env vars are read for behavior, never logged)
- Anything outside the MCP tool-call boundary

## When data leaves this machine

Only when one of these is run explicitly:

- `treeship session report`
- `treeship hub push <artifact>`
- `treeship session close` with `auto_push: true` configured

Otherwise receipts stay in `.treeship/sessions/`.

## Before starting any task

```bash
treeship session start --name "<task description>"
export TREESHIP_MODEL=claude-opus-4-6
```

## During work

Prefix every shell command with `treeship wrap --`:

```bash
treeship wrap -- npm test
treeship wrap -- cargo build
treeship wrap -- git commit -m "fix: description"
```

## When done

```bash
treeship session close \
  --headline "<one sentence summary>" \
  --summary "<what changed and why>" \
  --review "<what to verify>"
treeship session report
```

## Rules

- Always use `treeship wrap -- <command>` for shell commands
- Do not start a new session for sub-tasks -- use the same session
- Write specific headlines and summaries, not generic ones
- Close with a review note pointing out risks and edge cases
