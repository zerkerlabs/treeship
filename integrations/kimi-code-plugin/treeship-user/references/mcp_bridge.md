# Treeship MCP Bridge Reference

The Treeship MCP Bridge (`@treeship/mcp`) exposes Treeship operations as MCP
(Model Context Protocol) tools that Claude Code, Kimi, and other
MCP-compatible agents can invoke. It wraps the `treeship` CLI: every tool
call shells out to `treeship <command> --format json` and returns that
command's own JSON stdout as the tool result -- there is no separate wrapper
schema, so read a tool's description below for what it actually runs, not a
fixed `{ ..., "success": true }` shape.

## Installation

```bash
npm install -g @treeship/mcp
# or
npx -y @treeship/mcp
```

## Configuration

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"]
    }
  }
}
```

## Available tools (9 total, `bridges/mcp/src/server.ts`)

### `treeship_session_status`

No input. Runs `treeship session status --format json`: the active
session's id, name, started_at, event count and current actor.

### `treeship_session_event`

Append a structured event to the active session's timeline.

| Input | Type | Required |
|-------|------|----------|
| `type` | string | Yes -- e.g. `agent.note`, `agent.decision`, `agent.handoff` |
| `tool` | string | No |
| `durationMs` | number | No |
| `exitCode` | number | No |
| `meta` | object | No -- free-form, no secrets |

Use `type: "agent.note"` with `meta: { text: "..." }` for a free-form note
on the receipt timeline.

### `treeship_attest_action`

Sign an action artifact.

| Input | Type | Required |
|-------|------|----------|
| `action` | string | Yes -- e.g. `mcp.fetch.intent`, `git.commit.intent` |
| `parentId` | string | No -- parent artifact id for chaining |
| `meta` | object | No |

### `treeship_verify`

Verify an artifact id (or a path to a `.treeship` file) and its parent
chain.

| Input | Type | Required |
|-------|------|----------|
| `artifactId` | string | Yes |
| `chain` | boolean | No -- walk the full parent chain (default `true`) |

### `treeship_session_report`

Publish the latest closed session as a shareable report. If `summary` is
given, closes the active session with that summary first.

| Input | Type | Required |
|-------|------|----------|
| `summary` | string | No |

### `treeship_mint_challenge`

No input. Mints a 128-bit challenge nonce to hand to another agent. Run
this as the **receiver**, before accepting any work from another agent --
never accept a nonce the sender chose.

### `treeship_present`

Answers a challenge, proving live control of this ship's key.

| Input | Type | Required |
|-------|------|----------|
| `challenge` | string | Yes -- the nonce the counterparty minted (min 32 chars) |
| `actor` | string | No -- defaults to this bridge's actor |

### `treeship_verify_presentation`

Verifies a counterparty's presentation, fully offline, against your own
pinned trust roots.

| Input | Type | Required |
|-------|------|----------|
| `file` | string | Yes -- path to the presentation file |
| `challenge` | string | Yes -- the nonce you minted |
| `maxStapleAge` | string | No -- reject a staple older than this, e.g. `"1h"` |

### `treeship_attest_handoff`

Records that custody of some artifacts passed to another agent. Pass the
presentation file and nonce from a successful `treeship_verify_presentation`
call to get `custody: live`; without them the handoff is `custody: asserted`.
See `bridges/mcp/src/server.ts` for the full parameter list (`to`, `artifacts`,
`custodyReason`, etc.).

## Runtime behavior

- **`TREESHIP_ACTOR`** sets the bridge's actor (default derived from the
  process). **`TREESHIP_DISABLE=1`** disables capture entirely.
- **`TREESHIP_STRICT=1`** makes a signing failure, or an active
  `treeship halt` for this actor, fail the underlying tool call instead of
  letting it proceed with a note. The default is fail-open: a broken
  Treeship install never blocks the agent's real work.
- On startup the bridge best-effort provisions a per-agent signing key
  (`treeship agent register --own-key`) so receipts read `proven (key-bound)`
  instead of `asserted`; failure here is logged and swallowed, never fatal.

There is no `treeship_push_hub` tool -- hub pushes go through
`treeship_session_report` (session-level) or the CLI's `hub push` directly
(single-artifact). There is no automatic model-capture hook wired through
this bridge; that lives in the Claude Code plugin's separate `SessionStart`
hook, not in `@treeship/mcp` itself.
