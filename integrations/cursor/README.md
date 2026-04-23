# Treeship + Cursor

Cursor does not ship Treeship-specific hooks the way the [Claude Code plugin](../claude-code-plugin/) does, but **the same [`@treeship/mcp`](../../bridges/mcp/) bridge** works: every MCP `callTool` is attested and appears in the session timeline when a Treeship session is active.

## Method 1: CLI (recommended)

From a project with `treeship init` already run:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
treeship add cursor
# or: treeship add   # configures every detected agent, including Cursor
```

This merges a `treeship` entry into `~/.cursor/mcp.json` (creating the file and parent dirs if needed). The actor URI is `agent://cursor` so receipts identify Cursor as the tool caller.

**Restart Cursor** so it reloads MCP settings.

`treeship add` also drops `./TREESHIP.md` in the project (once) with the trust and capture details—read that before enabling the server.

## Method 2: Copy the template

If you prefer to edit config by hand, start from `mcp.json` in this directory and merge the `mcpServers.treeship` block into your existing `~/.cursor/mcp.json`.

## Prerequisites

- [Cursor](https://cursor.com) installed (so `~/.cursor/` exists—run Cursor once if the folder is missing).
- `treeship` CLI on `PATH` and Node/npx for `npx -y @treeship/mcp`.
- A Treeship project: `treeship init` in the repo you open in Cursor.

## Session lifecycle

1. `treeship session start` (or your usual workflow) before the agent does work.
2. Use the agent; MCP tool calls are recorded when the Treeship MCP server is enabled in Cursor.
3. `treeship session close` then `treeship log` / `treeship package verify` on the sealed session bundle.

## Optional: `.cursorrules`

Treeship no longer rewrites project rules automatically (`treeship add` focuses on `TREESHIP.md` + MCP). You can add a **`.cursorrules`** snippet if you want the model reminded to use `treeship wrap -- …` for shell commands—useful together with `treeship install` shell hooks. See the [docs site](https://docs.treeship.dev/docs/integrations/cursor).

## Test

1. `treeship init && treeship session start`
2. Open the project in Cursor; confirm **MCP: treeship** is available (Cursor Settings → MCP).
3. Run a task that invokes an MCP tool (or the Treeship-wrapped path you use).
4. `treeship log --tail 20` and `treeship session close` when done.

## What to expect in the receipt

- MCP tool name, SHA-256 digests of arguments and output (not raw content), duration, `isError`, and optional error text on failure.
- See [`TREESHIP.md`](../../TREESHIP.md) in the repo root for the full field list and trust model.
