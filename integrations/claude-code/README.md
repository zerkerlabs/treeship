# Treeship + Claude Code Integration

The recommended path is the official plugin -- see [the docs](https://docs.treeship.dev/integrations/claude-code) or run `treeship add claude-code`. The two methods below are for when you don't want the plugin.

## Method 1: CLAUDE.md (instruction-based)

Copy `CLAUDE.md` to your project root. Claude Code reads it automatically and follows the wrapping instructions.

```bash
curl -o CLAUDE.md https://raw.githubusercontent.com/zerkerlabs/treeship/main/integrations/claude-code/CLAUDE.md
```

## Method 2: MCP server (tool-call interception)

Claude Code reads MCP servers from a project's `.mcp.json` (project-scoped) or `~/.claude.json` (user-scoped, under a top-level `mcpServers` key) -- not from `~/.claude/mcp.json`, which Claude Code never reads.

```bash
# Copy the config template into your project root
cp mcp.json .mcp.json
```

Or manually add to your existing `.mcp.json` (or `~/.claude.json`'s `mcpServers` key):

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": {
        "TREESHIP_ACTOR": "agent://claude-code",
        "TREESHIP_HUB_ENDPOINT": "https://api.treeship.dev"
      }
    }
  }
}
```

Restart Claude Code after adding the MCP server.

## Prerequisites

```bash
curl -fsSL https://www.treeship.dev/install | sh
treeship init
```

## Test

1. Open Claude Code in a project with CLAUDE.md or the MCP server configured
2. Ask Claude Code to do a task (e.g. "run the tests")
3. After the task, check the receipt:

```bash
treeship package verify .treeship/sessions/ssn_*.treeship
treeship session report
```

## What to expect in the receipt

With CLAUDE.md (Method 1):
- Every shell command Claude Code wraps appears in the timeline
- Model and cost if TREESHIP_MODEL/COST env vars are set
- File operations detected automatically

With MCP server (Method 2):
- Every MCP tool call appears in the timeline with specific tool name
- Intent and receipt artifacts are Merkle-proven
- Session events make tool calls visible in the receipt
