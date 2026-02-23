# Treeship MCP Server

Model Context Protocol server for Treeship verification. Works with Claude Code, Cursor, and any MCP-compatible agent.

## Quick Start

Add to your MCP config:

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "treeship-mcp"],
      "env": {
        "TREESHIP_API_KEY": "ts_live_..."
      }
    }
  }
}
```

## Available Tools

Once configured, your agent has access to:

### `treeship_attest`
Create a verified attestation of an action.

```
<tool_use>
  <name>treeship_attest</name>
  <input>
    <agent>my-agent</agent>
    <action>Approved loan application #12345</action>
    <data>{"amount": 50000, "decision": "approved"}</data>
  </input>
</tool_use>
```

### `treeship_verify`
Verify an existing attestation.

```
<tool_use>
  <name>treeship_verify</name>
  <input>
    <attestation_id>abc123-def456</attestation_id>
  </input>
</tool_use>
```

### `treeship_history`
List recent attestations for an agent.

```
<tool_use>
  <name>treeship_history</name>
  <input>
    <agent>my-agent</agent>
    <limit>10</limit>
  </input>
</tool_use>
```

## Claude Code Setup

1. Create or edit `~/.cursor/mcp.json` (or your Claude Code MCP config location)
2. Add the treeship server config above
3. Restart Claude Code
4. The agent can now use `treeship_attest` in any project

## Cursor Setup

1. Go to Cursor Settings → MCP
2. Add new server with the config above
3. Restart Cursor

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TREESHIP_API_KEY` | Your API key (required) |
| `TREESHIP_DEFAULT_AGENT` | Default agent name if not specified |
| `TREESHIP_API_URL` | Custom API URL for self-hosted instances |
