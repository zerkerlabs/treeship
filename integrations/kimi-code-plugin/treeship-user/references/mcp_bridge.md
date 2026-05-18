# Treeship MCP Bridge Reference

The Treeship MCP Bridge (`@treeship/mcp`) exposes Treeship operations as MCP (Model Context Protocol) tools that Claude Code and other MCP-compatible agents can invoke.

## Installation

```bash
npm install -g @treeship/mcp
# or
npx @treeship/mcp@latest
```

## Configuration

Add to your MCP configuration (e.g., `.claude/mcp.json`):

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["@treeship/mcp@latest"]
    }
  }
}
```

Or run directly:
```bash
npx @treeship/mcp@latest --stdio
```

## Available Tools

### `treeship_attest_action`

Create an attestation for an action.

**Input:**
```json
{
  "actor": "agent://my-agent",
  "action": "tool.call",
  "parent_id": "art_abc123",
  "meta": {"tool": "read_file", "path": "src/main.rs"}
}
```

**Output:**
```json
{
  "artifact_id": "art_f7e6d5c4...",
  "success": true
}
```

### `treeship_verify`

Verify an artifact and its chain.

**Input:**
```json
{"artifact_id": "art_abc123"}
```

**Output:**
```json
{
  "outcome": "pass",
  "chain": 3,
  "target": "art_abc123",
  "success": true
}
```

### `treeship_push_hub`

Push an artifact to the Treeship Hub for sharing.

**Input:**
```json
{"artifact_id": "art_abc123"}
```

**Output:**
```json
{
  "hub_url": "https://treeship.dev/verify/art_abc123",
  "success": true
}
```

### `treeship_session_report`

Generate and upload a session report.

**Input:**
```json
{"session_id": "ssn_..."}
```

**Output:**
```json
{
  "session_id": "ssn_f882d38c...",
  "receipt_url": "https://treeship.dev/receipt/ssn_...",
  "events": 55,
  "success": true
}
```

## How It Works

The MCP Bridge wraps the Treeship CLI. When Claude Code invokes an MCP tool:

1. MCP server receives the tool call
2. Translates to `treeship <command>` with proper args
3. Executes via the CLI
4. Returns structured JSON to Claude Code

This means all cryptographic operations happen locally through the CLI — no network calls for signing, no API keys for attestation.

## Session Start Hook (Model Capture)

The Treeship plugin also installs a Claude Code hook for automatic model capture:

```bash
# Automatically reads model from SessionStart hook
# Emits: treeship session event --type agent.decision --model "..."
```

The plugin reads the `model` field from the SessionStart hook payload and emits a `treeship.session.event` of type `agent.decision` with the model name and provider.

**No configuration needed.** Works automatically when Treeship is attached via `treeship attach claude`.
