# Treeship × Nanobot.ai Integration

Add verifiable audit trails to Nanobot.ai agents via MCP (Model Context Protocol).

## Installation

Add Treeship to your Nanobot MCP configuration:

```yaml
# nanobot.yml or mcp.yml
mcp_servers:
  treeship:
    url: http://treeship-sidecar:2019/mcp
```

Or if running the sidecar locally:

```yaml
mcp_servers:
  treeship:
    url: http://localhost:2019/mcp
```

## Docker Compose Setup

```yaml
services:
  nanobot:
    image: your-nanobot-agent:latest
    depends_on:
      treeship-sidecar:
        condition: service_healthy

  treeship-sidecar:
    image: zerker/treeship-sidecar:latest
    environment:
      - TREESHIP_API_KEY=${TREESHIP_API_KEY}
      - TREESHIP_AGENT=my-nanobot-agent
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:2019/health"]
      interval: 10s
```

## Available Tool

Once configured, your Nanobot agent has access to:

### treeship_attest

Create a tamper-proof record of an agent action.

**Parameters:**
- `action` (string): What happened
- `inputs` (object, optional): Contextual data (hashed locally)

**Returns:**
- `url`: Verification URL on success
- Status message on failure

## Usage Example

The agent can call the tool naturally:

```
User: Summarize this contract and approve if valid.

Agent: I'll analyze the contract and create a verified record.
[MCP tool call: treeship_attest(
  action="Contract analyzed: valid, recommending approval",
  inputs={"contract_id": "c_123", "decision": "approve"}
)]

Contract approved. Verification record: https://treeship.dev/verify/ts_abc123
```

## Verification

Anyone can verify attestations at `treeship.dev/verify/{id}` without an account.
