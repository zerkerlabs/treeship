# @treeship/mcp

Drop-in [Treeship](https://treeship.dev) attestation for MCP tool calls. One import change, every tool call gets a signed receipt.

## Install

```bash
npm install @treeship/mcp
```

Requires the `treeship` CLI binary in PATH:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

## Usage

Change one import. Everything else stays the same.

```typescript
// Before (no attestation):
import { Client } from '@modelcontextprotocol/sdk'

// After (every tool call attested):
import { Client } from '@treeship/mcp'

const client = new Client({ name: 'my-agent', version: '1.0' }, {})
await client.connect(transport)

const result = await client.callTool({
  name: 'brave_search',
  arguments: { query: 'AI safety 2026' }
})

// Treeship metadata attached to result
console.log(result._treeship)
// { intent: 'art_aaa', tool: 'brave_search', actor: 'agent://mcp-my-agent' }
```

## What happens automatically

Every `callTool()` creates two artifacts:

1. **Intent** (awaited before the call) -- proves what was about to happen
2. **Receipt** (fire-and-forget after the call) -- proves what happened

Both are signed with Ed25519, content-addressed, and auto-chained.

## Environment variables

| Variable | Effect |
|----------|--------|
| `TREESHIP_DISABLE=1` | Full passthrough, zero attestation |
| `TREESHIP_ACTOR` | Override default actor URI |
| `TREESHIP_APPROVAL_NONCE` | Bind all calls to an approval |
| `TREESHIP_DEBUG=1` | Log attestation failures to stderr |

## Design rules

- Treeship errors **never** fail the underlying tool call
- Only hashes are stored, **never** raw content
- Intent attestation is **awaited** (proof of what was about to happen)
- Receipt attestation is **fire-and-forget** (never blocks response)
- `TREESHIP_DISABLE=1` produces **zero** overhead

## License

Apache-2.0
