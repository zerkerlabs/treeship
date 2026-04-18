# @treeship/mcp

Drop-in [Treeship](https://treeship.dev) attestation for MCP tool calls. One import change, every tool call gets a signed receipt and appears in the session receipt timeline.

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

Every `callTool()` does three things:

1. **Intent** (awaited before the call) -- signed artifact proving what was about to happen `[AUTO]`
2. **Receipt** (fire-and-forget after the call) -- signed artifact proving what happened `[AUTO]`
3. **Session event** -- `agent.called_tool` event emitted to the active session's event log so the tool call appears in the receipt timeline, agent graph, and side effects `[AUTO]`

All three are automatic. The signed artifacts are Merkle-proven. The session event makes them human-readable in the receipt.

## What is captured

| Field | Source | Status |
|-------|--------|--------|
| MCP tool name | `params.name` | `AUTO` -- always captured |
| Input content | SHA-256 digest only | `AUTO` -- never raw content |
| Output content | SHA-256 digest only | `AUTO` -- never raw content |
| Duration | `Date.now()` delta | `AUTO` |
| Exit code | `isError` flag | `AUTO` |
| Error message | `error.message` | `AUTO` -- only on failure |
| Actor URI | `TREESHIP_ACTOR` env or default | `AUTO` |
| Model | Not captured by MCP bridge | `NOT YET CAPTURED` -- set `TREESHIP_MODEL` env var with `treeship wrap` |
| Token counts | Not captured by MCP bridge | `NOT YET CAPTURED` -- set `TREESHIP_TOKENS_IN`/`OUT` env vars |
| Provider | Not captured by MCP bridge | `NOT YET CAPTURED` -- set `TREESHIP_PROVIDER` env var |

## Integration status

| Runtime | Status | Notes |
|---------|--------|-------|
| Generic MCP server | Tested (unit tests) | 3 tests covering Client export and subclass |
| Claude Code MCP | Not yet tested | Should work since Claude Code uses standard MCP transport |
| Hermes | Not yet tested | Hermes transport compatibility to be confirmed |
| Cursor MCP | Not yet tested | Standard stdio transport expected |

## Environment variables

| Variable | Effect |
|----------|--------|
| `TREESHIP_DISABLE=1` | Full passthrough, zero attestation |
| `TREESHIP_ACTOR` | Override default actor URI |
| `TREESHIP_APPROVAL_NONCE` | Bind all calls to an approval |
| `TREESHIP_DEBUG=1` | Log attestation failures to stderr |
| `TREESHIP_MODEL` | Model name for cost tracking (via `treeship wrap`) |
| `TREESHIP_TOKENS_IN` | Input token count (via `treeship wrap`) |
| `TREESHIP_TOKENS_OUT` | Output token count (via `treeship wrap`) |
| `TREESHIP_PROVIDER` | Provider name e.g. "anthropic" (via `treeship wrap`) |

## Design rules

- Treeship errors **never** fail the underlying tool call
- Only hashes are stored, **never** raw content
- Intent attestation is **awaited** (proof of what was about to happen)
- Receipt attestation is **fire-and-forget** (never blocks response)
- Session events are **best-effort** (no active session = silent no-op)
- `TREESHIP_DISABLE=1` produces **zero** overhead

## License

Apache-2.0
