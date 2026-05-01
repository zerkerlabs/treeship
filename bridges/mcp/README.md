# @treeship/mcp

Drop-in [Treeship](https://treeship.dev) attestation for MCP tool calls. One import change, every tool call gets a signed receipt and appears in the session receipt timeline.

## Install

```bash
npm install @treeship/mcp
```

Requires the `treeship` CLI binary in PATH. Pick whichever install path you trust:

```bash
# One-liner (installs CLI, runs init, instruments detected agents):
curl -fsSL treeship.dev/setup | sh

# Or read it first, then install via npm (no shell pipe):
curl -fsSL https://www.treeship.dev/setup.sh   # inspect
npm install -g treeship && treeship init       # install
```

## Inspect before you trust

Source for this bridge: <https://github.com/zerkerlabs/treeship/tree/main/bridges/mcp>

Every receipt this bridge produces can be verified locally, without trusting our hub:

```bash
npm install -g treeship
treeship package verify <path-to-receipt.treeship>
```

The verify command is pure WASM — it does not phone home and does not require the hub. So once you have a receipt (your own or someone else's), you can confirm exactly what was captured, by whom, and that the signatures hold, entirely offline.

## Two ways to use it

**As an MCP server** (new in 0.10.1) — add it to your agent's MCP config:

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": { "TREESHIP_ACTOR": "agent://your-agent" }
    }
  }
}
```

The server exposes 5 tools your agent can call: `treeship_session_status`, `treeship_session_event`, `treeship_attest_action`, `treeship_verify`, `treeship_session_report`. Use these to read or write the active Treeship session from any MCP-compatible client.

**As a library** — wrap your existing MCP client. Every `callTool()` gets signed automatically.

## Library usage

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
| Claude Code MCP | Shipped | Used by the official plugin and `treeship add`; stdio MCP — same code path as generic client |
| Cursor MCP | Documented + same client | `treeship add cursor` writes `~/.cursor/mcp.json`; see [`integrations/cursor/`](../../integrations/cursor/) — run a quick E2E when upgrading the bridge |
| Hermes | Not yet tested | Hermes transport compatibility to be confirmed |

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

## Runtime compatibility

Attestation paths (tool-call intent + receipt, session events) still shell out to the `treeship` CLI for filesystem access to the keystore and session log. Those paths need Node with the binary on `PATH`.

Verification helpers (`verifyReceipt`, `verifyCertificate`, `crossVerify`) are WASM-backed since v0.9.1 and run anywhere WebAssembly + `fetch` are available:

| Runtime | Verification | Attest paths |
|---------|-------------|--------------|
| Node.js 18+ | yes | yes |
| Deno | yes | no |
| Browser | yes | no |
| Vercel Edge | yes | no |
| Cloudflare Workers | yes | no |
| AWS Lambda (Node) | yes | no |

For read-only consumers (dashboards, third-party MCP audit tools) that only need verification, depend on [`@treeship/verify`](../../packages/verify-js/) instead — zero MCP dependency, zero subprocess, pure WASM.

## Design rules

- Treeship errors **never** fail the underlying tool call
- Only hashes are stored, **never** raw content
- Intent attestation is **awaited** (proof of what was about to happen)
- Receipt attestation is **fire-and-forget** (never blocks response)
- Session events are **best-effort** (no active session = silent no-op)
- `TREESHIP_DISABLE=1` produces **zero** overhead
- Verification helpers are **graceful** -- a runtime without WASM support will surface a clear error rather than crashing the MCP client

## License

Apache-2.0
