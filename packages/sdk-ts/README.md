# @treeship/sdk

TypeScript SDK for [Treeship](https://treeship.dev) -- portable trust receipts for agent workflows.

## Install

```bash
npm install @treeship/sdk
```

Requires the `treeship` CLI binary in PATH. Install it with:

```bash
curl -fsSL treeship.dev/install | sh
```

## Usage

```typescript
import { ship } from '@treeship/sdk'

const s = ship()

// Attest an action
const { artifactId } = await s.attest.action({
  actor: 'agent://my-agent',
  action: 'tool.call',
})

// Attest a decision (LLM reasoning)
await s.attest.decision({
  actor: 'agent://analyst',
  model: 'claude-opus-4',
  tokensIn: 8432,
  tokensOut: 1247,
  summary: 'Contract looks standard.',
  confidence: 0.91,
})

// Attest an approval
const { artifactId: approvalId, nonce } = await s.attest.approval({
  approver: 'human://alice',
  description: 'approve payment max $500',
})

// Attest a handoff
await s.attest.handoff({
  from: 'agent://researcher',
  to: 'agent://executor',
  artifacts: ['art_abc123'],
})

// Verify
const result = await s.verify.verify('art_abc123')
// { outcome: 'pass', chain: 3, target: 'art_abc123' }

// Push to Hub
const { hubUrl } = await s.dock.push('art_abc123')
// https://treeship.dev/verify/art_abc123
```

## API

### `ship()`

Returns a `Ship` instance with three modules:

### `ship.attest`

| Method | Params | Returns |
|--------|--------|---------|
| `action(params)` | `{ actor, action, parentId?, approvalNonce?, meta? }` | `{ artifactId }` |
| `approval(params)` | `{ approver, description, expiresIn? }` | `{ artifactId, nonce }` |
| `handoff(params)` | `{ from, to, artifacts, approvals?, obligations? }` | `{ artifactId }` |
| `decision(params)` | `{ actor, model?, tokensIn?, tokensOut?, summary?, confidence? }` | `{ artifactId }` |

### `ship.verify`

| Method | Params | Returns |
|--------|--------|---------|
| `verify(id)` | artifact ID string | `{ outcome, chain, target }` |

### `ship.dock`

| Method | Params | Returns |
|--------|--------|---------|
| `push(id)` | artifact ID string | `{ hubUrl, rekorIndex? }` |
| `pull(id)` | artifact ID string | `void` |
| `status()` | none | `{ docked, endpoint?, dockId? }` |

## How it works

The SDK shells out to the `treeship` CLI binary via `child_process.execFile`. All signing happens in the Rust binary. The SDK is a thin TypeScript wrapper that makes the CLI ergonomic from code.

A future version will embed the WASM verifier for in-process signing without the subprocess.

## License

Apache-2.0
