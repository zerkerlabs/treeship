# @treeship/sdk

TypeScript SDK for [Treeship](https://treeship.dev) -- portable trust receipts for agent workflows.

## Install

```bash
npm install @treeship/sdk
```

Requires the `treeship` CLI binary in PATH. Install with:

```bash
# One-liner: installs CLI, runs treeship init, instruments any detected agents
curl -fsSL treeship.dev/setup | sh

# Or via npm
npm install -g treeship
```

macOS and Linux only at v0.9.4. Windows users: install via WSL.

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
const { hubUrl } = await s.hub.push('art_abc123')
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

| Method | Params | Returns | Runtime |
|--------|--------|---------|---------|
| `verify(id)` | artifact ID string | `{ outcome, chain, target }` | CLI subprocess (legacy) |
| `verifyReceipt(target)` | receipt JSON / URL / parsed object | `VerifyReceiptResult` | WASM |
| `verifyCertificate(target, now?)` | cert JSON / URL / parsed object + optional `Date \| string` | `VerifyCertificateResult` | WASM |
| `crossVerify(receipt, cert, now?)` | receipt + cert in any of the above forms | `CrossVerifyResult` | WASM |

### `ship.hub`

| Method | Params | Returns |
|--------|--------|---------|
| `push(id)` | artifact ID string | `{ hubUrl, rekorIndex? }` |
| `pull(id)` | artifact ID string | `void` |
| `status()` | none | `{ connected, endpoint?, hubId? }` |

## Runtime compatibility

Verification (`verifyReceipt`, `verifyCertificate`, `crossVerify`) is WASM-backed since v0.9.1 and runs anywhere WebAssembly + `fetch` are available:

| Runtime | Verify | Attest / Session / Hub |
|---------|--------|-----------------------|
| Node.js 18+ | yes | yes (needs `treeship` CLI in PATH) |
| Node.js 20+ | yes | yes |
| Deno | yes | no (use the WASM-only `@treeship/verify` package for read-only consumers) |
| Browser | yes | no |
| Vercel Edge | yes | no |
| Cloudflare Workers | yes | no |
| AWS Lambda (Node) | yes | no |

Stateful operations — `attest.*`, `session.*`, `hub.*`, and `agent register` — continue to shell out to the `treeship` CLI binary because they need filesystem access for key storage, the artifact chain, and the session log. These paths work only in runtimes that can spawn the CLI (Node with the binary on `PATH`, typically).

For read-only consumers (dashboards, Witness, third-party verifiers) that only need verification, depend on [`@treeship/verify`](../verify-js/) instead — zero SDK dependency, zero subprocess, pure WASM.

## How it works

Verification paths: the SDK lazily imports `@treeship/core-wasm` on the first `verifyReceipt` / `verifyCertificate` / `crossVerify` call, then reuses the cached bindings. Same Rust code the CLI runs, compiled to WASM.

Attestation and other stateful paths: the SDK shells out to the `treeship` CLI binary via `child_process.execFile`. All signing happens in the Rust binary. The SDK is a thin TypeScript wrapper that makes the CLI ergonomic from code.

## License

Apache-2.0
