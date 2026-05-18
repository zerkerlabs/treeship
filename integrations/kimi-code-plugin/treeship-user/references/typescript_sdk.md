# Treeship TypeScript SDK Reference

## Installation

```bash
npm install @treeship/sdk
```

Requires Node.js 18+ and the `treeship` CLI binary in PATH, initialized with `treeship init`.

## Treeship Class

```typescript
import { Treeship } from '@treeship/sdk';

const ts = new Treeship();
```

### Methods

#### `attestAction(params)`

Create a signed action receipt.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `actor` | `string` | Yes | Actor URI, e.g. `"agent://my-agent"` |
| `action` | `string` | Yes | Label for the action |
| `parentId` | `string` | No | Parent artifact ID for chain linking |
| `approvalNonce` | `string` | No | Nonce from an existing approval |
| `meta` | `Record<string, unknown>` | No | Arbitrary metadata |

**Returns:** `Promise<ActionResult>`

```typescript
const result = await ts.attestAction({
    actor: 'agent://coder',
    action: 'tool.call',
    parentId: 'art_abc123',
    meta: { tool: 'read_file', path: 'src/main.rs' }
});
console.log(result.artifactId);  // art_...
```

#### `attestApproval(params)`

Create a signed approval receipt with a single-use nonce.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `approver` | `string` | Yes | Approver URI |
| `description` | `string` | Yes | What is being approved |
| `expiresIn` | `number` | No | Expiry in seconds |

**Returns:** `Promise<ApprovalResult>`

```typescript
const approval = await ts.attestApproval({
    approver: 'human://alice',
    description: 'approve deployment to production',
    expiresIn: 3600
});
console.log(approval.nonce);  // Single-use nonce
```

#### `verify(artifactId)`

Verify an artifact and walk its chain.

**Returns:** `Promise<VerifyResult>`

```typescript
const result = await ts.verify('art_abc123');
console.log(result.outcome);  // "pass", "fail", or "error"
console.log(result.chain);    // chain length
```

#### `dockPush(artifactId)`

Push an artifact to the configured hub.

**Returns:** `Promise<PushResult>`

```typescript
const push = await ts.dockPush('art_abc123');
console.log(push.hubUrl);  // https://treeship.dev/verify/art_...
```

### Result Types

```typescript
interface ActionResult {
    artifactId: string;
}

interface ApprovalResult {
    artifactId: string;
    nonce: string;
}

interface VerifyResult {
    outcome: 'pass' | 'fail' | 'error';
    chain: number;
    target: string;
}

interface PushResult {
    hubUrl: string;
    rekorIndex?: number;
}
```

### Error Handling

All methods throw `TreeshipError` (extends `Error`) on CLI failure.

```typescript
try {
    const result = await ts.attestAction({ actor: 'agent://test', action: 'test' });
} catch (e) {
    if (e instanceof TreeshipError) {
        console.error(`Attestation failed: ${e.message}`);
    }
}
```
