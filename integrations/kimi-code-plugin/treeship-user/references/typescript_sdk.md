# Treeship TypeScript SDK Reference

## Installation

```bash
npm install @treeship/sdk
```

Requires the `treeship` CLI binary on PATH, initialized once with
`treeship init`. The SDK shells out to that binary for every call; it does
not talk to any API directly.

## Getting an instance

There is no `Treeship` class. Get an instance with the `ship()` factory:

```typescript
import { ship } from "@treeship/sdk";

const s = ship();
```

`s` exposes four modules: `attest`, `verify`, `hub`, `session`. There are no
top-level `attestAction`/`dockPush` methods -- always go through a module
(`s.attest.action(...)`, `s.hub.push(...)`).

### `s.attest.action(params): Promise<ActionResult>`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `actor` | `string` | Yes | Actor URI, e.g. `"agent://my-agent"` |
| `action` | `string` | Yes | Label for the action |
| `parentId` | `string` | No | Parent artifact ID for chain linking |
| `approvalNonce` | `string` | No | Nonce from an existing approval |
| `meta` | `Record<string, unknown>` | No | Arbitrary metadata |

```typescript
const result = await s.attest.action({
    actor: "agent://coder",
    action: "tool.call",
    parentId: "art_abc123",
    meta: { tool: "read_file", path: "src/main.rs" },
});
console.log(result.artifactId);  // art_...
```

### `s.attest.approval(params): Promise<ApprovalResult>`

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `approver` | `string` | Yes | Approver URI |
| `description` | `string` | Yes | What is being approved |
| `expires` | `string` | No | RFC 3339 expiry timestamp -- **not** `expiresIn`/seconds |
| `subject` | `string` | No | URI this approval covers |

This module does not yet accept a scope (`allowedActions`/`allowedActors`/
`allowedSubjects`/`maxUses`); use the Python SDK or `treeship attest approval`
directly when the CLI you're driving requires one (it does by default).

```typescript
const approval = await s.attest.approval({
    approver: "human://alice",
    description: "approve deployment to production",
    expires: "2027-01-01T00:00:00Z",
});
console.log(approval.nonce);
```

### `s.attest.handoff(params): Promise<ActionResult>`

`{ from, to, artifacts, approvals? }`.

### `s.verify.verify(artifactId): Promise<VerifyResult>`

```typescript
const result = await s.verify.verify("art_abc123");
console.log(result.outcome);  // "pass" | "fail" | "error"
console.log(result.chain);    // chain length
```

`s.verify` also exports `verifyReceipt`, `verifyCertificate`, `crossVerify`,
`verifyResolution` and `verifyPresentation` -- see `packages/sdk-ts/src/verify.ts`.

### `s.hub.push(artifactId): Promise<PushResult>`

There is no `dockPush` -- the module is `hub`, the method is `push`.

```typescript
const push = await s.hub.push("art_abc123");
console.log(push.hubUrl);  // https://treeship.dev/verify/art_...
```

`s.hub` also has `pull(id)` and `status()` (returns `{ connected, endpoint?, hubId? }`).

### `s.session.event(params): Promise<SessionEventResult>`

Appends a structured event to the active session's timeline (mirrors
`treeship session event`). See `packages/sdk-ts/src/session.ts`.

## Result types

```typescript
interface ActionResult { artifactId: string }
interface ApprovalResult { artifactId: string; nonce: string }
interface VerifyResult { outcome: "pass" | "fail" | "error"; chain: number; target: string }
interface PushResult { hubUrl: string; rekorIndex?: number }
```

## Error handling

All methods throw `TreeshipError` (exported from `@treeship/sdk`, extends
`Error`) on CLI failure.

```typescript
import { ship, TreeshipError } from "@treeship/sdk";

try {
    const result = await ship().attest.action({ actor: "agent://test", action: "test" });
} catch (e) {
    if (e instanceof TreeshipError) {
        console.error(`Attestation failed: ${e.message}`);
    }
}
```
