# @treeship/verify

Zero-dependency cryptographic verification for [Treeship](https://treeship.dev) Session Receipts and Agent Certificates. Runs anywhere WebAssembly and `fetch` are available.

## Install

```bash
npm install @treeship/verify
```

The only dependency is `@treeship/core-wasm` (the compiled Rust core, under 170 KB gzipped). No transitive dependency on `@treeship/sdk`, so you can ship this to an edge worker, browser dashboard, or audit tool without pulling the subprocess code path in at all.

## API

Three functions. Each accepts a parsed object, a JSON string, or a URL.

### `verifyReceipt(target)`

Runs the JSON-level checks a Treeship Session Receipt carries: Merkle root recomputation, inclusion proof verification, leaf-count parity, timeline ordering, chain linkage.

```typescript
import { verifyReceipt } from '@treeship/verify';

const result = await verifyReceipt('https://treeship.dev/receipt/ssn_abc');

if (result.outcome === 'pass') {
  console.log(`session ${result.session.id} verified`);
} else {
  console.log(`verification failed:`, result.checks.filter(c => c.status === 'fail'));
}
```

### `verifyCertificate(target, now?)`

Verifies the Ed25519 signature on an Agent Certificate against the public key embedded in the certificate. With `now` supplied (Date or RFC 3339 string), also classifies the validity window.

```typescript
import { verifyCertificate } from '@treeship/verify';

const result = await verifyCertificate('./researcher.agent/certificate.json', new Date());

if (result.outcome === 'pass' && result.validity === 'valid') {
  console.log(`certificate valid for ${result.certificate.agent_name}`);
}
```

### `crossVerify(receipt, certificate, now?)`

Answers three questions: do the receipt and certificate reference the same ship, was the certificate valid at `now`, was every tool the session called authorized by the certificate. The `ok` field is the roll-up.

```typescript
import { crossVerify } from '@treeship/verify';

const result = await crossVerify(
  'https://treeship.dev/receipt/ssn_abc',
  'https://example.com/researcher.agent.json',
);

if (result.ok) {
  console.log('complete trust loop verified');
} else {
  console.log('ship_id_status:', result.ship_id_status);
  console.log('unauthorized:', result.unauthorized_tool_calls);
}
```

## Runtime compatibility

| Runtime | Supported |
|---------|-----------|
| Node.js 18+ | yes |
| Node.js 20+ | yes |
| Deno | yes |
| Browser (bundler) | yes |
| Vercel Edge | yes |
| Cloudflare Workers | yes |
| AWS Lambda (Node) | yes |

The package ships `@treeship/core-wasm` with `--target bundler`. Runtimes that need a different WASM wrapper (plain Node without a bundler) can still consume the core via the subprocess-backed `@treeship/sdk`.

## Examples

### Vercel Edge Function

```typescript
import { verifyReceipt } from '@treeship/verify';

export const config = { runtime: 'edge' };

export default async function handler(req: Request) {
  const { url } = await req.json();
  const result = await verifyReceipt(url);
  return Response.json(result);
}
```

### Cloudflare Worker

```typescript
import { verifyReceipt } from '@treeship/verify';

export default {
  async fetch(request: Request): Promise<Response> {
    const { url } = await request.json();
    const result = await verifyReceipt(url);
    return Response.json(result);
  },
};
```

### AWS Lambda (Node runtime)

```typescript
import { verifyReceipt } from '@treeship/verify';

export const handler = async (event: { body: string }) => {
  const { url } = JSON.parse(event.body);
  const result = await verifyReceipt(url);
  return { statusCode: 200, body: JSON.stringify(result) };
};
```

### Browser dashboard

```typescript
import { verifyReceipt } from '@treeship/verify';

const file = await fileInput.files[0];
const text = await file.text();
const result = await verifyReceipt(text);

renderChecks(result.checks);
```

## What this package is NOT

- **Not an attestation SDK.** For signing artifacts, session management, Hub push/pull, or agent registration, use [`@treeship/sdk`](../sdk-ts/) which shells out to the `treeship` CLI.
- **Not a trust anchor.** The embedded Ed25519 signature on an Agent Certificate is verified against the certificate's own public key. Chaining a certificate to a trusted issuer is the caller's responsibility.
- **Not a drop-in for local-chain verification.** Some signature verification needs the original envelope bytes, which a URL-fetched receipt does not carry. Use `treeship verify <artifact-id>` on the CLI for that.

## License

Apache-2.0
