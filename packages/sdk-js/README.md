# @treeship/sdk

Treeship JavaScript/TypeScript SDK — cryptographic verification for AI agents.

## Installation

```bash
npm install @treeship/sdk
```

## Quick Start

```typescript
import { TreshipClient } from '@treeship/sdk';

const client = new TreshipClient();

const result = await client.attest({
  action: 'Document processed',
  inputs: { doc_id: '123', user: 'alice' }  // hashed locally
});

console.log(result.url);  // https://treeship.dev/verify/ts_abc123
```

## API

### TreshipClient

```typescript
const client = new TreshipClient({
  apiKey: 'your_key',        // or TREESHIP_API_KEY env
  apiUrl: 'https://...',     // optional, for self-hosted
  agent: 'my-agent',         // default agent slug
  timeout: 10000,            // request timeout in ms
});
```

### attest()

Create an attestation.

```typescript
const result = await client.attest({
  action: 'User request processed',  // required
  inputs: { user_id: 'u123' },        // optional, hashed locally
  agent: 'custom-agent',              // optional, overrides default
  metadata: { version: '1.0' },       // optional
});

if (result.attested) {
  console.log(`Verified: ${result.url}`);
} else {
  console.log(`Failed: ${result.error}`);
}
```

### verify()

Verify an attestation.

```typescript
const result = await client.verify('ts_abc123');

if (result.valid) {
  console.log('Signature valid!');
  console.log(`Agent: ${result.attestation.agent_slug}`);
} else {
  console.log(`Invalid: ${result.error}`);
}
```

## Privacy

Inputs are hashed locally with SHA-256. Raw content never leaves your server.

## Environment Variables

```bash
export TREESHIP_API_KEY="your_key"
export TREESHIP_AGENT="my-agent"
```

## License

MIT
