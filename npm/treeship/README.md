# treeship

Portable trust receipts for agent workflows.

## Install

```bash
npm install -g treeship
# or
npx treeship init
```

This package downloads the prebuilt Treeship CLI binary for your platform. No Rust required.

## Usage

```bash
treeship init
treeship wrap -- npm test
treeship verify last --full
treeship dock push <artifact-id>
```

## What it does

Every action, approval, and handoff your agents make gets a cryptographically signed receipt. Verifiable by anyone, anywhere.

- **Signed receipts** with Ed25519 (output digest, file changes, git state)
- **Auto-chaining** between receipts
- **Human approvals** with nonce binding
- **Merkle checkpoints** for batch integrity
- **WASM verification** in the browser
- **Templates** for common workflows

## Documentation

https://docs.treeship.dev

## License

Apache-2.0
