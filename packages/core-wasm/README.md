# treeship-core-wasm

WebAssembly build of treeship-core for browser-side attestation verification.

## What it does

treeship-core-wasm compiles the core cryptographic engine to WebAssembly so browsers can verify Treeship attestations without a server round-trip:

- **Ed25519 signature verification**
- **Merkle proof validation**

Groth16 zero-knowledge proof verification exists in the crate behind the
non-default `zk` feature, but that path is quarantined (see
[the ZK verification spec](https://github.com/zerkerlabs/treeship/blob/main/docs/specs/private-verification.md))
and the published `@treeship/core-wasm` package is built without it -- the
browser never checks a ZK proof today.

This package powers the verification widget at [treeship.dev/verify](https://treeship.dev/verify), which verifies signatures and Merkle proofs only.

## Installation

The published package is `@treeship/core-wasm` -- there is no `treeship-core-wasm` package on npm.

```sh
npm install @treeship/core-wasm
```

## Usage

Every export takes and returns JSON *strings* (not typed objects, and not raw
bytes), and there is no `init()` to await -- neither the bundler nor the
Node.js build has one.

```js
import { verify_envelope } from "@treeship/core-wasm";

const result = JSON.parse(verify_envelope(envelopeJson, trustedKeysJson));
console.log(result.valid); // true | false
```

## Building from source

Requires [wasm-pack](https://rustwasm.github.io/wasm-pack/). The published
package bundles two builds from one `wasm-pack` invocation each -- a bundler
target for the browser/webpack consumer and a separate Node.js (CommonJS)
target, not a single `--target web` build:

```sh
wasm-pack build packages/core-wasm --target bundler --out-dir pkg --release
wasm-pack build packages/core-wasm --target nodejs --out-dir pkg/node --release
```

`build-npm.sh` in this directory does both and assembles the published
package.json; that's the script the release workflow actually runs.

## Documentation

Full API reference: [docs.treeship.dev](https://docs.treeship.dev)

## Repository

[github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
