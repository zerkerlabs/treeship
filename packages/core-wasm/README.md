# treeship-core-wasm

WebAssembly build of treeship-core for browser-side attestation verification.

## What it does

treeship-core-wasm compiles the core cryptographic engine to WebAssembly so browsers can verify Treeship attestations without a server round-trip:

- **Ed25519 signature verification**
- **Merkle proof validation**
- **Groth16 zero-knowledge proof verification**

This package powers the verification widget at [treeship.dev/verify](https://treeship.dev/verify).

## Installation

```sh
npm install treeship-core-wasm
```

## Usage

```js
import init, { verify_envelope, verify_zk_proof } from "treeship-core-wasm";

await init();

const result = verify_envelope(envelopeBytes);
console.log(result.valid); // true | false
```

## Building from source

Requires [wasm-pack](https://rustwasm.github.io/wasm-pack/):

```sh
wasm-pack build packages/core-wasm --target web
```

## Documentation

Full API reference: [docs.treeship.dev](https://docs.treeship.dev)

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
