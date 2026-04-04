# treeship-core

Cryptographic engine powering the Treeship supply-chain attestation system.

## What it does

treeship-core provides the foundational cryptographic primitives used across the Treeship stack:

- **Ed25519 signing and verification** for artifact attestations
- **DSSE (Dead Simple Signing Envelope)** encoding and decoding
- **Merkle tree** construction and proof generation
- **Statement types** for in-toto and Treeship-native attestation formats

This crate is used directly by the Treeship CLI and compiled to WebAssembly for browser-side verification.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
treeship-core = "0.1"
```

Or install from source:

```sh
cargo build -p treeship-core
```

## Usage

```rust
use treeship_core::crypto::Ed25519Signer;
use treeship_core::dsse::Envelope;

let signer = Ed25519Signer::generate();
let envelope = Envelope::sign(payload, &signer)?;
```

## Documentation

Full API reference and guides: [docs.treeship.dev](https://docs.treeship.dev)

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
