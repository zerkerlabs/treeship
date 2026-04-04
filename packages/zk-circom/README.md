# treeship-zk-circom

Circom circuits and Groth16 proving infrastructure for Treeship attestations.

## What it does

This package contains three Circom circuits that generate zero-knowledge proofs over attestation data:

| Circuit | Purpose |
|---------|---------|
| `policy-checker` | Proves an attestation satisfies a policy without revealing the full statement |
| `input-output-binding` | Proves input/output artifact hashes are correctly linked |
| `prompt-template` | Proves a prompt matches a registered template without exposing the prompt |

All circuits use **Groth16** proofs. Trusted setup ceremony artifacts are included in `setup/`.

## Installation

This crate is feature-gated. Enable it in your `Cargo.toml`:

```toml
[dependencies]
treeship-zk-circom = { version = "0.1", features = ["zk"] }
```

Or build from the CLI:

```sh
cargo build -p treeship-zk-circom --features zk
```

## Requirements

- [circom](https://docs.circom.io/) 2.1+
- [snarkjs](https://github.com/iden3/snarkjs) (for local proof generation and verification)

## Documentation

Full guide: [docs.treeship.dev](https://docs.treeship.dev)

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
