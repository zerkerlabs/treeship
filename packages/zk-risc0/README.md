# treeship-zk-risc0

RISC Zero guest program for chain-level zero-knowledge proofs of Treeship attestation chains.

## What it does

While the Circom circuits prove properties of individual attestations, treeship-zk-risc0 proves properties of entire artifact chains:

- A **guest program** runs inside the RISC Zero zkVM
- It walks an attestation chain, verifying each envelope's signature and hash linkage
- The resulting proof shows the full chain is valid without revealing intermediate artifacts

This is useful for auditing multi-step build pipelines where each stage produces its own attestation.

## Requirements

- [rzup](https://dev.risczero.com/api/zkvm/install) toolchain (installs the RISC Zero SDK and guest compiler)
- Rust nightly (required by the zkVM guest target)

## Building

```sh
rzup install
cargo build -p treeship-zk-risc0
```

## Usage

```sh
treeship prove --engine risc0 --chain ./chain.json
```

## Documentation

Full guide: [docs.treeship.dev](https://docs.treeship.dev)

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
