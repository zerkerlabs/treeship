# treeship-zk-circom

Circom circuits and Groth16 proving infrastructure for Treeship attestations.

## What it does

This package contains three Circom circuits that generate zero-knowledge proofs over attestation data:

| Circuit | Purpose |
|---------|---------|
| `policy-checker` | Proves an attestation satisfies a policy without revealing the full statement |
| `input-output-binding` | Proves input/output artifact hashes are correctly linked |
| `prompt-template` | Proves a prompt matches a registered template without exposing the prompt |

All circuits use **Groth16** proofs.

**Quarantined.** This path's proving keys, under `zkeys/`, were generated
locally with no real multi-party ceremony -- there is no `setup/` directory
of ceremony contributions, because no ceremony took place. That makes the
circuits forgeable by construction, and `treeship prove`/`verify-proof` fail
closed rather than trust them. See
[the ZK verification spec](https://github.com/zerkerlabs/treeship/blob/main/docs/specs/private-verification.md)
for the rebuild. The circuits here are retained as design references, not as
a sound proving path.

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

[github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
