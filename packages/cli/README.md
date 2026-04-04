# treeship-cli

Command-line interface for creating, verifying, and managing Treeship supply-chain attestations.

## Installation

**Recommended (via npm):**

```sh
npm install -g treeship
```

**From source (via Cargo):**

```sh
cargo install treeship-cli
```

## Commands

| Command | Description |
|---------|-------------|
| `treeship wrap` | Wrap an artifact with a signed attestation envelope |
| `treeship verify` | Verify an attestation envelope against its artifact |
| `treeship hub attach` | Attach a local attestation to Treeship Hub |
| `treeship prove` | Generate a zero-knowledge proof for a wrapped artifact |

Run `treeship --help` for the full list of options and subcommands.

## Quick start

```sh
# Wrap a build artifact
treeship wrap --artifact ./dist/bundle.js --out ./bundle.attestation.json

# Verify it
treeship verify --envelope ./bundle.attestation.json

# Attach to Hub
treeship hub attach --envelope ./bundle.attestation.json
```

## Documentation

CLI reference and walkthroughs: [docs.treeship.dev/cli/overview](https://docs.treeship.dev/cli/overview)

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
