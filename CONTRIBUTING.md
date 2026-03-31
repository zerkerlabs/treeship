# Contributing to Treeship

Thank you for your interest in contributing to Treeship.

## Getting started

```bash
git clone https://github.com/zerkerlabs/treeship
cd treeship
cargo build
cargo test -p treeship-core
```

## Development setup

- Rust 1.75+ for core and CLI
- Go 1.22+ for Hub server
- Node.js 20+ for SDK, MCP bridge, and docs
- Python 3.9+ for Python SDK

## Project structure

```
packages/core/       Rust core library (attestation, merkle, rules)
packages/cli/        Rust CLI binary
packages/hub/        Go HTTP server (Hub API)
packages/sdk-ts/     TypeScript SDK (@treeship/sdk)
packages/sdk-python/ Python SDK (treeship-sdk)
packages/core-wasm/  WASM build for browser verification
bridges/mcp/         MCP bridge (@treeship/mcp)
docs/                Fumadocs documentation site
npm/                 npm binary wrapper packages
```

## How to contribute

1. Fork the repository
2. Create a branch: `git checkout -b fix/your-fix`
3. Make your changes
4. Run tests: `cargo test -p treeship-core`
5. Commit with a clear message
6. Open a pull request

## Commit messages

Use clear, descriptive messages. Examples:
- `Fix chain verification for odd-length chains`
- `Add treeship attest endorsement CLI command`
- `Update quickstart docs for new init flow`

## Code style

- Rust: follow `cargo fmt` and `cargo clippy`
- TypeScript: standard ES modules
- Go: follow `go fmt`
- Docs: no em dashes, direct language, real CLI examples

## Reporting bugs

Open an issue at https://github.com/zerkerlabs/treeship/issues with:
- What you expected
- What happened
- Steps to reproduce
- `treeship version` output

## Security vulnerabilities

See SECURITY.md for responsible disclosure.

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
