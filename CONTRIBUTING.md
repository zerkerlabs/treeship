# Contributing to Treeship

Thank you for your interest in contributing to Treeship.

## Getting started

```bash
git clone https://github.com/zerkerlabs/treeship
cd treeship
cargo build --bin treeship
cargo test -p treeship-core
```

If `cargo build` succeeds and `cargo test -p treeship-core` reports `177 passed`, your environment is good.

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
tests/cross-sdk/     Cross-language SDK contract suite
```

## Running tests

The test suites you should run depend on what you touched:

| If you changed... | Run |
|---|---|
| `packages/core/` (anything) | `cargo test -p treeship-core` |
| `packages/cli/` | `cargo build --bin treeship && cargo test -p treeship-core` |
| `packages/hub/` | `cd packages/hub && go test ./...` |
| `packages/sdk-ts/` | `cd packages/sdk-ts && npm install && npm run build && npm test` |
| `packages/sdk-python/` | `cd packages/sdk-python && python3 -m pip install -e . && python3 -c "import treeship_sdk"` |
| Anything that affects the CLI verify path, the receipt format, or either SDK | `./tests/cross-sdk/run.sh` -- this is the contract test the matrix in CI runs |

`./tests/cross-sdk/run.sh` builds an isolated keystore, generates signed artifacts, runs the TS and Python SDKs against the same corpus, and fails if their `(outcome, chain)` outputs disagree on any vector. CI runs it across `{ubuntu, macos} × {Node 20, 22} × {Python 3.11, 3.12}`. If you broke the SDK contract, this is where it'll show up.

## How to contribute

1. Fork the repository
2. Create a branch: `git checkout -b fix/your-fix`
3. Make your changes
4. Run the relevant test suites from the table above
5. Commit with a clear message (see below)
6. Open a pull request -- the PR template will prompt you for what changed and how you tested it

## Commit messages

Use clear, descriptive messages, ideally with a conventional-commits-style prefix:

- `fix(graph): tool_calls counter must include AgentReadFile`
- `feat(keys): graceful rotation primitive`
- `perf(event_log): O(1) append via counter sidecar`
- `docs(readme): add 30-second demo`
- `test(cross-sdk): add valid.handoff vector`

The body should explain WHY (motivation, previous behavior, evidence) more than WHAT (the diff already shows that).

## Code style

- Rust: `cargo fmt && cargo clippy --all-targets` -- both must be clean
- TypeScript: standard ES modules; no compiler warnings
- Go: `go fmt`
- Docs and code comments: no em dashes, direct language, real CLI examples (not invented flags)

## Good first contributions

- Add a doc example to a package README that's currently sparse
- Add a vector to `tests/cross-sdk/gen-vectors.sh` for a statement type we don't yet cover (handoff, endorsement, receipt)
- Improve a CLI error message (grep for `eprintln!` in `packages/cli/src/commands/`)
- Document an undocumented public function (run `cargo doc --no-deps --open` to see what's missing)

## Reporting bugs

Use the bug-report issue template at <https://github.com/zerkerlabs/treeship/issues/new/choose>. The template lists what we need to reproduce; please fill it in.

## Security vulnerabilities

See [SECURITY.md](SECURITY.md). Do not file public issues for security bugs -- use the GitHub private advisory link or email `security@treeship.dev`.

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
