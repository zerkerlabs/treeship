# treeship

**Portable, cryptographically signed receipts for AI agent sessions.**

Treeship turns every AI agent session into a portable, signed receipt. Local-first. Cryptographically verifiable. Works offline. **The receipt is yours, not ours.**

## Install

```bash
npm install -g treeship
```

This package downloads the prebuilt Treeship CLI binary for your platform. No Rust required.

**Platform support:** macOS and Linux. Windows users: install via WSL (a native Windows binary is planned for v0.10.0). The package's `preinstall` script will exit with a clear message on Windows rather than yielding a broken install.

## Quick start

```bash
treeship init                       # one-time, per machine
treeship session start              # opens a recording session
treeship wrap -- npm test           # captures the command + exit code + file writes
treeship session close              # seals the receipt
treeship session report             # uploads + prints a shareable URL
treeship verify <url>               # anyone can verify, offline, no account
```

## Claude Code users

If you're using Claude Code, install the plugin instead — it auto-records every session via SessionStart / PostToolUse / SessionEnd hooks, no manual `session start` to remember:

```bash
claude plugin marketplace add zerkerlabs/treeship
claude plugin install treeship@treeship
```

## What gets captured

`@treeship/mcp` and the Claude Code plugin capture:

- Tool name (e.g. `read_file`, `bash`)
- SHA-256 digest of arguments — **not the raw arguments**
- SHA-256 digest of output content — **not the raw content**
- Exit code, duration, error message text on failures
- Actor URI (e.g. `agent://claude-code`)

What's **not** captured: raw argument values, raw output content, file contents, environment variable values, secrets. Full inventory at <https://github.com/zerkerlabs/treeship/blob/main/TREESHIP.md>.

## Where data lives

- Receipts stay in `.treeship/sessions/<id>.treeship` on your machine
- They leave only on explicit `treeship session report`, `treeship hub push`, or with `auto_push: true` configured
- Verification (`treeship package verify`) is pure WASM, runs entirely offline, doesn't phone home

## Documentation

- Full docs: <https://docs.treeship.dev>
- Trust model + complete capture inventory: <https://github.com/zerkerlabs/treeship/blob/main/TREESHIP.md>
- Source: <https://github.com/zerkerlabs/treeship>

## License

Apache-2.0
