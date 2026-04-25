# treeship-cli

The Treeship CLI: cryptographically signed receipts for what AI agents do.

Wrap a command, attest an action, package a session, verify any of it offline. Local-first; the optional Hub adds shareability, never trust.

## Installation

```sh
# Quickest path: npm wrapper auto-downloads the platform binary
npm install -g treeship

# Direct binary install
curl -fsSL https://treeship.dev/install | sh

# From source (requires Rust 1.75+)
cargo install --git https://github.com/zerkerlabs/treeship --locked treeship-cli
```

After install, run `treeship init` once to generate a keypair and config in `~/.treeship/`.

## The 90-second loop

```sh
treeship init                           # one-time keystore setup
treeship session start --name "demo"    # begin recording
treeship wrap -- npm test               # any command, captured + signed
treeship session close                  # produce a .treeship package
treeship session report                 # publish; prints a verify URL
```

Every command has a manpage-style help: `treeship <command> --help`.

## Most-used commands

| Command | What it does |
|---|---|
| `treeship init` | Generate a keypair and config |
| `treeship session start [--name NAME]` | Begin recording a session |
| `treeship session close` | Finalize the active session into a `.treeship` package |
| `treeship session report` | Push the closed session to the configured Hub, get a public verify URL |
| `treeship wrap -- <cmd> [args...]` | Run a command and attest it inside the active session |
| `treeship attest action --actor <uri> --action <name>` | Sign a standalone action statement |
| `treeship attest approval --approver <uri> --description <text>` | Sign an approval (with auto-generated nonce) |
| `treeship attest decision --actor <uri> [--model <id>]` | Sign a decision attestation |
| `treeship attest handoff --from <uri> --to <uri>` | Sign a work handoff between actors |
| `treeship verify <ID-or-path-or-URL>` | Verify an artifact ID, a `.treeship` package, or a hub URL |
| `treeship package verify <PATH>` | Verify a `.treeship` package directory |
| `treeship hub attach [--name NAME]` | Connect to a Hub workspace via device flow |
| `treeship hub push <ARTIFACT_ID>` | Push an artifact to the active Hub connection |
| `treeship hub ls` | List configured Hub connections |
| `treeship keys list` | List signing keys (shows rotation status) |
| `treeship keys rotate [--grace-hours N]` | Mint a successor key and stamp the predecessor with a grace window |
| `treeship status` | Print ship state: keys, recent artifacts, hub status |
| `treeship doctor` | Self-diagnose common environment issues |

Full reference (every command, every flag): `treeship --help` or `https://docs.treeship.dev/cli/overview`.

## Output formats

Every command accepts `--format json` for machine-readable output. Pair with `--quiet` to suppress text noise on stderr:

```sh
treeship --format json --quiet attest action --actor agent://me --action "tool.call"
# → {"action":"tool.call","actor":"agent://me","id":"art_…","signed":"2026-…Z"}
```

## Pointing at a non-default keystore

The CLI honors `TREESHIP_CONFIG` as a fallback when `--config` isn't passed (introduced in v0.9.5). Useful for testing against an isolated keystore or for SDK callers that need to redirect every invocation:

```sh
export TREESHIP_CONFIG=/tmp/scratch/config.json
treeship init                           # creates the scratch keystore
treeship attest action --actor … …      # writes into the scratch dir
```

`--config <path>` always wins over the env var.

## Building from source

```sh
git clone https://github.com/zerkerlabs/treeship && cd treeship
cargo build --bin treeship
./target/debug/treeship --help
```

## Documentation

- CLI reference: <https://docs.treeship.dev/cli/overview>
- Concepts (trust model, receipts, Merkle, security): <https://docs.treeship.dev/concepts>
- Guides (quickstart, approvals, handoffs): <https://docs.treeship.dev/guides>

## Repository

[github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## License

Apache-2.0. See [LICENSE](https://github.com/zerkerlabs/treeship/blob/main/LICENSE).
