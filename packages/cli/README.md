# @treeship/cli

Treeship CLI — cryptographic verification for AI agents from the command line.

## Installation

```bash
npm install -g @treeship/cli
```

## Quick Start

```bash
# 1. Configure (get free API key at treeship.dev)
treeship init

# 2. Create attestation
treeship attest --action "Document processed"

# 3. Verify any attestation
treeship verify ts_abc123
```

## Commands

### treeship init

Configure your API key and default agent.

```bash
treeship init
```

Configuration is saved to `~/.config/treeship/config.json`.

### treeship attest

Create a new attestation.

```bash
# Basic usage
treeship attest --action "User request processed"

# With inputs (hashed locally, never sent)
treeship attest --action "Document summarized" --inputs '{"doc_id": "123"}'

# Custom agent
treeship attest --action "Task completed" --agent my-custom-agent

# JSON output
treeship attest --action "Done" --json
```

Options:
- `-a, --action <action>` — Action description (required)
- `-g, --agent <agent>` — Agent slug (default: from config)
- `-i, --inputs <json>` — Inputs as JSON (hashed locally)
- `--inputs-hash <hash>` — Pre-computed SHA-256 hash
- `-j, --json` — Output as JSON

### treeship verify

Verify an attestation. Works without authentication.

```bash
# Verify by ID
treeship verify ts_abc123

# JSON output
treeship verify ts_abc123 --json
```

The CLI verifies the Ed25519 signature locally and checks that the signing key matches Treeship's production key.

### treeship pubkey

Get Treeship's public key for manual verification.

```bash
treeship pubkey

# JSON output
treeship pubkey --json
```

### treeship agent

View an agent's attestation feed.

```bash
# View recent attestations
treeship agent my-agent

# Limit results
treeship agent my-agent --limit 5

# JSON output
treeship agent my-agent --json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TREESHIP_API_KEY` | API key (overrides config file) |
| `TREESHIP_API_URL` | API URL (default: https://api.treeship.dev) |

## Exit Codes

- `0` — Success
- `1` — Error (invalid attestation, API error, etc.)

## License

MIT
