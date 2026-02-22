# treeship-cli

Treeship CLI — cryptographic verification for AI agents from the command line.

## Installation

```bash
npm install -g treeship-cli
```

## Quick Start

```bash
# Configure (get API key at treeship.dev)
export TREESHIP_API_KEY="your_key"
export TREESHIP_AGENT="my-agent"

# Create attestation
treeship attest --action "Document processed" --inputs-hash abc123

# Verify any attestation (no auth needed)
treeship verify abc123-def456
```

## Commands

### treeship attest

Create a new attestation.

```bash
# Basic usage
treeship attest --action "User request processed" --inputs-hash abc123

# Custom agent
treeship attest --action "Task completed" --agent my-custom-agent --inputs-hash abc123

# JSON output
treeship attest --action "Done" --inputs-hash abc123 --json

# Quiet mode (URL only)
treeship attest --action "Done" --inputs-hash abc123 --quiet
```

Options:
- `--action <text>` — Action description (required)
- `--inputs-hash <hash>` — SHA256 hash of inputs (required)
- `--agent <slug>` — Agent slug (default: from env)
- `--json` — Output as JSON
- `--quiet` — Output only the verification URL

### treeship verify

Verify an attestation. Works without authentication.

```bash
treeship verify abc123-def456
```

Output:
```
✓ Attestation abc123-def456
  Agent:     my-agent
  Action:    Document processed
  Timestamp: 2026-02-22T14:23:01Z
  Signature: valid (Ed25519)
```

### treeship whoami

Check your configuration.

```bash
treeship whoami
```

### treeship config

View or set configuration.

```bash
# View current config
treeship config

# Set values
treeship config --agent my-agent
treeship config --api-key ts_live_xxx
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TREESHIP_API_KEY` | API key (required) |
| `TREESHIP_AGENT` | Default agent slug |
| `TREESHIP_API_URL` | API URL (default: https://api.treeship.dev) |

## Generating Input Hashes

The CLI requires pre-computed hashes. Generate them with:

```bash
# Using sha256sum
echo -n '{"user":"id-123","doc":"contract.pdf"}' | sha256sum | awk '{print $1}'

# Using openssl
echo -n '{"user":"id-123"}' | openssl dgst -sha256 | awk '{print $2}'

# Using Python
python -c "import hashlib,json; print(hashlib.sha256(json.dumps({'user':'id-123'}, sort_keys=True).encode()).hexdigest())"
```

## CI/CD Usage

```bash
# In a CI pipeline
HASH=$(echo -n "${DEPLOYMENT_INFO}" | sha256sum | awk '{print $1}')
URL=$(treeship attest --action "Deployed v${VERSION}" --inputs-hash $HASH --quiet)
echo "Verification: $URL"
```

## License

MIT
