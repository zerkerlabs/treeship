# Getting Started with Treeship

This guide will have you creating verified attestations in under 5 minutes.

## What is Treeship?

Treeship creates cryptographic proofs of what your AI agent did. These proofs are:

- **Tamper-proof** — Ed25519 signatures that anyone can verify
- **Privacy-preserving** — Only hashes are stored, never raw content
- **Independently verifiable** — No trust in Treeship required

## Prerequisites

- Node.js 18+ (for CLI) or Python 3.10+ (for SDK)
- A free Treeship API key from [treeship.dev](https://treeship.dev)

## Option 1: CLI (Fastest)

```bash
# Install
npm install -g @treeship/cli

# Configure
treeship init
# Enter your API key when prompted

# Create your first attestation
treeship attest --action "My first verified action"
# → https://treeship.dev/verify/ts_abc123

# Verify it
treeship verify ts_abc123
# ✓ Signature valid
```

## Option 2: Python SDK

```bash
pip install treeship-sdk
```

```python
from treeship import TreshipClient

# Initialize (reads TREESHIP_API_KEY from env)
client = TreshipClient(agent="my-agent")

# Create attestation
result = client.attest(
    action="Document processed",
    inputs={"doc_id": "123", "user": "alice"}  # hashed locally
)

print(result.url)  # https://treeship.dev/verify/ts_abc123
```

## Option 3: Docker Sidecar

For production deployments, run Treeship as a sidecar:

```yaml
# docker-compose.yml
services:
  my-agent:
    image: your-agent:latest
    depends_on: [treeship-sidecar]

  treeship-sidecar:
    image: zerker/treeship-sidecar:latest
    environment:
      - TREESHIP_API_KEY=${TREESHIP_API_KEY}
      - TREESHIP_AGENT=my-agent
    ports: ["2019:2019"]
```

Your agent calls `http://treeship-sidecar:2019/attest`:

```bash
curl -X POST http://treeship-sidecar:2019/attest \
  -H "Content-Type: application/json" \
  -d '{"action": "Task completed", "inputs": {"task_id": "123"}}'
```

## What to Attest

Attest at these key points:

1. **Data reads** — Before making decisions based on external data
2. **Consequential decisions** — Approvals, rejections, recommendations
3. **External actions** — Emails, API calls, purchases
4. **Final outputs** — Summaries, reports, user-facing content

## Privacy Model

By default, Treeship never sees your content:

| Sent to Treeship | Stays Local |
|-----------------|-------------|
| Action description | Raw inputs |
| SHA-256 hash of inputs | Documents |
| Timestamp | User data |
| Agent identifier | API keys |

The hash proves inputs existed without revealing them.

## Verification

Anyone can verify attestations without an account:

```bash
# Via CLI
treeship verify ts_abc123

# Via API
curl https://api.treeship.dev/v1/verify/ts_abc123

# Via web
open https://treeship.dev/verify/ts_abc123
```

## Next Steps

- [Protocol Specification](../protocol/SPEC.md) — How it works under the hood
- [Privacy Model](privacy.md) — Detailed privacy guarantees
- [Self-Hosting Guide](self-hosting.md) — Run your own Treeship
- [Framework Integrations](../integrations/) — LangChain, OpenClaw, Nanobot
