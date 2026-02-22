# Treeship

**Open source cryptographic verification for AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/github/stars/zerkerlabs/treeship?style=social)](https://github.com/zerkerlabs/treeship)

Treeship proves what your AI agent did — cryptographically, without exposing any content.

This is not monitoring. Monitoring tells you what happened from inside the system.
Treeship proves what happened to **anyone outside the system** — including enterprise
compliance teams, regulators, and clients who have no reason to trust the builder.

## Quick Start (Python)

```python
# pip install treeship-sdk  # coming soon — for now, install from source
from treeship import TreshipClient

client = TreshipClient(api_key="your_key", agent="my-agent")

# Create an attestation (inputs are hashed locally, never sent)
result = client.attest(
    action="Document processed",
    inputs={"doc_id": "123", "user": "alice"}
)

print(result.url)  # https://treeship.dev/verify/ts_abc123
```

That's it. Your agent now has a permanent, tamper-proof audit trail.

> **Note:** Packages are coming soon to npm/PyPI. For now, install from source or use the [Docker sidecar](packages/sidecar/).

## How It Works

```
Your VPS
├── agent container    [OpenClaw / Nanobot / LangChain / any Docker]
│   └── calls http://treeship-sidecar:2019/attest
└── treeship sidecar   [zerker/treeship-sidecar:latest]
    ├── hashes inputs locally (content never leaves your server)
    ├── signs via Ed25519
    └── posts to api.treeship.dev → public verification URL
```

## Privacy by Default

| Sent to Treeship | Stays on your server |
|-----------------|---------------------|
| Action description | The actual content processed |
| SHA-256 hash of inputs | Raw user messages |
| Timestamp | Documents and files |
| Agent slug | AI model API keys |

Treeship never sees content. It sees proofs that content was processed.
**Healthcare, finance, and legal deployments supported.**

## Installation

### From Source (Current)

```bash
# Python SDK
git clone https://github.com/zerkerlabs/treeship.git
cd treeship/packages/sdk-python
pip install -e .

# CLI (requires Node.js 18+)
cd treeship/packages/cli
npm install && npm link
```

### From Package Managers (Coming Soon)

```bash
# CLI
npm install -g @treeship/cli

# Python SDK
pip install treeship-sdk
```

### Docker Sidecar

```yaml
# docker-compose.yml
services:
  agent:
    image: your-agent:latest
    depends_on: [treeship-sidecar]

  treeship-sidecar:
    image: zerker/treeship-sidecar:latest
    environment:
      - TREESHIP_API_KEY=${TREESHIP_API_KEY}
      - TREESHIP_AGENT=my-agent
    ports: ["2019:2019"]
```

Your agent calls `http://treeship-sidecar:2019/attest` — that's it.

## Framework Integrations

| Framework | Integration | Status |
|-----------|-------------|--------|
| [OpenClaw](integrations/openclaw/) | SKILL.md | ✅ Ready |
| [Nanobot.ai](integrations/nanobot-ai/) | MCP config | ✅ Ready |
| [LangChain](integrations/langchain/) | Callback handler | ✅ Ready |
| CrewAI | Agent tool | Planned |
| AutoGen | Message hook | Planned |

## Independent Verification

You don't have to trust Treeship. Verify any attestation yourself:

```bash
# Anyone can run this — no account, no API key
treeship verify ts_abc123

# Or manually:
# 1. Fetch the attestation
curl https://api.treeship.dev/v1/verify/ts_abc123

# 2. Fetch the public key
curl https://api.treeship.dev/v1/pubkey

# 3. Verify the Ed25519 signature locally
```

The [protocol specification](protocol/SPEC.md) documents exactly how verification works.

## Self-Hosting

Treeship can be fully self-hosted. See [docs/self-hosting.md](docs/self-hosting.md).

```bash
# Generate your own signing keys
treeship-api keygen

# Run the full stack
docker-compose -f self-hosted.yml up
```

If Zerker disappears, you can run everything yourself.

## What Treeship Proves (and Doesn't)

### ✅ Fully Provable

- **Memory state transitions** — State was X, became Y, at timestamp Z
- **Execution latency** — Action took N milliseconds (timestamp delta)
- **Data was processed** — Hash of inputs existed at decision time

### ⚠️ Partially Provable

- **Reasoning at decision time** — The reasoning text existed and is bound to the output. Does NOT prove the reasoning caused the output or is logically correct.

### ❌ Not Provable

- **Decision quality** — Was it the right decision? Requires external ground truth.
- **Content accuracy** — Treeship proves content was processed, not that it's correct.

We're honest about this.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Protocol Specification](protocol/SPEC.md)
- [Privacy Model](docs/privacy.md)
- [Self-Hosting Guide](docs/self-hosting.md)

## Packages

| Package | Description | Status |
|---------|-------------|--------|
| [@treeship/cli](packages/cli/) | Command-line interface | 🚧 Coming soon |
| [treeship-sdk](packages/sdk-python/) | Python SDK | 🚧 Coming soon |
| [@treeship/sdk](packages/sdk-js/) | JavaScript/TypeScript SDK | 🚧 Coming soon |
| [treeship-sidecar](packages/sidecar/) | Docker sidecar | 🚧 Coming soon |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE)

---

**Managed hosting with higher limits?** → [treeship.dev](https://treeship.dev)
