# Treeship

**Open source cryptographic verification for AI agents.**

[![npm version](https://img.shields.io/npm/v/@treeship/cli.svg)](https://www.npmjs.com/package/@treeship/cli)
[![PyPI version](https://img.shields.io/pypi/v/treeship-sdk.svg)](https://pypi.org/project/treeship-sdk/)
[![Docker Pulls](https://img.shields.io/docker/pulls/zerker/treeship-sidecar.svg)](https://hub.docker.com/r/zerker/treeship-sidecar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Treeship proves what your AI agent did — cryptographically, without exposing any content.

This is not monitoring. Monitoring tells you what happened from inside the system.
Treeship proves what happened to **anyone outside the system** — including enterprise
compliance teams, regulators, and clients who have no reason to trust the builder.

## Quick Start

```bash
# 1. Install
npm install -g @treeship/cli

# 2. Get a free API key (30 seconds)
treeship init

# 3. Attest your first action
treeship attest --action "My agent processed a request"
# → https://treeship.dev/verify/ts_abc123

# 4. Anyone can verify — no account needed
treeship verify ts_abc123
# ✓ Signature valid. Signed by Treeship at 2026-02-22T14:23:01Z
```

That's it. Your agent now has a permanent, tamper-proof audit trail.

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

### CLI

```bash
npm install -g @treeship/cli
```

### Python SDK

```bash
pip install treeship-sdk
```

```python
from treeship import TreshipClient

client = TreshipClient()  # reads TREESHIP_API_KEY from env

result = client.attest(
    action="User document summarized",
    inputs={"user_id": "u123", "doc": "contract.pdf"}  # hashed, never sent
)
print(result.url)  # https://treeship.dev/verify/ts_abc123
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
| [Nanobot HKUDS](integrations/nanobot-hkuds/) | Python skill | ✅ Ready |
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

We're honest about this. See [Technical Feasibility](docs/technical-feasibility.md).

## Documentation

- [Getting Started](docs/getting-started.md)
- [Protocol Specification](protocol/SPEC.md)
- [Privacy Model](docs/privacy.md)
- [Self-Hosting Guide](docs/self-hosting.md)
- [API Reference](docs/api-reference.md)

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| [@treeship/cli](packages/cli/) | Command-line interface | `npm i -g @treeship/cli` |
| [treeship-sdk](packages/sdk-python/) | Python SDK | `pip install treeship-sdk` |
| [@treeship/sdk](packages/sdk-js/) | JavaScript/TypeScript SDK | `npm i @treeship/sdk` |
| [treeship-sidecar](packages/sidecar/) | Docker sidecar | `docker pull zerker/treeship-sidecar` |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE)

---

**Managed hosting with higher limits?** → [treeship.dev](https://treeship.dev)
