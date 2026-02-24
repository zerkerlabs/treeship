<div align="center">

# Treeship

### Your AI agents need a permanent record.

[![npm](https://img.shields.io/npm/v/treeship-cli)](https://www.npmjs.com/package/treeship-cli)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[Documentation](https://docs.treeship.dev) · [Get API Key](https://treeship.dev) · [Verify](https://treeship.dev/verify) · [llms.txt](https://docs.treeship.dev/llms.txt)

</div>

---

## The Problem

Your AI agent approves loans, processes orders, makes decisions. But when a customer asks **"how do I know it actually analyzed my data?"** — what do you show them?

Logs can be modified. Screenshots can be faked. Trust isn't enough.

## The Solution

Treeship creates tamper-proof records of every action. Each gets a verification URL that anyone can check — without trusting you or Treeship.

```
Your Agent → Treeship → https://treeship.dev/verify/your-agent/abc123 → Anyone verifies
```

---

## Quick Start

### MCP Server (recommended for Claude Code, Cursor)

Add to your MCP config:

```json
{
  "mcpServers": {
    "treeship": {
      "command": "treeship-mcp",
      "env": {
        "TREESHIP_API_KEY": "ts_live_..."
      }
    }
  }
}
```

Your agent automatically discovers `treeship_attest` and `treeship_verify` tools.

### Python SDK

```bash
pip install treeship-sdk
```

```python
from treeship_sdk import Treeship

ts = Treeship()  # uses TREESHIP_API_KEY env var

result = ts.attest(
    agent="loan-processor",
    action="Approved application #12345",
    inputs_hash=ts.hash(application_data)
)

print(result.verify_url)
# → https://treeship.dev/verify/loan-processor/abc123
```

### CLI

```bash
npx treeship-cli attest \
  --agent my-agent \
  --action "Processed order #12345"

# → ✓ Attestation created
# → treeship.dev/verify/my-agent/a8f3b2c1
```

That's it. Your customer can verify at that URL.

---

## How It Works

1. **Your agent does something** — approves a loan, processes an order, whatever.
2. **You call `ts.attest()`** — pass the action description and a hash of the inputs.
3. **Treeship signs it** — creates a cryptographic signature with timestamp. Impossible to forge.
4. **Anyone verifies** — share the URL. Customers verify with one click.

No changes to your agent logic. No new infrastructure. One API call.

---

## Dashboard & Multi-Agent Workflows

The [Treeship dashboard](https://treeship.dev/dashboard) gives you:

- **Overview** — total agents, attestation counts, recent activity with ZK/human/tool badges
- **Multi-agent workflows** — link attestations into chains with `previous_attestation_id` and `workflow_id` for full audit trails across agent handoffs
- **Agent identity scores** — cryptographic keypair, domain verification, tool manifests, and code hash registration scored out of 100
- **Tool authorization** — whitelist which tools each agent can use

### Workflow chains

```python
# Step 1: First agent
step1 = ts.attest(
    agent="code-reviewer",
    action="Reviewed PR #891: 0 critical issues",
    workflow_id="deploy-v2.1.0",
    workflow_step=1
)

# Step 2: Second agent links to step 1
step2 = ts.attest(
    agent="deploy-agent",
    action="Deployed v2.1.0 to production",
    previous_attestation_id=step1.id,
    workflow_id="deploy-v2.1.0",
    workflow_step=2
)
```

Each step is cryptographically linked — tamper-proof audit trail for multi-agent operations.

---

## Why This Matters

We're betting that enterprise clients will start requiring a verification link before deploying AI agents. When that happens:

- **The URL becomes a requirement** — like SSL for websites
- **Your audit trail locks you in** — migrating means a gap regulators notice
- **Demand flows from clients to builders** — enterprises require it, builders add it
- **Open source builds trust** — security teams can audit the protocol

Once clients expect a `treeship.dev/verify/` link, that expectation becomes the standard.

---

## Privacy

| Sent to Treeship | Stays on your server |
|------------------|----------------------|
| Action description (you control) | Actual content |
| SHA-256 hash of inputs | Raw data, files, PII |
| Timestamp | Everything else |

You decide what's in the action description. Sensitive data never leaves your infrastructure — only a hash that proves it existed.

---

## Packages

| Package | Install |
|---------|---------|
| Python SDK | `pip install treeship-sdk` |
| CLI | `npm install -g treeship-cli` |
| MCP Server | `treeship-mcp` ([GitHub](https://github.com/zerkerlabs/treeship-mcp)) |

---

## Integrations

Works with popular AI agent frameworks:

| Framework | Documentation |
|-----------|---------------|
| Claude Code | [docs.treeship.dev/integrations/claude-code](https://docs.treeship.dev/integrations/claude-code) |
| Cursor | [docs.treeship.dev/guides/cursor-mcp-setup](https://docs.treeship.dev/guides/cursor-mcp-setup) |
| OpenClaw | [docs.treeship.dev/integrations/openclaw](https://docs.treeship.dev/integrations/openclaw) |
| Nanobot | [docs.treeship.dev/integrations/nanobot](https://docs.treeship.dev/integrations/nanobot) |
| LangChain | [docs.treeship.dev/integrations/langchain](https://docs.treeship.dev/integrations/langchain) |

Don't see your framework? The SDK works with any Python code.

---

## AI Context

Treeship documentation is available in machine-readable format for AI agents:

- **llms.txt** — [docs.treeship.dev/llms.txt](https://docs.treeship.dev/llms.txt)
- **Full docs** — [docs.treeship.dev/llms-full.txt](https://docs.treeship.dev/llms-full.txt)

These are automatically maintained by our docs platform and always up to date.

---

## Examples

### Demo Agent

A deployable loan processing agent with built-in verification:

```bash
cd examples/demo-agent
pip install -r requirements.txt
python agent.py

# Test it
curl http://localhost:8000/process \
  -H "Content-Type: application/json" \
  -d '{"applicant": "Jane", "amount": 50000}'
```

Returns a verification URL for each decision. See [examples/demo-agent](examples/demo-agent).

---

## Independent Verification

Anyone can verify without trusting Treeship:

```bash
# Get the public key
curl https://api.treeship.dev/v1/pubkey

# Get attestation data
curl https://api.treeship.dev/v1/verify/abc123

# Verify Ed25519 signature with OpenSSL
openssl pkeyutl -verify -pubin -inkey pubkey.pem -sigfile sig.bin -in payload.txt
```

Signatures use Ed25519 (RFC 8032). Any implementation can verify.

See [protocol/SPEC.md](protocol/SPEC.md) for the full specification.

---

## Self-Hosting

Run your own instance with your own signing keys:

```bash
# Generate Ed25519 keypair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Deploy
docker run -d \
  -e TREESHIP_SIGNING_KEY="$(base64 < private.pem)" \
  -p 8000:8000 \
  ghcr.io/zerkerlabs/treeship-api:latest
```

See [docs/self-hosting.md](docs/self-hosting.md) for details.

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — [LICENSE](LICENSE)

---

<div align="center">

**Treeship** · Verification for AI agents

[Website](https://treeship.dev) · [Docs](https://docs.treeship.dev) · [GitHub](https://github.com/zerkerlabs/treeship)

</div>
