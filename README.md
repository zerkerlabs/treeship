<div align="center">

# Treeship

### Trust Infrastructure for AI Agents

[![Version](https://img.shields.io/badge/v1.0-stable-blue)](protocol/SPEC.md)
[![npm](https://img.shields.io/npm/v/treeship-cli)](https://www.npmjs.com/package/treeship-cli)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Documentation](https://docs.treeship.dev) · [Get Started](https://treeship.dev) · [Verify](https://treeship.dev/verify)

</div>

---

## The Problem

AI agents are making real decisions—approving loans, summarizing medical records, reviewing contracts. But when something goes wrong, there's no way to prove what actually happened.

- **"Did the agent actually analyze my documents?"**
- **"Can I audit what the AI did last Tuesday?"**
- **"How do I prove this to a regulator?"**

Logs aren't enough. They can be modified. They require trusting the operator.

## The Solution

Treeship creates tamper-proof records of AI agent actions that anyone can verify independently.

```
Your Agent → Treeship → Verifiable Record → Anyone Can Audit
```

Every action gets a unique verification link. Share it with customers, auditors, or regulators. They verify without trusting you.

---

## How It Works

**1. Your agent does something**
```python
result = process_loan_application(data)
```

**2. Record it with Treeship**
```python
from treeship_sdk import Treeship

ts = Treeship()
attestation = ts.attest(
    agent="loan-processor",
    action="Approved application #12345",
    inputs_hash=ts.hash(data)
)
```

**3. Share the verification link**
```
https://treeship.dev/verify/abc123
```

Anyone with that link can verify the record is authentic and unmodified.

---

## Why Treeship?

| Challenge | How Treeship Helps |
|-----------|-------------------|
| "Prove your AI actually did this" | Verification links anyone can check |
| "We need audit trails for compliance" | Immutable records with timestamps |
| "Customers don't trust AI decisions" | Independent verification builds confidence |
| "What if logs are tampered with?" | Records are cryptographically signed |

---

## Use Cases

### Financial Services
Prove loan decisions, trading algorithms, and risk assessments were made correctly at the time they happened.

### Healthcare
Create verifiable records of AI-assisted diagnoses and document processing—without exposing patient data.

### Legal & Compliance
Audit trails that satisfy regulators. Evidence that AI reviews actually occurred.

### Enterprise AI
Give customers confidence that your AI product does what you claim.

---

## Quick Start

### 1. Get an API Key

Visit [treeship.dev](https://treeship.dev) and enter your email.

### 2. Install

```bash
pip install treeship-sdk    # Python
npm install -g treeship-cli # CLI
```

### 3. Create Your First Record

```python
from treeship_sdk import Treeship

ts = Treeship()  # Uses TREESHIP_API_KEY env var

result = ts.attest(
    agent="my-agent",
    action="Processed customer request",
    inputs_hash=ts.hash({"request_id": "123"})
)

print(result.verify_url)
# → https://treeship.dev/verify/abc123
```

### 4. Verify

Anyone can verify at the URL—or programmatically:

```bash
treeship verify abc123
```

---

## Privacy

| Sent to Treeship | Stays on Your Server |
|------------------|----------------------|
| Action description | Actual content |
| Hash of inputs | Raw data |
| Timestamp | Files & documents |

You control what's in the action description. Sensitive data never leaves your infrastructure—only a hash that proves the data existed.

---

## Under the Hood

Records are signed with Ed25519 and can be verified offline using only our public key. No trust in Treeship required for verification.

For the technically curious:
- [Protocol Specification](protocol/SPEC.md) — Full attestation format and verification procedure
- [Independent Verification](docs/verification.md) — Verify with OpenSSL or any Ed25519 library

---

## Packages

| Package | Install |
|---------|---------|
| Python SDK | `pip install treeship-sdk` |
| CLI | `npm install -g treeship-cli` |

---

## Self-Hosting

Run your own Treeship instance with your own signing keys. Full documentation: [Self-Hosting Guide](docs/self-hosting.md)

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — [LICENSE](LICENSE)

---

<div align="center">

**Treeship** · Trust infrastructure for AI agents

[Website](https://treeship.dev) · [Docs](https://docs.treeship.dev) · [GitHub](https://github.com/zerkerlabs/treeship)

</div>
