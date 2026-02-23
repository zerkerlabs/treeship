<div align="center">

# Treeship Protocol

### Cryptographic Attestation Standard for AI Agents

[![Protocol Version](https://img.shields.io/badge/Protocol-v1.0-blue)](protocol/SPEC.md)
[![npm](https://img.shields.io/npm/v/treeship-cli)](https://www.npmjs.com/package/treeship-cli)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Protocol Spec](protocol/SPEC.md) · [Documentation](https://docs.treeship.dev) · [Reference Implementation](https://api.treeship.dev) · [Verification](https://treeship.dev/verify)

</div>

---

## Abstract

Treeship is an open protocol for creating verifiable, tamper-proof records of AI agent actions. Each attestation is cryptographically signed using Ed25519 and can be independently verified by any party without trusting the attestation provider.

This repository contains the protocol specification, reference implementations, and client SDKs.

---

## Motivation

As AI agents increasingly make autonomous decisions in high-stakes domains—finance, healthcare, legal, infrastructure—stakeholders require more than logs or screenshots as evidence of agent behavior.

Current approaches fail because:

1. **Logs are mutable.** Database records can be modified after the fact.
2. **Trust is centralized.** Verification requires trusting the agent operator.
3. **No standard format.** Every system implements its own audit trail.

Treeship addresses these gaps by providing:

- **Cryptographic binding** between actions and timestamps via Ed25519 signatures
- **Independent verification** using only the public key and attestation data
- **Open protocol** that any implementation can produce and verify

---

## Protocol Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          ATTESTATION FLOW                            │
└──────────────────────────────────────────────────────────────────────┘

    Agent                    Treeship                    Verifier
      │                         │                           │
      │  1. Action executed     │                           │
      │  ───────────────────►   │                           │
      │     {action, hash}      │                           │
      │                         │                           │
      │  2. Sign & store        │                           │
      │  ◄───────────────────   │                           │
      │     {attestation}       │                           │
      │                         │                           │
      │                         │   3. Request attestation  │
      │                         │   ◄───────────────────────│
      │                         │                           │
      │                         │   4. Verify signature     │
      │                         │   ───────────────────────►│
      │                         │      (offline capable)    │
```

### Attestation Structure

```json
{
  "id": "abb90e83-122a-40ef-920b-91467b32bbb8",
  "agent": "loan-processor",
  "action": "Approved application #12345",
  "inputs_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924...",
  "timestamp": "2026-02-22T14:30:00.000Z",
  "signature": "Ed25519(canonical_payload)",
  "key_id": "753b4a06e6bcfb26"
}
```

See [Protocol Specification](protocol/SPEC.md) for complete field definitions, canonicalization rules, and verification procedures.

---

## Security Model

### Trust Assumptions

| Component | Trust Required | Notes |
|-----------|---------------|-------|
| Ed25519 cryptography | Yes | Well-audited, industry standard |
| SHA-256 hashing | Yes | Collision-resistant |
| Treeship servers | **No** | Signatures verifiable offline |
| Network integrity | **No** | Tampering detectable via signature |

### What Attestations Prove

| Claim | Provable | Mechanism |
|-------|----------|-----------|
| Action was recorded | Yes | Signature existence |
| Timestamp is authentic | Yes | Signed timestamp |
| Inputs were hashed | Yes | Hash binding |
| Action actually occurred | No | Requires trust in agent operator |
| Decision was correct | No | Requires external ground truth |

We are explicit about cryptographic guarantees. Attestations prove that *a claim was signed at time T*, not that the claim itself is true.

---

## Reference Implementation

The canonical implementation is available at `api.treeship.dev`:

```bash
# Create attestation
curl -X POST https://api.treeship.dev/v1/attest \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_slug": "my-agent",
    "action": "Processed request",
    "inputs_hash": "sha256:..."
  }'

# Verify attestation
curl https://api.treeship.dev/v1/verify/{attestation_id}

# Get public key for independent verification
curl https://api.treeship.dev/v1/pubkey
```

---

## Client SDKs

### Python

```bash
pip install treeship-sdk
```

```python
from treeship_sdk import Treeship

client = Treeship(api_key="ts_live_...")

attestation = client.attest(
    agent="loan-processor",
    action="Approved application #12345",
    inputs_hash=client.hash(application_data)
)

print(attestation.verify_url)
```

### CLI

```bash
npm install -g treeship-cli
```

```bash
export TREESHIP_API_KEY=ts_live_...

treeship attest \
  --agent loan-processor \
  --action "Approved application #12345" \
  --inputs-hash $(echo -n "$DATA" | sha256sum | cut -d' ' -f1)

treeship verify <attestation_id>
```

---

## Independent Verification

Attestations can be verified without contacting Treeship servers:

```bash
# 1. Obtain the public key (cache this)
curl -s https://api.treeship.dev/v1/pubkey | jq -r '.public_key_pem' > pubkey.pem

# 2. Fetch attestation data
curl -s https://api.treeship.dev/v1/verify/$ID > attestation.json

# 3. Extract canonical payload and signature
jq -r '.independent_verification.recreate_payload' attestation.json > payload.txt
jq -r '.signature' attestation.json | base64 -d > signature.bin

# 4. Verify with OpenSSL
openssl pkeyutl -verify -pubin -inkey pubkey.pem \
  -sigfile signature.bin -in payload.txt

# Output: Signature Verified Successfully
```

Any Ed25519 implementation in any language can perform this verification.

---

## Repository Structure

```
treeship/
├── protocol/
│   ├── SPEC.md                 # Protocol specification
│   ├── attestation.schema.json # JSON Schema for attestations
│   └── keys.json               # Key format specification
├── packages/
│   ├── sdk-python/             # Python SDK source
│   ├── sdk-js/                 # JavaScript SDK source
│   ├── cli/                    # CLI tool source
│   └── sidecar/                # Docker sidecar
├── integrations/
│   ├── langchain/              # LangChain callback handler
│   └── openclaw/               # OpenClaw skill
├── docs/
│   ├── getting-started.md
│   ├── self-hosting.md
│   └── privacy.md
└── examples/
    └── ...
```

---

## Self-Hosting

Organizations requiring full control can deploy the complete stack:

```bash
# Generate Ed25519 keypair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Run with Docker
docker run -d \
  -e TREESHIP_SIGNING_KEY="$(base64 < private.pem)" \
  -e DATABASE_URL="postgresql://..." \
  -p 8000:8000 \
  ghcr.io/zerkerlabs/treeship-api:latest
```

Self-hosted instances produce attestations that are verifiable against your public key. See [Self-Hosting Guide](docs/self-hosting.md).

---

## Contributing

We welcome contributions to the protocol specification, SDKs, and documentation.

1. **Protocol changes** require an RFC process. Open an issue with `[RFC]` prefix.
2. **SDK contributions** should maintain API compatibility. See [CONTRIBUTING.md](CONTRIBUTING.md).
3. **Security issues** should be reported privately. See [SECURITY.md](SECURITY.md).

```bash
git clone https://github.com/zerkerlabs/treeship.git
cd treeship
# See packages/*/README.md for package-specific setup
```

---

## Specification Documents

| Document | Description |
|----------|-------------|
| [Protocol Spec](protocol/SPEC.md) | Complete attestation format and verification procedure |
| [JSON Schema](protocol/attestation.schema.json) | Machine-readable attestation schema |
| [Privacy Model](docs/privacy.md) | Data handling and privacy guarantees |
| [Security Policy](SECURITY.md) | Vulnerability reporting process |

---

## License

MIT License. See [LICENSE](LICENSE).

---

<div align="center">

**Treeship Protocol** · Verifiable AI, Cryptographically

[Website](https://treeship.dev) · [Documentation](https://docs.treeship.dev) · [API Reference](https://docs.treeship.dev/api-reference/overview)

</div>
