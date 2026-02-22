# Security Policy

## Reporting Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: security@zerker.ai

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We will acknowledge receipt within 48 hours and aim to resolve critical issues within 7 days.

## Security Model

### What Treeship Guarantees

1. **Signature Integrity** — Attestations are signed with Ed25519. Valid signatures prove the attestation was signed by the holder of the private key.

2. **Independent Verification** — Anyone can verify signatures without trusting Treeship using the public key at `/v1/pubkey`.

3. **Payload Integrity** — The signature covers the canonical JSON payload. Any modification invalidates the signature.

4. **Privacy Contract** — With default settings (`hash_only: true`), only SHA-256 hashes of inputs are sent to Treeship. Raw content never leaves the agent's environment.

### What Treeship Does NOT Guarantee

1. **Truth of Claims** — Treeship signs what agents report. It doesn't verify that agents are telling the truth.

2. **Agent Identity** — Treeship identifies agents by `agent_slug`. It doesn't verify the real-world identity behind an agent.

3. **Logical Correctness** — Treeship can prove reasoning text existed at decision time. It cannot prove the reasoning is logically correct or that it caused the output.

## Key Management

### Treeship-Hosted Keys

- Production signing keys are stored in secure infrastructure
- Keys are never exposed via API
- Key rotation follows documented procedure
- `key_id` in attestations identifies which key was used

### Self-Hosted Keys

Self-hosters are responsible for:
- Generating keys securely (`treeship-api keygen`)
- Storing private keys securely
- Rotating keys periodically
- Publishing public keys for verifiers

## Known Limitations

1. **Replay Protection** — Attestations include timestamps but no built-in replay protection. Verifiers should check timestamp freshness.

2. **Clock Skew** — Timestamps are server-generated. Self-hosters should use NTP.

3. **Sidecar Trust** — The sidecar runs alongside your agent. If an attacker compromises the host, they can make false attestations. This is inherent to any local signing system.

## Vulnerability Disclosure Timeline

| Severity | Response Time | Fix Timeline |
|----------|---------------|--------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 1 week | 30 days |
| Low | 2 weeks | 60 days |

## Public Key Rotation

When rotating production keys:
1. New key added to `protocol/keys.json` with future `effective` date
2. 30-day overlap period where both keys are valid
3. Old key marked as deprecated
4. Old key removed after 90 days

Verifiers should always check `key_id` against the published keys.
