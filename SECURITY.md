# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Treeship, please report it responsibly.

**Do not open a public issue.**

Email: security@treeship.dev

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | Yes (current)      |
| 0.3.x   | Security fixes only |
| < 0.3   | No longer supported |

## Security model

Treeship's security is documented at https://docs.treeship.dev/docs/concepts/security

Key properties:
- Ed25519 signatures via ed25519-dalek (NCC Group audited)
- AES-256-CTR + HMAC encrypted keystore, machine-bound
- Content-addressed artifact IDs derived from PAE bytes
- DPoP authentication (no stored session tokens)
- Approval nonce binding prevents approval reuse

## Trust boundary

The trust boundary is the machine. Root access breaks all guarantees. Hardware key support (YubiKey, Secure Enclave) is planned for a future release.

## Known limitations

- TLSNotary integration is not yet implemented (specced, not built)
- The daemon runs as a user process, not sandboxed
- Shell hooks run the treeship binary -- PATH hijacking is mitigated by using absolute paths
