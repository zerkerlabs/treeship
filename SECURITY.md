# Security Policy

## Hub authentication (design summary)

**Enrollment (once per connection):** `treeship hub attach` uses a **device-style** flow (browser approval, single-use challenge) to register a **dock** on the Hub with **ship** + **dock** Ed25519 public keys.

**Operation (every Hub write):** **DPoP (RFC 9449)** only -- the client proves possession of the **connection private key** per request. There is no long-lived **bearer** token for those writes. No device code is required on each `hub push` or `session report`; that is **by design** and matches proof-of-possession best practices.

**"Device"** means a **registered keypair + `dock_id`**, not hardware attestation, unless a future release adds it. See the full [threat model and Hub section](https://docs.treeship.dev/docs/concepts/security#hub-connection-model-enrollment-and-operation) in the documentation.

---

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

| Version | Supported            |
|---------|------------------------|
| 0.9.x   | Yes (current)          |
| 0.8.x   | Security fixes only     |
| < 0.8   | No longer supported     |

## Security model

Full detail: [Security -- concepts](https://docs.treeship.dev/docs/concepts/security)

Key properties:
- Ed25519 signatures via ed25519-dalek (NCC Group audited)
- AES-256-CTR + HMAC encrypted keystore, machine-bound
- Content-addressed artifact IDs derived from PAE bytes
- Hub: device authorization for **enrollment**, **DPoP (RFC 9449)** for **every authenticated Hub write** (no bearer session tokens for that path)
- Approval nonce binding prevents approval reuse

## Trust boundary

The trust boundary is the machine. Root access breaks all guarantees. **Hub "device" identity is key-based (dock + DPoP),** not bound to a specific physical machine unless we add platform attestation later. Hardware key support (YubiKey, Secure Enclave) is a possible future hardening. Copying `~/.treeship` with hub keys copies that identity.

## Known limitations

- Hub connections are as strong as **key storage and revocation hygiene**; treat stolen config like stolen SSH keys.
- TLSNotary integration is not yet implemented (specced, not built)
- The daemon runs as a user process, not sandboxed
- Shell hooks run the `treeship` binary -- PATH hijacking is mitigated by using absolute paths
