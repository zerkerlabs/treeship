# Security Policy

## Hub authentication (design summary)

**Enrollment (once per connection):** `treeship hub attach` uses a **device-style** flow (browser approval, single-use challenge) to register a **dock** on the Hub with **ship** + **dock** Ed25519 public keys.

**Operation (every Hub write):** **DPoP (RFC 9449)** only -- the client proves possession of the **connection private key** per request. There is no long-lived **bearer** token for those writes. No device code is required on each `hub push` or `session report`; that is **by design** and matches proof-of-possession best practices.

**"Device"** means a **registered keypair + `dock_id`**, not hardware attestation, unless a future release adds it. See the full [threat model](docs/security/threat-model.md) (in-repo, canonical) or the rendered [docs.treeship.dev/concepts/security](https://docs.treeship.dev/concepts/security#hub-connection-model-enrollment-and-operation) page.

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

| Version | Supported              |
|---------|------------------------|
| 0.20.x  | Yes (current)          |
| 0.19.x  | Security fixes only    |
| < 0.19  | No longer supported    |

## Security model

Full detail: [`docs/security/threat-model.md`](docs/security/threat-model.md) (canonical, in-repo). Rendered at [docs.treeship.dev/concepts/security](https://docs.treeship.dev/concepts/security).

Key properties:
- Ed25519 signatures via ed25519-dalek (NCC Group audited)
- AES-256-GCM encrypted keystore, machine-bound (see [TS-2026-001](docs/security/TS-2026-001.md) for migration from prior construction)
- Content-addressed artifact IDs derived from PAE bytes
- Hub: device authorization for **enrollment**, **DPoP (RFC 9449)** for **every authenticated Hub write** (no bearer session tokens for that path)
- Approval nonce binding prevents approval reuse

## Trust boundary

The trust boundary is the machine. Root access breaks all guarantees. **Hub "device" identity is key-based (dock + DPoP),** not bound to a specific physical machine unless we add platform attestation later. Hardware key support (YubiKey, Secure Enclave) is a possible future hardening. Copying `~/.treeship` with hub keys copies that identity.

## Trust roots (issuer pinning)

Three verification paths used to trust whichever public key was embedded inside the artifact they verified -- Merkle checkpoints, hub-org `JournalCheckpoint`s, and Agent Certificates. An attacker who minted their own keypair could self-sign any of these and verification returned success. Starting in v0.10.3, each of these surfaces requires the embedded pubkey to be present in the operator's local trust root store at `~/.treeship/trust_roots.json` (mode `0o600`, JSON schema v1). Configure via `treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|hub_org|cert_issuer|revoker|agent_cert|session_host>` (the v0.19 trust-split replaced the single `ship` power with the scoped `hub_org` / `cert_issuer` / `revoker` kinds). Fresh installs have no roots configured; verification fails closed until roots are pinned out-of-band.

## Known limitations

- Hub connections are as strong as **key storage and revocation hygiene**; treat stolen config like stolen SSH keys.
- TLSNotary integration is not yet implemented (specced, not built)
- The daemon runs as a user process, not sandboxed
- Shell hooks run the `treeship` binary -- PATH hijacking is mitigated by using absolute paths
