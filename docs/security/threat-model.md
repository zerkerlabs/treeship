# Treeship Threat Model

> Authoritative, in-repo description of what Treeship is designed to defend
> against, what it is not, and which cryptographic primitives carry that
> weight. This document is the canonical reference; the
> `docs.treeship.dev` site renders from this file.

---

## Overview

Treeship produces portable, cryptographically signed receipts for AI agent
sessions. Every action an agent takes — every shell command wrapped, every
MCP tool call, every approval grant, every handoff between agents — is
serialized into a DSSE envelope, signed with an Ed25519 key, and appended
to an append-only Merkle log. The artifact is content-addressed by its
PAE digest, so the same action under the same identity always yields the
same ID.

The core invariant is this: **every action an agent takes can be
cryptographically replayed and verified by anyone who has the receipt and
a configured trust root, without contacting any Treeship-operated
infrastructure.** Verification is offline, deterministic, and runs in
pure WASM. The hub is a publishing surface, not a custodian.

What this means for the trust model:

- A receipt is evidence in the cryptographic sense, not the legal sense.
  It proves that *some* signer with control of a specific private key
  produced an envelope whose PAE digest matches the claimed content. It
  does not prove the signer was human, was the named agent, or was
  authorized to act — those are policy decisions, decided at the
  verifier by checking the signer's public key against a configured
  trust root.
- Treeship is **not** a global trust authority. There is no Treeship-run
  CA, no Sigstore-style Rekor that verifiers must call. Trust is local
  policy. Every verifier brings its own pinned public keys (the trust
  root) and decides which signers it accepts.
- Treeship makes specific cryptographic claims: receipts are bound to
  their signer, Merkle proofs are bound to a signed checkpoint, hub
  writes are bound to a per-request DPoP proof of possession. It makes
  no claim about the truthfulness of the agent's *outputs* — Treeship
  records what an agent did, not whether the agent's reasoning was
  correct.

This document describes the actual code that ships in
`packages/core`, not aspirations. Where a property is shipping in
`v0.10.3` because of audit fixes (TS-2026-001 and the P0 series), that is
called out explicitly.

---

## Identities

Treeship distinguishes four identity concepts. They are not
interchangeable.

| Concept     | Lifetime               | Key material                       | Issued by                     | Stored at                                |
|-------------|------------------------|------------------------------------|-------------------------------|------------------------------------------|
| **Ship**    | Long-lived (per machine) | Ed25519 keypair                  | Local `treeship init`         | `~/.treeship/keys/`                      |
| **Dock**    | Long-lived (per hub)     | Ed25519 keypair                  | Local `treeship hub attach`   | `~/.treeship/hub/<name>/dock.key`        |
| **Session** | Ephemeral (one workflow) | None — signs under the ship key  | The ship that opens it        | `.treeship/sessions/<session_id>/`       |
| **Agent**   | Conceptual (the actor)   | None — names a URI like `agent://researcher` | Configured by the user or auto-detected | Embedded in receipt statements |

### Ship

A **ship** is a long-lived per-machine identity. Its Ed25519 keypair is
created on `treeship init` and lives in the encrypted keystore at
`~/.treeship/keys/`. The ship signs every receipt, every checkpoint,
every bundle. There is exactly one default ship per machine, though the
keystore supports multiple labeled ships for advanced workflows.

The ship private key is the root of every cryptographic claim Treeship
makes about that machine's actions. Compromise of the ship key allows
forging arbitrary receipts that will verify successfully against any
verifier that trusts that ship's public key. Defense is at-rest
encryption (AES-256-GCM as of `v0.10.3`; see TS-2026-001) plus
filesystem permissions (mode `0o600`, enforced at creation and verified
on every load).

### Dock

A **dock** is the per-hub connection identity. When a user runs
`treeship hub attach`, a fresh Ed25519 keypair is generated locally; the
public key is registered with the hub through a device-style approval
flow (browser confirmation, single-use challenge). The hub stores the
dock's public key and a `dock_id`. Every subsequent hub write is signed
with a DPoP (RFC 9449) proof using the dock's private key.

The dock is *not* the ship. A ship can have multiple docks (one per hub
connection); revoking a dock revokes the connection but leaves the ship
identity intact. The dock private key never leaves the machine.

### Session

A **session** is the unit of work a Treeship records. It is ephemeral —
it has a `session_id`, an open and close time, an append-only event
log, and a sealed receipt that is signed at close. Sessions do not have
their own signing keys; everything in a session is signed by the ship
that opened it. The session is a scoping construct, not an identity.

### Agent

An **agent** is the named actor in a receipt. Agents are URIs like
`agent://researcher` or `human://alice`. The agent identifier is
metadata embedded in the signed payload — Treeship records what
identifier was claimed, but does not verify that the named agent is
actually what produced the action. That is the verifier's job, by
matching the signer's public key against a trust root that lists
acceptable agents per ship.

---

## Signing model

All signing in Treeship goes through one path:

```
Statement (JSON) ──► RFC 8785 canonicalize ──► PAE bind type+payload ──► Ed25519 sign
```

### Ed25519

Signatures use [`ed25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek)
2.x, the implementation that was audited by NCC Group in 2020. The crate
uses the `subtle` library throughout for constant-time scalar operations.
Treeship does not implement its own elliptic-curve code anywhere; all
signing and verification call into `ed25519-dalek`.

Public keys are 32 bytes, private keys are 32 bytes (seed form), and
signatures are 64 bytes. Key IDs are the form `key_<hex>` where the
hex is the first 16 bytes of `sha256(public_key_bytes)`.

### PAE (DSSE pre-authentication encoding)

Every signature in Treeship is over PAE bytes, never the raw payload.
The PAE construction is:

```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

This is the standard DSSE construction (compatible with Sigstore and
in-toto). The `payloadType` is a MIME type like
`application/vnd.treeship.action.v1+json`. Binding the type and its
length into the signed bytes prevents type-confusion attacks where an
attacker signs bytes under type B that parse validly under type A.

The implementation is in `packages/core/src/attestation/pae.rs`. It
pre-allocates the exact buffer size and panics on no error path; PAE
construction is infallible.

### DSSE envelopes

The signed artifact is a DSSE `Envelope`:

```json
{
  "payload": "<base64url(statement_bytes)>",
  "payloadType": "application/vnd.treeship.action.v1+json",
  "signatures": [
    { "keyid": "key_abc123", "sig": "<base64url(64 bytes)>" }
  ]
}
```

The outer JSON is not signed. Only the PAE bytes are. The envelope
serves as a portable transport wrapper; verifying it always re-derives
the PAE from `payload` and `payloadType` and re-checks the signature.

`v1` envelopes carry exactly one signature. Multi-signature DSSE
envelopes are valid by the spec but currently unused; the verifier
rejects empty `signatures` arrays.

### At-rest keystore: AES-256-GCM

Private keys are encrypted at rest with AES-256-GCM via the RustCrypto
[`aes-gcm`](https://crates.io/crates/aes-gcm) 0.10 crate. The keystore
file format is:

```
[ magic = 0x54 ('T') ]   1 byte
[ version = 0x02     ]   1 byte
[ nonce              ]  12 bytes (random per encryption, OS CSPRNG)
[ ciphertext || tag  ]  N + 16 bytes (GCM authentication tag)
```

The `[magic, version]` framing prefix is bound into the AEAD's Associated
Authenticated Data, so flipping the magic or version byte on disk
triggers a clean MAC failure rather than a downgrade.

The `v0.10.3` keystore replaces a prior construction that was documented
as AES-256-GCM but actually shipped a homemade SHA-256-CTR + HMAC scheme
with a degenerate keystream. That advisory is **[TS-2026-001](./TS-2026-001.md)**
and migration to the real AEAD is automatic on first signing operation
after upgrade.

The keystore is encrypted with a machine-bound key derived from
`hostname + username` on macOS or `/etc/machine-id` on Linux. The
machine-key derivation is not a secret — it is a defense-in-depth
binding so an exfiltrated keystore cannot be decrypted on a different
machine without also exfiltrating the machine identifier. Filesystem
permissions (`0o600`) remain the primary access control.

### Constant-time primitives

Where signing or comparison happens on secret material, Treeship relies
on `ed25519-dalek`'s constant-time operations (via the `subtle` crate)
and on `aes-gcm`'s constant-time tag verification. Treeship does not
implement its own constant-time comparison anywhere in the signing or
keystore path.

---

## Receipts and bundles

A **receipt** is one signed envelope describing one event in a session.
Receipts have a stable artifact ID derived from the SHA-256 of the PAE
bytes, encoded as `art_<base32>`. Two receipts with byte-identical PAE
have the same ID; any change to the payload changes the ID.

A **session receipt** is a special receipt that seals a session. It
references every artifact in the session timeline by ID, captures the
Merkle root of the session's event log, and is itself signed and
content-addressed like every other artifact.

A **bundle** is a portable export — a JSON file (`.treeship` extension)
containing a top-level signed `BundleStatement` plus all the artifact
envelopes the bundle references. Bundles are what get uploaded to the
hub or shared as files. Bundle verification re-checks every envelope
inside, walks the chain (each artifact links to the hash of the
previous), and checks Merkle inclusion against the bundle's checkpoint.

### What verify checks

`treeship verify` and the WASM `verify_receipt` API run five checks:

1. **Signature** — every envelope's PAE bytes verify against its claimed
   signer key.
2. **Chain integrity** — each artifact's `previous_hash` field equals
   the SHA-256 digest of the previous artifact's PAE bytes.
3. **Merkle inclusion** — the inclusion proof in each artifact reconstructs
   the same root that the checkpoint claims to commit to.
4. **Checkpoint signature** — the signed Merkle root is itself a DSSE
   envelope, signed by the ship; the verifier re-checks that signature.
5. **Policy** — the verifier's local policy (e.g. trust roots, required
   approval nonces, max-age) is satisfied.

None of these require network access. The verifier needs the bundle and
its configured trust root; nothing else.

### Bundle import safety

Until `v0.10.3`, the bundle import path (`treeship package import` and
the WASM equivalent) silently trusted envelope signatures inside the
bundle without re-verifying them against the bundle's own signer. The
P0 fix in audit lane H rebuilds bundle import to re-verify every
contained envelope before any local state mutation, and rejects bundles
whose contents do not chain cleanly to the bundle's signed root. See the
`v0.10.3` CHANGELOG and PR #86 for the diff.

### Merkle v1 versus v2

The Merkle tree algorithm is identified by a constant on each leaf and
checkpoint:

- `sha256-duplicate-last` (v1) — pre-`v0.10.3`. Duplicates the last leaf
  for odd levels. This construction is vulnerable to a second-preimage
  forgery against the proof, because an interior node and a duplicated
  leaf can produce the same parent hash.
- `sha256-rfc9162` (v2) — `v0.10.3`+. The RFC 9162 Certificate
  Transparency construction with explicit domain separation bytes
  (`0x00` for leaves, `0x01` for interior nodes). No second-preimage
  collisions are possible across leaf/interior levels.

`v0.10.3` writes v2 trees by default and verifies both v1 and v2 trees.
`v0.13.0` will remove the v1 verifier path entirely; bundles signed
before that release that still carry v1 trees will need to be re-bundled
under v2 before `v0.13.0` ships. The migration window is generous because
historical bundles are typically short-lived.

---

## Hub model

The hub is the optional publishing surface. Receipts are local until you
explicitly push them. The hub's job is to:

- Host a public verify URL (`https://treeship.dev/verify/<artifact_id>`)
- Store the receipt bundle so anyone with the URL can fetch and verify
- Enforce per-dock rate limits and quotas

It is **not** part of the trust chain. The verifier does not need to
trust the hub; the hub serves bytes that the verifier re-validates.

### Enrollment (device-style flow)

`treeship hub attach` runs once per hub connection:

1. The client generates a fresh Ed25519 dock keypair locally.
2. The client requests a single-use device challenge from the hub.
3. The user is shown a URL and a short code; they open the URL in a
   browser, authenticate (whatever scheme the hub uses; the reference
   `api.treeship.dev` uses GitHub OAuth), and confirm the code.
4. The hub registers the dock's public key under the user's account and
   returns a `dock_id`.
5. The client persists the `dock_id` and dock private key in
   `~/.treeship/hub/<name>/`.

This is a one-shot device authorization flow modeled on RFC 8628 but
adapted for proof-of-possession (the dock keypair is the proof material,
not a returned bearer token). After enrollment, the hub has the dock's
public key, the client has the matching private key, and the channel
between them is authenticated by demonstrating possession of that key
on every request.

### Operation (DPoP)

Every authenticated hub write — `hub push`, `session report`, `hub pull`
when authenticated, every metadata mutation — proves possession of the
dock private key on each request using DPoP (RFC 9449). Concretely, each
request carries a `DPoP` header whose value is a JWT-style token signed
by the dock keypair and bound to:

- The HTTP method
- The full request URL
- A fresh nonce (`jti`)
- An issued-at timestamp

The hub verifies the DPoP signature against the registered dock public
key, checks the nonce is unused within the replay window, and rejects
the request otherwise. There is **no long-lived bearer token** for hub
writes; possession of the dock private key is proven per request.

This design intentionally rules out a class of vulnerabilities: there
is no `Authorization: Bearer <token>` to steal from a log file or leak
through a proxy. An attacker who captures one DPoP-bound request body
gains nothing because the DPoP token is bound to that single request.

### What the hub trusts

The hub trusts a client iff:

1. The client presents a DPoP proof signed by a registered dock keypair,
   AND
2. The DPoP token is fresh (within the replay window, jti unused), AND
3. The request URL/method match the DPoP-bound claims.

The hub does **not** verify the *content* of pushed receipts beyond what
storage demands (well-formed JSON, valid envelope shape, size limits).
Verification is the verifier's job, not the hub's.

---

## Trust roots

A **trust root** is a verifier's local list of public keys it will
accept signatures from. There is no Treeship-operated PKI; trust is a
local file.

`v0.10.3` (audit lane J) introduces a structured trust root store at
`~/.treeship/trust_roots.json`. The format pins issuer public keys for
the three self-signed verification boundaries:

- **Merkle checkpoint** — the ship that signed the checkpoint must
  appear in the trust roots as a `MerkleCheckpoint` issuer, or the
  verifier rejects the bundle.
- **Hub-org `JournalCheckpoint`** — when a hub publishes its own signed
  journal (a meta-receipt that anchors a batch of receipts), the hub-org
  key must be pinned.
- **Agent certificate** — when an agent presents a certificate binding
  its `agent://...` URI to a public key, the certificate's issuer must
  be pinned.

Without pinned trust roots, verification fails closed. There is no
default trust root that Treeship ships with — bootstrapping is an
explicit step (`treeship trust add <pubkey> --kind merkle-checkpoint`).
The file is mode `0o600` with the same `TREESHIP_ALLOW_INSECURE_KEY_PERMS=1`
override semantics as the keystore.

> **Status:** The `TrustRootStore` module is implemented and tested
> (`packages/core/src/trust/mod.rs`, 11 unit tests covering roundtrip,
> permissions, kind discrimination, and idempotent add/remove). The
> wiring that *enforces* trust roots in the three verification paths is
> shipping in `v0.10.3` and is tracked in audit lane J.

Pre-`v0.10.3`, the verifier accepted any signature that mathematically
validated, without a configured trust root. This is the class of issue
the lane-J pinning addresses (P0 #3, self-signed checkpoint acceptance).

---

## Trust boundaries

Treeship's guarantees terminate at specific boundaries. Past those
boundaries, no cryptography in this codebase can help you.

### Machine

The machine is the inner boundary. **Root access on the machine breaks
all guarantees.** This is the same level of trust as SSH keys: anyone
who can read `~/.treeship/keys/` and `~/.treeship/hub/*/dock.key` and
the machine identifier can sign as you.

The keystore at-rest encryption (AES-256-GCM since `v0.10.3`) is
defense-in-depth, not a primary control. It protects against:

- An exfiltrated keystore copy (e.g. an unsecured backup) being usable
  on a different machine.
- A non-`root` attacker who reaches the file briefly but cannot
  exfiltrate it (e.g. a misconfigured world-readable home dir
  momentarily exposed).

It does **not** protect against an attacker with persistent
same-user-or-root access to the running machine. That attacker can:

- Read the decrypted key during signing operations.
- Trace `treeship` invocations and capture in-memory key material.
- Replace the `treeship` binary outright.

### Network

Network paths use TLS, terminated against the system trust store. The
hub does not implement its own certificate pinning; an attacker who can
mint a certificate accepted by the user's OS-level CA store can MITM
the hub connection.

DPoP on top of TLS means a network adversary who breaks TLS still cannot
forge writes to the hub: they would also need the dock private key to
produce a valid DPoP token. They can, however, read receipt content
(which is by design public — receipts are designed to be shared) and
they can block uploads (availability).

### Hub

The hub trusts clients via the registered dock public key plus per-request
DPoP. The hub **cannot impersonate a ship** — the ship's signing key
never leaves the machine. A compromised hub can:

- Refuse to publish receipts (availability).
- Serve modified receipts to verifiers (the verifier will reject them on
  signature check).
- Leak receipt content (which, again, is public-by-design).

A compromised hub **cannot**:

- Forge signatures.
- Substitute one ship's receipts for another's.
- Cause a verifier with a correctly configured trust root to accept a
  fraudulent bundle.

### Receipts

The verifier trusts:

- The implementation of `ed25519-dalek` (NCC Group audited, widely
  deployed)
- The implementation of `sha2` (RustCrypto, widely deployed)
- The implementation of `aes-gcm` (RustCrypto, widely deployed)
- Its own configured trust roots

The verifier does **not** trust:

- Any Treeship-operated service
- The bundle's own claims about which keys are trusted
- The hub the bundle came from

There is no trusted third party at verify time. The only authority is
the signer's public key, gated by the verifier's local trust root.

---

## In scope

Treeship is designed to detect or prevent the following classes of
attack. Each is covered by code in `packages/core` and by unit tests in
`packages/core/src/**/tests`.

| Threat                                                   | Defense                                                       | Where                                            |
|----------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------------|
| Forged action receipts (attacker without the ship key)   | Ed25519 signature over PAE bytes                              | `attestation/sign.rs`, `attestation/verify.rs`   |
| Receipt tampering after signing                          | PAE binds payload type + payload bytes; any change invalidates | `attestation/pae.rs`                             |
| Type-confusion (signing bytes under type B that parse as type A) | PAE includes payload type in the signed bytes               | `attestation/pae.rs`                             |
| Replay of approval grants across actions                 | Approval nonce binding; each action consumes a single-use nonce | `statements/approval.rs`, `verify.rs`            |
| Receipt swap between sessions                            | Chain integrity check (`previous_hash` references prior PAE digest) | `attestation/verify.rs`                          |
| Verifier accepting envelopes with empty signature arrays | Envelope parsing rejects empty `signatures`; verifier rejects envelopes that fail signature re-check | Audit lane H, `v0.10.3`                          |
| Verifier accepting unverified bundle imports             | Bundle import re-verifies every contained envelope before mutating local state | Audit lane H, `v0.10.3`                          |
| Merkle proof second-preimage forgery                     | RFC 9162 domain-separated tree (`sha256-rfc9162`); v1 verifier removed in `v0.13.0` | Audit lane I, `v0.10.3`; `merkle/tree.rs`        |
| Self-signed checkpoint acceptance                        | Trust roots pin acceptable checkpoint issuers; verifier refuses checkpoints without a matching trust root | Audit lane J, `v0.10.3`; `trust/mod.rs`          |
| Bearer-token theft for hub writes                        | DPoP (RFC 9449) — every write is bound to the dock keypair    | Hub server, `packages/hub`                       |
| Device-flow code phishing                                | Single-use device challenge, time-bounded; user sees URL+code in their own browser | Hub enrollment flow                              |
| Keystore tampering at rest (file-level swap)             | AES-256-GCM with framing prefix bound into AAD               | `v0.10.3`; `keys/mod.rs`. See TS-2026-001.       |
| Concurrent keystore migration races                      | Per-entry advisory lock on `<entry>.migrate.lock`            | `v0.10.3`; `keys/mod.rs`                         |
| Event log race on concurrent writers                     | `flock(2)` advisory lock + counter sidecar; bounded retry, fail-open with stderr warning | `session/event_log.rs`                           |

---

## Out of scope

Treeship makes no claim to defend against these. They are listed here
explicitly so that users do not assume defenses that do not exist.

- **Compromised local machine.** An attacker with root or same-user
  file-system access can read decrypted keys during signing, replace the
  `treeship` binary, or scrape memory. The trust boundary is the machine;
  past that boundary, no in-codebase defense applies.

- **Compromised model provider.** Treeship records what an agent *did*,
  under what identity. It does not verify the *correctness* of the
  agent's outputs. If Anthropic, OpenAI, or any other model provider is
  compromised and produces a malicious tool call, Treeship will faithfully
  record the malicious call. The receipt is true; the action it records
  may still be harmful.

- **Network adversary against TLS.** Treeship uses TLS for hub connections,
  terminated against the system trust store. An attacker who can mint
  a certificate accepted by the OS-level CA store can MITM. We do not
  ship certificate pinning. DPoP partially mitigates by preventing write
  forgery, but read paths remain MITM-able.

- **User-side social engineering.** If a human is convinced to approve
  a malicious action via `treeship attest approval`, the resulting
  receipt is cryptographically valid. Treeship does not, and structurally
  cannot, prevent humans from being deceived. UI surfaces (the approval
  prompt, the hub verify page) try to make the action being approved
  visible and unambiguous, but the ultimate decision is the human's.

- **Hardware-level attacks.** No Secure Enclave, TPM, or YubiKey binding
  yet. The `treeship-vi` companion crate has its own hardware-binding
  plans, but core `treeship-core` does not. A flagged future hardening.

- **Side channels in non-`ed25519-dalek` code.** We rely on
  `ed25519-dalek` and `aes-gcm` to be constant-time. We do not audit our
  own code for timing side channels at the same level. In particular,
  JSON canonicalization, base64 encoding, and Merkle tree construction
  are not constant-time.

- **Hub availability.** The hub is a single point of failure for
  publishing receipts. Treeship is designed to work offline; hub
  failures degrade the publishing surface but do not break local
  attestation or local verification. We do not run a multi-region
  hub today.

- **Long-term archival storage of receipts.** Receipts are durable for
  as long as the bytes survive. Treeship makes no claim about preserving
  receipts past the lifetime of the hub or the user's local store.
  Long-term archival (e.g. anchoring to Bitcoin via OpenTimestamps) is
  on the research backlog but not implemented.

- **Compromised dependencies.** A malicious update to `ed25519-dalek`,
  `aes-gcm`, `sha2`, or any other crate in the dependency tree would
  compromise Treeship. We pin exact versions in `Cargo.lock`, audit
  releases via `cargo audit` in CI, and treat the supply chain as part
  of the platform — but a sophisticated supply-chain attack is not
  something we can detect in-codebase.

---

## Cryptographic primitives in use

| Purpose                          | Primitive               | Implementation                   | Notes                                                                          |
|----------------------------------|-------------------------|----------------------------------|--------------------------------------------------------------------------------|
| Signing                          | Ed25519                 | `ed25519-dalek` 2.x              | NCC Group audited. Constant-time via `subtle`.                                 |
| Hashing                          | SHA-256                 | RustCrypto `sha2`                | Used for content addressing, Merkle tree, fingerprints.                        |
| Canonical JSON                   | RFC 8785 JCS            | In-tree, `packages/core/src/statements/canonical.rs` | Deterministic key ordering, no whitespace.                                     |
| Envelope binding                 | DSSE PAE                | In-tree, `packages/core/src/attestation/pae.rs`      | `DSSEv1 <type-len> <type> <payload-len> <payload>`                             |
| Keystore AEAD (`v0.10.3`+)       | AES-256-GCM             | RustCrypto `aes-gcm` 0.10        | 96-bit nonce, framing prefix bound into AAD. See TS-2026-001.                  |
| Authenticated transport          | TLS 1.2/1.3             | `rustls` (client), system store (cert validation) | No certificate pinning to the hub today.                                       |
| Hub proof-of-possession          | DPoP                    | RFC 9449                         | Per-request signature with the dock keypair. No long-lived bearer tokens.      |
| Merkle tree (`v0.10.3`+)         | SHA-256 RFC 9162        | In-tree, `packages/core/src/merkle/tree.rs` | Domain-separated `0x00` leaves, `0x01` interior nodes.                         |
| Approval nonce                   | 16-byte OS CSPRNG       | `rand::rngs::OsRng`              | Single-use; consumed on first matched action.                                  |
| Content addressing               | SHA-256 of PAE bytes    | In-tree                          | Artifact IDs encode as `art_<base32>` from the first 16 bytes of the digest.   |

All cryptographic operations route through these crates. Treeship does
not implement its own elliptic-curve, AEAD, or hash code.

---

## Known limitations

These are tracked, not hidden. Each one has a path forward and is open
in the project tracker.

- **`treeship-vi` keystore migration is pending.** The companion crate
  at `packages/vi` continues to use the pre-fix keystore construction
  described in [TS-2026-001](./TS-2026-001.md) until its own migration
  release ships. If you use `treeship vi` to sign L2/L3 mandates, plan
  to rotate vi-issued keys after the vi migration release.

- **No hardware key binding in `treeship-core`.** The ship and dock
  keypairs live in software, protected at rest by AES-256-GCM and
  filesystem permissions. There is no Secure Enclave, TPM, or YubiKey
  integration. `treeship-vi` does hardware-bind some keys on supported
  platforms; the core path does not.

- **The `treeship` daemon and hooks run as user processes.** Not
  sandboxed, not isolated from the rest of the user's filesystem. A
  hostile process running as the same Unix user has full access to the
  keystore.

- **PATH hijacking partially mitigated.** Shell hooks invoke the
  `treeship` binary by absolute path, which prevents a hostile PATH
  entry from intercepting attestation calls. However, the binary itself
  is owned by the user; an attacker who can write `~/.local/bin/treeship`
  with appropriate permissions can substitute their own implementation.

- **No certificate pinning to `api.treeship.dev`.** TLS validation falls
  back to the system trust store. An attacker with a state-level CA can
  MITM. DPoP prevents write forgery in that scenario but not read
  observation.

- **TLSNotary integration is not yet implemented.** Specced, on the
  research backlog; not in the codebase today.

- **Merkle v1 verification will be removed in `v0.13.0`.** Bundles
  signed with the v1 `sha256-duplicate-last` algorithm will need to be
  re-bundled under v2 (`sha256-rfc9162`) before `v0.13.0` ships, or
  verification will fail. This is intentional — v1 has a known
  second-preimage vulnerability against the proof structure (P0 #2,
  fixed in `v0.10.3` for newly signed bundles).

- **No formal external security audit yet.** We've completed an internal
  launch audit (lanes A through K), which surfaced and fixed
  TS-2026-001 and the P0 series. A third-party audit is on the
  pre-`v1.0` checklist but not yet scheduled.

---

## Reporting

Vulnerabilities should be reported to **security@treeship.dev**.

Do not open a public GitHub issue for security-impacting findings.

Include:

- Description of the vulnerability
- Steps to reproduce (a minimal repro is appreciated)
- Impact assessment
- Suggested fix, if any

We acknowledge reports within 48 hours and aim to ship fixes for
critical issues within 7 days. Disclosure timelines are coordinated
with the reporter; we publish advisories under the `TS-YYYY-NNN`
identifier scheme (see [TS-2026-001](./TS-2026-001.md) for an example).

See [SECURITY.md](../../SECURITY.md) for the policy summary and
supported-versions matrix.
