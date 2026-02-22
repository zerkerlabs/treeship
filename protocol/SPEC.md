# Treeship Protocol Specification

**Version:** 1.0  
**Status:** Stable  
**Last Updated:** February 2026

## Overview

The Treeship Protocol defines a standard format for cryptographically signed attestations of AI agent actions. Any implementation that follows this specification can create and verify Treeship attestations.

## Attestation Object

```json
{
  "id": "ts_abc123xyz",
  "agent": "my-agent-slug",
  "version": "1.0",
  "action": "User request processed",
  "inputs_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": "2026-02-22T14:23:01.000Z",
  "signature": "base64url(Ed25519_sign(private_key, canonical_payload))",
  "public_key": "base64url(public_key_bytes)",
  "url": "https://treeship.dev/verify/ts_abc123xyz"
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique attestation identifier (format: `ts_[a-z0-9]+`) |
| `agent` | string | Yes | Agent slug (1-64 chars, lowercase alphanumeric + hyphens) |
| `version` | string | Yes | Protocol version (currently "1.0") |
| `action` | string | Yes | Human-readable description of the action (max 500 chars) |
| `inputs_hash` | string | Yes | SHA-256 hex digest of the inputs (64 chars) |
| `timestamp` | string | Yes | ISO 8601 timestamp with milliseconds and Z suffix |
| `signature` | string | Yes | Base64url-encoded Ed25519 signature |
| `public_key` | string | Yes | Base64url-encoded Ed25519 public key (32 bytes) |
| `url` | string | No | Public verification URL |
| `metadata` | object | No | Optional key-value metadata |

## Canonical Payload

The signature is computed over a canonical JSON representation. This ensures deterministic signing and verification.

### Canonicalization Rules

1. Include only these fields, in this exact order:
   - `id`
   - `agent`
   - `action`
   - `inputs_hash`
   - `timestamp`
   - `version`
   - `metadata` (if present)

2. Serialize as JSON with:
   - No whitespace
   - Keys sorted alphabetically within objects
   - No trailing newline

### Example

```javascript
// Input attestation
{
  "id": "ts_abc123",
  "agent": "my-agent",
  "action": "Document processed",
  "inputs_hash": "e3b0c44...",
  "timestamp": "2026-02-22T14:23:01.000Z",
  "version": "1.0"
}

// Canonical payload (what gets signed)
{"action":"Document processed","agent":"my-agent","id":"ts_abc123","inputs_hash":"e3b0c44...","timestamp":"2026-02-22T14:23:01.000Z","version":"1.0"}
```

## Signing

### Algorithm

- **Signature scheme:** Ed25519 (RFC 8032)
- **Key size:** 256-bit private key, 256-bit public key
- **Signature size:** 64 bytes

### Process

```
1. Construct canonical payload JSON
2. Encode payload as UTF-8 bytes
3. Sign bytes with Ed25519 private key
4. Encode 64-byte signature as base64url (no padding)
```

### Reference Implementation (JavaScript)

```javascript
import { sign } from '@noble/ed25519';

function signAttestation(attestation, privateKey) {
  const canonical = JSON.stringify({
    action: attestation.action,
    agent: attestation.agent,
    id: attestation.id,
    inputs_hash: attestation.inputs_hash,
    timestamp: attestation.timestamp,
    version: attestation.version,
  });
  
  const payload = new TextEncoder().encode(canonical);
  const signature = sign(payload, privateKey);
  
  return base64url.encode(signature);
}
```

## Verification

### Process

```
1. Fetch attestation from /v1/verify/{id}
2. Reconstruct canonical payload from attestation fields
3. Decode base64url signature and public key
4. Verify Ed25519 signature over canonical payload bytes
5. (Optional) Check public key matches known Treeship keys
```

### Reference Implementation (JavaScript)

```javascript
import { verify } from '@noble/ed25519';

function verifyAttestation(attestation) {
  const canonical = JSON.stringify({
    action: attestation.action,
    agent: attestation.agent,
    id: attestation.id,
    inputs_hash: attestation.inputs_hash,
    timestamp: attestation.timestamp,
    version: attestation.version,
  });
  
  const payload = new TextEncoder().encode(canonical);
  const signature = base64url.decode(attestation.signature);
  const publicKey = base64url.decode(attestation.public_key);
  
  return verify(signature, payload, publicKey);
}
```

### Reference Implementation (Python)

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json
import base64

def verify_attestation(attestation: dict) -> bool:
    canonical = json.dumps({
        "action": attestation["action"],
        "agent": attestation["agent"],
        "id": attestation["id"],
        "inputs_hash": attestation["inputs_hash"],
        "timestamp": attestation["timestamp"],
        "version": attestation["version"],
    }, separators=(",", ":"), sort_keys=True)
    
    payload = canonical.encode("utf-8")
    signature = base64.urlsafe_b64decode(attestation["signature"] + "==")
    public_key_bytes = base64.urlsafe_b64decode(attestation["public_key"] + "==")
    
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
```

## Inputs Hashing

Inputs are hashed client-side to preserve privacy. The hash proves inputs existed without revealing them.

### Process

```
1. Serialize inputs as JSON (sorted keys, no whitespace)
2. Encode as UTF-8 bytes
3. Compute SHA-256 hash
4. Encode as lowercase hex string (64 chars)
```

### Example

```python
import hashlib
import json

def hash_inputs(inputs: dict) -> str:
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

# Example
inputs = {"user_id": "u123", "action": "summarize"}
hash_inputs(inputs)
# → "a1b2c3d4e5f6..."
```

## API Endpoints

### POST /v1/attest

Create a new attestation.

**Request:**
```json
{
  "agent": "my-agent",
  "action": "Document summarized",
  "inputs_hash": "e3b0c44..."
}
```

**Response:**
```json
{
  "id": "ts_abc123",
  "agent": "my-agent",
  "action": "Document summarized",
  "inputs_hash": "e3b0c44...",
  "timestamp": "2026-02-22T14:23:01.000Z",
  "version": "1.0",
  "signature": "...",
  "public_key": "...",
  "url": "https://treeship.dev/verify/ts_abc123"
}
```

### GET /v1/verify/{id}

Retrieve and verify an attestation.

**Response:**
```json
{
  "valid": true,
  "attestation": { ... }
}
```

### GET /v1/pubkey

Get the current signing public key.

**Response:**
```json
{
  "key_id": "treeship_prod_2026",
  "algorithm": "Ed25519",
  "public_key": "base64url(...)",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

## Public Keys

Production public keys are published at:
- `https://api.treeship.dev/v1/pubkey`
- `https://github.com/zerker-ai/treeship/blob/main/protocol/keys.json`

### keys.json Format

```json
{
  "1.0": {
    "production": {
      "key_id": "treeship_prod_2026",
      "public_key": "base64url(...)",
      "effective": "2026-01-01T00:00:00Z"
    },
    "staging": {
      "key_id": "treeship_staging_2026",
      "public_key": "base64url(...)",
      "effective": "2026-01-01T00:00:00Z"
    }
  }
}
```

## Versioning

- Protocol version is included in every attestation (`version` field)
- Current version: `1.0`
- Breaking changes require major version bump and 90-day migration period
- Old versions remain verifiable indefinitely

## Security Considerations

1. **Key Security** — Private keys must be stored securely and never exposed
2. **Timestamp Freshness** — Verifiers should check timestamps are recent
3. **Replay Attacks** — Attestation IDs are unique; verifiers may track seen IDs
4. **Clock Synchronization** — Servers should use NTP for accurate timestamps
