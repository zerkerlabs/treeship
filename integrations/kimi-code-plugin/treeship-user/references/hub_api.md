# Treeship Hub API Reference

## Overview

The Hub API provides optional infrastructure for artifact storage, shareable verification URLs, and transparency log anchoring. Artifact validity never depends on the Hub — signatures are the trust.

**Base URL:** `https://api.treeship.dev/v1/`

**What Hub provides:**
1. Artifact storage for signed envelopes pushed from local Treeships
2. Shareable verification URLs at `treeship.dev/verify/{artifact_id}`
3. Transparency log anchoring via Sigstore Rekor

Hub does not sign, modify, or interpret artifacts. It stores and serves DSSE envelopes created locally.

## Authentication

Hub uses **DPoP** (Demonstration of Proof-of-Possession) for write endpoints. No API keys, session tokens, or bearer tokens.

Authenticated requests require two headers:

| Header | Value |
|--------|-------|
| `Authorization` | `DPoP {hub_id}` |
| `DPoP` | A fresh JWT signed by the hub private key |

The DPoP JWT payload:

```json
{
  "iat": 1711500000,
  "jti": "unique-random-hex-32-chars",
  "htm": "POST",
  "htu": "https://api.treeship.dev/v1/artifacts"
}
```

Hub verifies:
- `iat` is within 60 seconds of current time
- `jti` has not been seen before (replay protection)
- Signature matches the hub public key

The Python SDK and CLI handle DPoP signing automatically via `treeship session report` and `treeship hub push`.

## Endpoints

### `POST /v1/artifacts`

Push a signed artifact to the Hub.

**Auth:** DPoP required

**Request body:**
```json
{
  "artifact_id": "art_f7e6d5c4b3a2",
  "envelope": {
    "payloadType": "application/vnd.treeship.receipt+json",
    "payload": "base64-encoded-payload",
    "signatures": [
      {
        "keyid": "key_9f8e7d6c",
        "sig": "base64-signature"
      }
    ]
  }
}
```

**Response:**
```json
{
  "artifact_id": "art_f7e6d5c4b3a2",
  "verify_url": "https://treeship.dev/verify/art_f7e6d5c4b3a2",
  "rekor_index": 1234567
}
```

### `GET /v1/artifacts/:id`

Retrieve a stored artifact envelope.

**Auth:** None required

**Response:** The DSSE envelope as stored.

### `GET /v1/verify/:id`

Public verification endpoint. Returns verification result without auth.

**Auth:** None required

**Response:**
```json
{
  "artifact_id": "art_f7e6d5c4b3a2",
  "valid": true,
  "actor": "agent://my-agent",
  "action": "tool.call",
  "signed_at": "2025-08-05T14:22:11Z",
  "key_id": "key_9f8e7d6c",
  "chain_length": 4,
  "signature_valid": true,
  "chain_valid": true
}
```

### `PUT /v1/receipt/{session_id}`

Upload a session receipt package.

**Auth:** DPoP required

The session receipt is a bundled package containing all artifacts from a session, uploaded by the CLI's `treeship session report` command.

**Response:**
```json
{
  "session_id": "ssn_42e740bd9eb238f6",
  "receipt_url": "https://treeship.dev/receipt/ssn_42e740bd9eb238f6",
  "agents": ["agent://researcher", "agent://writer"],
  "events": 12
}
```

### `GET /v1/receipt/{session_id}`

Fetch a session receipt. Public — no auth required.

**Auth:** None required

**Response:** Session receipt with full artifact chain and verification results.

### `GET /v1/ship/agents`

List all agents registered to this ship.

**Auth:** DPoP required

**Response:**
```json
{
  "agents": [
    {
      "slug": "my-agent",
      "actor_uri": "agent://my-agent",
      "first_seen": "2025-08-01T10:00:00Z",
      "attestation_count": 42
    }
  ]
}
```

### `GET /v1/ship/sessions`

List all sessions for this ship.

**Auth:** DPoP required

### `GET /v1/merkle/:artifactId`

Get Merkle inclusion proof for an artifact.

**Auth:** None required

**Response:**
```json
{
  "artifact_id": "art_f7e6d5c4b3a2",
  "merkle_root": "sha256:abc123...",
  "proof": ["sha256:def456...", "sha256:ghi789..."],
  "checkpoint": "sha256:chk001..."
}
```

### `GET /v1/hub/challenge`

Get a challenge for hub authorization flow.

**Auth:** None

### `POST /v1/hub/authorize`

Authorize a ship to connect to a hub workspace.

**Auth:** DPoP required

## Public Verification URLs

These URLs work without authentication and are designed for sharing:

| URL | Purpose |
|-----|---------|
| `https://treeship.dev/verify/{artifact_id}` | Verify single artifact with client-side WASM verifier |
| `https://treeship.dev/receipt/{session_id}` | View full session receipt |
| `https://treeship.dev/api/badge/{agent}` | SVG badge showing attestation count |

## Error Format

All errors follow this structure:

```json
{
  "error": {
    "code": "invalid_dpop",
    "message": "DPoP token expired or replayed",
    "status": 401
  }
}
```

Common error codes:

| Code | Status | Meaning |
|------|--------|---------|
| `invalid_dpop` | 401 | DPoP token invalid, expired, or replayed |
| `artifact_not_found` | 404 | Artifact ID does not exist |
| `hub_not_connected` | 403 | Ship not authorized for this hub |
| `rate_limited` | 429 | Too many requests |
| `rekor_unavailable` | 503 | Transparency log anchoring failed |

## Direct API Usage Example

For users who want to call the API directly without the SDK:

```bash
# Create an attestation via API
curl -X POST https://api.treeship.dev/v1/attest \
  -H "Authorization: Bearer $TREESHIP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_slug": "my-agent",
    "action": "Deployed main branch to production",
    "inputs_hash": "'$(git rev-parse HEAD)'",
    "metadata": {
      "commit": "'$(git rev-parse HEAD)'",
      "branch": "'$(git branch --show-current)'"
    }
  }'
```

```python
import requests
import os

# Verify an artifact publicly (no auth needed)
response = requests.get(f"https://api.treeship.dev/v1/verify/{artifact_id}")
result = response.json()
if result["valid"]:
    print(f"Verified: {result['actor']} performed {result['action']}")
```

## WebSocket Endpoints

The Hub supports WebSocket connections for real-time attestation streaming:

```
wss://api.treeship.dev/v1/stream/{agent_slug}
```

Subscribe to receive new attestations as they are pushed for a given agent.
