# Treeship Privacy Model

Treeship is designed for privacy-sensitive deployments including healthcare, finance, and legal.

## Default Behavior: Hash-Only Mode

With default settings (`hash_only: true`), Treeship operates in hash-only mode:

```
Your Infrastructure                    Treeship
┌─────────────────────────┐            ┌─────────────────────────┐
│ Agent                   │            │                         │
│  ├── user data          │            │ Receives:               │
│  ├── documents          │  ──────►   │  - action string        │
│  ├── API responses      │            │  - SHA-256 hash         │
│  └── PII                │            │  - timestamp            │
│                         │            │  - agent identifier     │
│ SHA-256 hash computed   │            │                         │
│ locally before sending  │            │ NEVER receives:         │
│                         │            │  - raw content          │
└─────────────────────────┘            │  - user data            │
                                       │  - documents            │
                                       └─────────────────────────┘
```

## What Gets Sent

| Data | Sent | Description |
|------|------|-------------|
| Action | ✓ | Human-readable description you provide |
| Inputs hash | ✓ | SHA-256 of serialized inputs |
| Timestamp | ✓ | When attestation was created |
| Agent slug | ✓ | Identifier for your agent |
| Metadata | ✓ | Optional key-value pairs you add |
| Raw inputs | ✗ | Never sent with hash_only=true |
| Documents | ✗ | Never sent |
| User data | ✗ | Never sent |

## Hashing Process

Inputs are hashed deterministically:

```python
import hashlib
import json

def hash_inputs(inputs: dict) -> str:
    # 1. Serialize with sorted keys (deterministic)
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    
    # 2. Hash with SHA-256
    return hashlib.sha256(canonical.encode()).hexdigest()

# Example
inputs = {"user_id": "u123", "document": "sensitive content here"}
hash_inputs(inputs)
# → "a1b2c3d4e5f6..." (64-char hex string)
```

The hash is collision-resistant: different inputs produce different hashes, but you cannot reverse-engineer the original content from the hash.

## Action String Guidelines

The action string IS sent to Treeship. Follow these guidelines:

### Good Actions (Privacy-Preserving)

```
"User document processed"
"Loan application evaluated"
"Email sent to customer"
"Contract analyzed: 15 pages"
```

### Bad Actions (Privacy-Leaking)

```
"Processed document for john.doe@email.com"  # Contains PII
"Loan for $50,000 approved"                   # Contains financial details
"Sent email about divorce proceedings"        # Contains sensitive context
```

**Rule:** Treat action strings as if they were public. Include enough context to be useful, but no PII or sensitive details.

## Metadata Guidelines

Metadata key-value pairs ARE sent to Treeship:

### Good Metadata

```python
{
    "document_type": "contract",
    "page_count": 15,
    "processing_time_ms": 250,
    "decision": "approved"
}
```

### Bad Metadata

```python
{
    "user_email": "john@example.com",  # PII
    "ssn": "123-45-6789",              # Sensitive
    "api_key": "sk_..."                # Secret
}
```

## Audit Trail Without Content

Treeship provides an audit trail that proves:

1. **What happened** — Action description
2. **When it happened** — Timestamp
3. **What was processed** — Hash of inputs
4. **Who did it** — Agent identifier
5. **It hasn't been tampered** — Ed25519 signature

Without revealing:

1. The actual content processed
2. User identities
3. Sensitive business data
4. API keys or credentials

## Self-Hosted: Full Control

For maximum privacy, [self-host Treeship](self-hosting.md):

- Signing keys never leave your infrastructure
- All data stays on your servers
- You control retention and access
- Same verification interface

## Compliance Considerations

### HIPAA (Healthcare)

- PHI should only appear in hashed inputs, never in action strings
- Consider self-hosting for full control
- Document your attestation practices in your compliance documentation

### GDPR (EU Privacy)

- Hashes of personal data may still be considered personal data
- Action strings should not contain PII
- Consider data retention policies for attestations
- Self-hosting may simplify compliance

### SOC 2 / Financial

- Treeship provides audit trail requirements
- Document what is and isn't attested
- Consider self-hosting for Type II requirements

## Technical Security

- **TLS:** All API communication over HTTPS
- **Ed25519:** Industry-standard signature algorithm
- **No storage of content:** Only hashes stored
- **Independent verification:** Don't trust Treeship? Verify yourself.

## Questions?

Contact security@zerker.ai for privacy-related inquiries.
