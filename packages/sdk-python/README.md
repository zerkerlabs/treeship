# treeship-sdk

Treeship Python SDK — cryptographic verification for AI agents.

## Installation

```bash
pip install treeship-sdk
```

## Quick Start

```python
from treeship_sdk import Treeship

ts = Treeship()  # reads TREESHIP_API_KEY, TREESHIP_AGENT from env

result = ts.attest(
    action="User document summarized",
    inputs_hash=ts.hash({"user_id": "u123", "doc": "contract.pdf"})
)

print(result.url)  # https://treeship.dev/verify/my-agent/abc123
```

## Decorator-Based Usage (v0.2.0+)

For common patterns, use decorators instead of manual attestation:

```python
from treeship_sdk import attest_reasoning, attest_memory, attest_performance

@attest_reasoning
def make_decision(context: dict) -> dict:
    """Automatically attests the decision and reasoning."""
    reasoning = f"User qualifies because score={context['score']} > 700"
    return {"decision": "approved", "reasoning": reasoning}

@attest_memory
def save_preferences(user_id: str, prefs: dict):
    """Automatically attests state changes."""
    db.save(user_id, prefs)
    return {"saved": True}

@attest_performance(threshold_ms=1000)
def process_document(doc: str) -> dict:
    """Only attests if execution takes >1s."""
    # ... expensive processing ...
    return {"summary": "..."}
```

## API

### Treeship

```python
ts = Treeship(
    api_key='your_key',        # or TREESHIP_API_KEY env
    agent='my-agent',          # or TREESHIP_AGENT env
    api_url='https://...',     # optional, for self-hosted
)
```

### ts.attest()

Create an attestation.

```python
result = ts.attest(
    action="User request processed",  # required
    inputs_hash=ts.hash(data),        # optional, hashes data locally
    agent="custom-agent",             # optional, overrides default
    metadata={"version": "1.0"},      # optional
)

print(result.url)           # verification URL
print(result.attestation_id)  # attestation ID
print(result.signature)     # Ed25519 signature
```

### ts.hash()

Hash any data for use as inputs_hash.

```python
# Dict
hash1 = ts.hash({"user_id": "123", "action": "summarize"})

# String
hash2 = ts.hash("some content")

# Bytes
hash3 = ts.hash(b"binary data")
```

### ts.verify()

Verify an attestation.

```python
result = ts.verify("abc123-def456")
print(result["valid"])  # True/False
```

### Async Support

```python
from treeship_sdk import AsyncTreeship

async with AsyncTreeship() as ts:
    result = await ts.attest(
        action="Async task completed",
        inputs_hash=ts.hash({"task_id": "456"})
    )
    print(result.url)
```

## Privacy

Inputs are hashed locally with SHA-256. Raw content never leaves your server.

| Sent to Treeship | Stays Local |
|-----------------|-------------|
| Action description | Raw inputs |
| SHA-256 hash | User data |
| Timestamp | Documents |
| Agent slug | API keys |

## Environment Variables

```bash
export TREESHIP_API_KEY="your_key"
export TREESHIP_AGENT="my-agent"
export TREESHIP_API_URL="https://api.treeship.dev"  # optional
```

## License

MIT
