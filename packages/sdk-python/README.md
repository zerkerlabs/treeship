# treeship-sdk

Treeship Python SDK — cryptographic verification for AI agents.

## Installation

```bash
pip install treeship-sdk
```

## Quick Start

```python
from treeship import TreshipClient

client = TreshipClient()  # reads TREESHIP_API_KEY from env

result = client.attest(
    action="User document summarized",
    inputs={"user_id": "u123", "doc": "contract.pdf"}  # hashed, never sent
)

print(result.url)  # https://treeship.dev/verify/ts_abc123
```

## Decorator-Based Usage

For common patterns, use decorators instead of manual attestation:

```python
from treeship import attest_reasoning, attest_memory, attest_performance

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

## Client Methods

### attest()

Create an attestation.

```python
result = client.attest(
    action="Document processed",      # Required: what happened
    inputs={"doc_id": "123"},         # Optional: hashed locally, never sent
    agent="my-agent",                 # Optional: override default agent
    metadata={"version": "1.0"}       # Optional: additional metadata
)

if result.attested:
    print(f"Verified: {result.url}")
else:
    print(f"Failed: {result.error}")
```

### verify()

Verify an attestation.

```python
result = client.verify("ts_abc123")

if result.valid:
    print(f"Valid! Agent: {result.attestation['agent_slug']}")
else:
    print(f"Invalid: {result.error}")
```

### Async Support

```python
import asyncio
from treeship import TreshipClient

async def main():
    client = TreshipClient()
    result = await client.attest_async(
        action="Async operation completed",
        inputs={"task_id": "456"}
    )
    print(result.url)

asyncio.run(main())
```

## Privacy

With default settings, inputs are hashed locally:

| Sent to Treeship | Stays Local |
|-----------------|-------------|
| Action description | Raw inputs |
| SHA-256 hash of inputs | User data |
| Timestamp | Documents |
| Agent slug | API keys |

## Configuration

### Environment Variables

```bash
export TREESHIP_API_KEY="your_api_key"
export TREESHIP_AGENT="my-agent"
export TREESHIP_API_URL="https://api.treeship.dev"  # optional
```

### Client Options

```python
client = TreshipClient(
    api_key="your_api_key",      # or TREESHIP_API_KEY env var
    api_url="https://...",        # optional, for self-hosted
    agent="my-agent",             # default agent slug
    timeout=10.0,                 # request timeout in seconds
    hash_only=True,               # hash inputs locally (default)
)
```

## Error Handling

The SDK never raises exceptions for attestation failures:

```python
result = client.attest(action="Something")

# Always check result.attested
if not result.attested:
    # Attestation failed, but your code continues
    logger.warning(f"Attestation failed: {result.error}")
```

This ensures attestation never blocks your agent's primary work.

## License

MIT
