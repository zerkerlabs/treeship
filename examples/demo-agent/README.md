# Treeship Demo Agent

A simple AI agent with built-in Treeship verification. Deploy it to see verification in action.

## What it does

This demo agent processes "loan applications" and creates verifiable attestations for each decision. It's designed to show how Treeship verification works in practice.

## Quick Start

### 1. Get your API key

```bash
# Visit https://treeship.dev and get an API key
export TREESHIP_API_KEY=ts_live_...
```

### 2. Run locally

```bash
pip install -r requirements.txt
python agent.py
```

### 3. Test it

```bash
curl http://localhost:8000/process \
  -H "Content-Type: application/json" \
  -d '{"applicant": "John Doe", "amount": 50000, "credit_score": 720}'
```

Response:
```json
{
  "decision": "approved",
  "amount": 50000,
  "verification_url": "https://treeship.dev/verify/demo-loan-agent/abc123"
}
```

## Deploy

### Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/treeship-demo)

Set `TREESHIP_API_KEY` in your environment variables.

### Docker

```bash
docker build -t treeship-demo-agent .
docker run -p 8000:8000 -e TREESHIP_API_KEY=ts_live_... treeship-demo-agent
```

### Render

1. Fork this repo
2. Connect to Render
3. Add `TREESHIP_API_KEY` env var
4. Deploy

## Verification Page

After processing applications, view all decisions at:

```
https://treeship.dev/verify/demo-loan-agent
```

Each decision is:
- Timestamped
- Cryptographically signed
- Independently verifiable

## Customizing

Edit `agent.py` to change:
- Agent name (`AGENT_NAME`)
- Decision logic (`process_application`)
- What gets attested

## Learn More

- [Treeship Docs](https://docs.treeship.dev)
- [Python SDK](https://pypi.org/project/treeship-sdk/)
- [Self-hosting](https://docs.treeship.dev/guides/self-hosting)
