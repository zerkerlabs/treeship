# Treeship Sidecar

Universal verification bridge for AI agents. Runs alongside any agent in Docker.

## Quick Start

```bash
docker run -d \
  -e TREESHIP_API_KEY=your_api_key \
  -e TREESHIP_AGENT=my-agent \
  -p 2019:2019 \
  zerker/treeship-sidecar:latest
```

Your agent calls `http://localhost:2019/attest` — that's it.

## Docker Compose

```yaml
services:
  agent:
    image: your-agent:latest
    depends_on:
      treeship-sidecar:
        condition: service_healthy

  treeship-sidecar:
    image: zerker/treeship-sidecar:latest
    environment:
      - TREESHIP_API_KEY=${TREESHIP_API_KEY}
      - TREESHIP_AGENT=my-agent
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:2019/health"]
      interval: 10s
      timeout: 5s
      retries: 5
```

## API

### POST /attest

Create an attestation.

```bash
curl -X POST http://localhost:2019/attest \
  -H "Content-Type: application/json" \
  -d '{"action": "Document processed", "inputs": {"doc_id": "123"}}'
```

Response:
```json
{
  "attested": true,
  "url": "https://treeship.dev/verify/ts_abc123",
  "id": "ts_abc123",
  "agent": "my-agent",
  "timestamp": "2026-02-22T14:23:01Z"
}
```

### GET /health

Health check for Docker/Kubernetes.

```bash
curl http://localhost:2019/health
```

### MCP Endpoint

If your framework supports MCP (Model Context Protocol), the sidecar exposes:

```
GET http://localhost:2019/mcp
```

The `treeship_attest` tool is available to MCP-compatible agents.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TREESHIP_API_KEY` | Yes | — | Your Treeship API key |
| `TREESHIP_AGENT` | Yes | — | Agent slug for verification pages |
| `TREESHIP_API_URL` | No | https://api.treeship.dev | API URL (for self-hosted) |
| `TREESHIP_HASH_ONLY` | No | true | Hash inputs locally (privacy mode) |
| `TREESHIP_TIMEOUT` | No | 10 | API timeout in seconds |
| `TREESHIP_LOG_LEVEL` | No | warning | Log level |
| `PORT` | No | 2019 | Server port |

## Privacy

With `TREESHIP_HASH_ONLY=true` (default):

| Sent to Treeship | Stays in Sidecar |
|-----------------|------------------|
| Action description | Raw inputs |
| SHA-256 hash of inputs | Documents |
| Timestamp | Personal data |
| Agent slug | API keys |

The sidecar hashes your inputs locally. Raw content never leaves your infrastructure.

## Building

```bash
docker build -t treeship-sidecar .
```

## License

MIT
