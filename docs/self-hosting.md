# Self-Hosting Treeship

Run Treeship entirely on your own infrastructure. No external dependencies.

## Why Self-Host?

- **Full data control** — Everything stays on your servers
- **Compliance requirements** — Meet strict regulatory needs
- **No vendor dependency** — If Zerker disappears, you're unaffected
- **Custom retention** — Control how long attestations are stored

## Architecture

```
Your Infrastructure
├── treeship-api         [Signing + storage]
│   ├── Ed25519 keys     [Generated locally]
│   ├── PostgreSQL       [Attestation storage]
│   └── REST API         [/v1/attest, /v1/verify]
├── treeship-sidecar     [Agent bridge - optional]
└── Your agents          [Call API directly or via sidecar]
```

## Quick Start

### 1. Generate Signing Keys

```bash
# Generate new Ed25519 keypair
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Or use the Treeship CLI
treeship-api keygen --output ./keys/
```

### 2. Deploy with Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  treeship-api:
    image: zerker/treeship-api:latest
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/treeship
      - SIGNING_KEY_PATH=/keys/private.pem
      - PUBLIC_KEY_PATH=/keys/public.pem
      - BASE_URL=https://treeship.yourcompany.com
    volumes:
      - ./keys:/keys:ro
    ports:
      - "8000:8000"
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=treeship
      - POSTGRES_PASSWORD=password
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

### 3. Start Services

```bash
docker-compose up -d
```

### 4. Test

```bash
# Create attestation
curl -X POST http://localhost:8000/v1/attest \
  -H "Content-Type: application/json" \
  -d '{"agent_slug": "test", "action": "Test attestation", "inputs_hash": "abc123"}'

# Verify
curl http://localhost:8000/v1/verify/ts_abc123
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `SIGNING_KEY_PATH` | Yes | — | Path to Ed25519 private key |
| `PUBLIC_KEY_PATH` | Yes | — | Path to Ed25519 public key |
| `BASE_URL` | No | http://localhost:8000 | Base URL for verification links |
| `LOG_LEVEL` | No | INFO | Logging level |
| `CORS_ORIGINS` | No | * | Allowed CORS origins |

### Database Schema

The API will auto-create tables on first run. Schema:

```sql
CREATE TABLE agents (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE attestations (
    id VARCHAR(32) PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id),
    action VARCHAR(500) NOT NULL,
    inputs_hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_attestations_agent ON attestations(agent_id);
CREATE INDEX idx_attestations_timestamp ON attestations(timestamp);
```

## Production Deployment

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: treeship-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: treeship-api
  template:
    metadata:
      labels:
        app: treeship-api
    spec:
      containers:
        - name: api
          image: zerker/treeship-api:latest
          ports:
            - containerPort: 8000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: treeship-secrets
                  key: database-url
          volumeMounts:
            - name: signing-keys
              mountPath: /keys
              readOnly: true
      volumes:
        - name: signing-keys
          secret:
            secretName: treeship-signing-keys
```

### Key Security

**Critical:** Protect your private signing key.

- Store in secrets manager (Vault, AWS Secrets Manager, etc.)
- Never commit to git
- Rotate periodically (see Key Rotation below)
- Limit access to production systems only

### Key Rotation

1. Generate new keypair
2. Add new key to `protocol/keys.json` with future effective date
3. Update API to use new key
4. Old attestations remain verifiable with old key
5. After 90 days, remove old key from active rotation

```json
{
  "1.0": {
    "current": {
      "key_id": "selfhosted_2026_02",
      "effective": "2026-02-01T00:00:00Z"
    },
    "previous": {
      "key_id": "selfhosted_2026_01",
      "effective": "2026-01-01T00:00:00Z",
      "deprecated": "2026-02-01T00:00:00Z"
    }
  }
}
```

## Publishing Your Public Key

For external verification, publish your public key:

1. **API endpoint:** Your `/v1/pubkey` returns your key
2. **Documentation:** Include in your API docs
3. **DNS TXT record (optional):** `treeship-pubkey.yourcompany.com`

## Migration from Hosted

To migrate from Treeship hosted to self-hosted:

1. Export your attestation data (contact support@zerker.ai)
2. Import into your PostgreSQL database
3. Update agent configurations to point to your API
4. Old verification URLs will redirect if you contact us

## Troubleshooting

### "Signature verification failed"

- Check that canonical JSON serialization matches exactly
- Verify key encoding (base64url vs base64)
- Ensure timestamp format is ISO 8601 with milliseconds

### "Database connection failed"

- Check DATABASE_URL format
- Verify network connectivity
- Check PostgreSQL logs

### "Key not found"

- Verify key file paths
- Check file permissions (readable by container)
- Ensure PEM format is correct

## Support

For self-hosting support:
- GitHub Issues: https://github.com/zerker-ai/treeship/issues
- Email: support@zerker.ai
