# Treeship Hub

API server for storing, querying, and distributing Treeship attestations.

## What it does

Treeship Hub is a Go service that acts as the central registry for attestation envelopes:

- **13 REST endpoints** for envelope CRUD, search, and verification status
- **DPoP (Demonstration of Proof-of-Possession) authentication** for token-bound requests
- Stores attestation metadata and links to artifact hashes
- Serves the public transparency log

## Requirements

- Go 1.22+
- PostgreSQL 15+

## Running locally

```sh
cd packages/hub
cp .env.example .env   # configure database URL and secrets
go run ./cmd/server
```

The server starts on `http://localhost:8080` by default.

## API overview

See the full endpoint reference at [docs.treeship.dev/api/overview](https://docs.treeship.dev/api/overview).

## Repository

[github.com/nicholasgriffintn/treeship](https://github.com/nicholasgriffintn/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
