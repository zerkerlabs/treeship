# Treeship Hub

API server for storing, querying, and distributing Treeship attestations.

## What it does

Treeship Hub is a Go service that acts as the central registry for attestation envelopes:

- **~23 REST endpoints** (see `main.go` for the exact, current route list -- device-flow enrollment, artifact push/pull, workspace listing, Merkle checkpoint/proof/consistency, session receipts, ship listing). There is no server-side verification-status endpoint; `/v1/verify/{id}` is retired and returns `410`.
- **DPoP (Demonstration of Proof-of-Possession) authentication** for token-bound requests
- Stores attestation metadata and links to artifact hashes
- Serves this hub's Merkle checkpoint/proof log -- readable by anyone if the hub is public, but a single hub-controlled log, not a federated Certificate-Transparency-style set of independently monitored logs

## Requirements

- Go 1.23+
- No external database -- SQLite, file-backed (`modernc.org/sqlite`)

## Running locally

```sh
cd packages/hub
go run .
```

Configure the database path with `TREESHIP_HUB_DB` (checked first) or `DATABASE_PATH` (what Railway sets); with neither set, it defaults to `/var/lib/treeship/hub.db`. The server starts on `http://localhost:8080` by default (`PORT` env var to change it).

`treeship hub attach` prints a device code. The person types that code on the activate page, and submitting it approves the attach. There is no hub account for this step.

Set `TREESHIP_REKOR_URL` to a Rekor you operate if pushes should be anchored. Leave it unset, or set it to `off`, and anchoring stays off. The hub does not submit to the public Sigstore log unless that variable names it.

## Deploying

Production runs on Railway. Deploy with `scripts/hub-deploy.sh` from the repository root (`RAILWAY_SERVICE=<service id>`); it sets `HUB_VERSION`, `HUB_COMMIT` and `HUB_BUILT_AT` on the service, which the Dockerfile takes as build args, then runs `railway up`. A plain `railway up` has no `.git`, so without those variables `/v1/version` reports `commit: unknown`; with them left from an earlier run it would report that run's commit, which is why the script sets them fresh every time. A deploy from the connected repository takes its commit from `RAILWAY_GIT_COMMIT_SHA` regardless. See `RELEASING.md`.

## API overview

See the full endpoint reference at [docs.treeship.dev/api/overview](https://docs.treeship.dev/api/overview).

## Repository

[github.com/zerkerlabs/treeship](https://github.com/zerkerlabs/treeship)

## License

See [LICENSE](../../LICENSE) in the repository root.
