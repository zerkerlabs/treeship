# Treeship Hub API Reference

This file used to hand-derive the Hub's routes, and drifted badly: it
invented a `POST /v1/attest` endpoint, a `wss://.../v1/stream/{agent_slug}`
websocket, `GET /v1/hub/challenge` / `POST /v1/hub/authorize`, an
`Authorization: Bearer $TREESHIP_API_KEY` scheme, and a JSON verdict from
`GET /v1/verify/:id` -- **none of which exist**. For the current, generated
route-by-route reference, read:

- `docs/content/docs/api/overview.mdx` (base URL, auth, error format)
- The per-route pages under `docs/content/docs/api/` (one per route --
  `artifacts-push.mdx`, `artifacts-get.mdx`, `dock-challenge.mdx`,
  `dock-authorize.mdx`, `dock-authorized.mdx`, `receipt-put.mdx`,
  `receipt-get.mdx`, `verify.mdx`, `merkle-checkpoint.mdx`,
  `merkle-proof.mdx`, `merkle-consistency.mdx`, `workspace.mdx`,
  `ship-registry.mdx`, `revoked.mdx`, `stats.mdx`, `agents.mdx`)
- `packages/hub/main.go` for the literal route table

## What's true regardless of the exact route list

- **Base URL:** `https://api.treeship.dev`. Everything is under `/v1/`.
- **Auth:** DPoP (RFC 9449) for writes -- the client proves possession of a
  private key per request. There is no API key and no bearer token.
  Enrollment (`treeship hub attach`) is a separate device-style flow
  (`/v1/dock/challenge`, `/v1/dock/authorize`, `/v1/dock/authorized`); it is
  not the same thing as per-request DPoP.
- **`GET /v1/verify/:id` is retired.** It returns `410 Gone` with
  `{"outcome": "retired", ...}` on purpose -- the hub never re-derives a
  verdict server-side. It is transport and index only; verify locally
  against your own pinned roots (`treeship verify`, `package verify`,
  `@treeship/core-wasm`).
- **Two endpoints answer for anyone and take no id**, useful to confirm the
  hub is up: `GET /v1/merkle/checkpoint/latest` and `GET /v1/dock/challenge`.
- **No websockets, no streaming subscription API.** Nothing pushes
  attestations to a client in real time.
- **Public receipt/verify URLs:**
  - `https://treeship.dev/receipt/{session_id}` -- a session report,
    from `treeship session report`
  - `https://treeship.dev/verify/{artifact_id}` -- a single artifact push,
    from `treeship hub push`
  - There is no `https://treeship.dev/api/badge/{agent}`.

## CLI and SDK cover this for you

You will rarely call these routes directly. `treeship session report`,
`treeship hub push`, `treeship hub pull`, `treeship hub attach` and
`treeship merkle proof/publish` (and the Python/TypeScript SDK's `hub_push`
/ `s.hub.push`) already do the DPoP signing and the request shape correctly
-- that's the layer to script against, not raw `curl`.
