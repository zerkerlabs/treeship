# Local Dashboard — design

**Status:** working markdown, not committed
**Last updated:** 2026-05-25

## Short version

A Hermes-style "local dashboard opens in browser" should be treated as a view over an append-only local event/receipt store, not as the source of truth. For Treeship, the equivalent source of truth is the **Session Receipt**: canonical JSON, Merkle-rooted, independently verifiable, portable, shareable. The dashboard is a projection of that receipt, plus optional live local state while a session is still active.

Product rule:

> Hermes dashboard answers "what is the agent doing right now?" Treeship dashboard answers "what happened, why was it allowed, what changed, and can anyone verify it from the receipt?"

The dashboard may include an operator console, but it should be receipt-native first. Live runtime views are convenience projections. The durable product is the receipt-native control plane.

## The receipt inversion (what makes Treeship different from Hermes)

Hermes verified architecture (from their docs):
- `hermes dashboard` opens `http://127.0.0.1:9119`
- FastAPI/Uvicorn backend + React 19 frontend
- "The dashboard runs entirely on your machine — no data leaves localhost"
- No auth; localhost is the trust boundary; `--insecure` to expose
- 5-second polling for status/logs; WebSocket+xterm.js for PTY-mirrored chat
- Three-layer plugin model: themes (YAML), UI plugins (manifest.json + IIFE JS bundle, no build step), backend plugins (Python + FastAPI router)
- Drop-in `~/.hermes/plugins/`; `window.__HERMES_PLUGIN_SDK__` exposes React, shadcn/ui components, typed API client, slot registration

Six things match what Treeship should do: localhost-only server, no auth, mix of WebSocket and polling, TUI mirrored into the browser, drop-in plugins, config in files (not UI defaults).

One thing **must differ**:

| Hermes | Treeship |
|---|---|
| Source of truth = running agent process | Source of truth = signed Session Receipt |
| Dashboard reads live state from the agent loop | Dashboard reads from `~/.treeship/sessions/` and `receipt.json` |
| Trust = "the agent on this machine" | Trust = Ed25519 signature + Merkle root + verification chain |
| Config-editable from UI (form editor for 150+ settings) | Read-only by default; CLI/SDK is the only write path |
| Account-less because localhost is the boundary | Account-less because receipts are self-verifying |

Hermes's local-only model is a **deployment choice**. Treeship's local-first model is a **trust model**. Same browser-on-localhost architecture serves both, but the implications differ. Hermes can add cloud sync if it wants. Treeship can't, because the receipt's portability is the whole point.

## Projection model

Do not build "logs with a nice UI." Build from receipts and derive the UI:

| Surface | Source |
|---|---|
| Receipt feed | `receipt.json`, artifact records, package index |
| Timeline | `receipt.timeline` |
| Agent graph | `receipt.agent_graph` |
| Side effects | `receipt.side_effects` |
| Approval queue | live pending approvals, then approval artifacts in the sealed receipt |
| Trust posture | verifier checks, not display parsing |
| Public proof page | same receipt renderer, fetched from Hub or local package |

The receipt or artifact is the source of truth. Feed, graph, approval state, trust posture, and proof pages are projections.

## What Treeship already has

| Primitive | Where | Role for the dashboard |
|---|---|---|
| `treeship ui` (Ratatui TUI) | `packages/cli/src/tui/` | Existing terminal dashboard, reads local store, shows session state, recent artifacts, pending approvals, hub status. 2s refresh loop. Shares its backend with the web SPA. |
| Session events | `~/.treeship/sessions/<id>/events.jsonl` | Append-only log. Live-mode data source. |
| Receipt composition | Triggered on `treeship session close` | Composes `receipt.json` from events + artifact chain + agent graph. Builds a `.treeship` package with Merkle data, proofs, render hints, and preview.html. |
| `preview.html` | Inside every `.treeship` package | Static, self-contained HTML view of the receipt. Already produced. The dashboard becomes this file served from localhost + a small verifier bundle. |
| `render.json` | Inside every `.treeship` package | Layout hints for `preview.html`. Reused by the web dashboard. |
| `treeship daemon` | `packages/cli/src/commands/daemon.rs` | Long-lived local process. Already watches files, emits events, processes ZK proof queue. Natural home for the HTTP API. |
| Receipt verifier | `packages/cli/src/commands/verify_external.rs`, WASM mirror | Computes Merkle root, checks signatures, validates inclusion proofs, asserts timeline ordering. The trust panel reads from this. |
| Hub receipt URLs | `treeship.dev/receipt/<id>` (human) → `api.treeship.dev/v1/receipt/<id>` (raw JSON) | Public, unauthenticated, permanent. The universal deep link to any shared session. |

## Two modes

The dashboard is fundamentally two different views, and the UI should make the distinction visible.

### Live mode (session is still open)

- Localhost server reads `~/.treeship/sessions/<active_id>/events.jsonl`
- New events streamed via SSE or WebSocket as the file grows
- Local artifacts read from `~/.treeship/artifacts/` on demand
- Trust panel labeled `LIVE — not yet sealed`. Verification checks that can run on partial state are shown (signature counts, partial Merkle, etc.); checks that require seal (Merkle root match, final inclusion-proof count, timeline ordering across all entries) are shown as `pending close`.
- Clearly labels evidence as in-progress

### Sealed mode (session has been closed)

- Loads `receipt.json` from `~/.treeship/sessions/<id>/<id>.treeship/`
- Runs the verifier in full:
  - receipt parses
  - canonical bytes match (determinism)
  - Merkle root recomputes
  - all inclusion proofs valid
  - leaf count matches artifact count
  - timeline ordering valid
  - signature(s) valid against trust roots
- Renders all views from the receipt only (timeline, agent graph, side effects, artifacts/proofs)
- This is the mode that also works on a remote receipt URL — fetch the JSON from `api.treeship.dev/v1/receipt/<id>`, verify client-side via WASM, render

The toggle between modes is automatic: dashboard knows which mode it's in by looking at whether the session is active (has an unclosed events.jsonl) or closed (has a `.treeship/receipt.json`).

## v0 strategy: promote `preview.html`

The `.treeship` package already produces a self-contained `preview.html` that renders the receipt. The v0 dashboard is **that file served from localhost**, plus a small client-side verifier bundle that runs on load.

```
treeship dashboard open [session_id]
```

Implementation shape:

```
.treeship/sessions/ssn_xxx.treeship/
  receipt.json          authoritative data
  render.json           layout hints
  preview.html          static local UI
  proofs/               inclusion proofs

http://127.0.0.1:<port>/session/ssn_xxx
  serves the package files + verifier bundle
```

Why this beats building a new SPA:
- The artifact already exists and is generated on every `session close`
- Same HTML is used locally, by Hub for public receipt pages, and in shared links
- No framework, no build step, no `node_modules`
- Survives any UI redesign because the data shape is what matters

The dashboard becomes a thin orchestrator: routing, file serving, the verifier bundle, the live-mode event streaming. Not a UI rewrite.

## Trust panel as first-class

The dashboard's reason to exist: answer "can I trust this receipt?" in one glance.

Top-level verdict block on every session detail page:

```
Trust
  ✓ receipt parses
  ✓ deterministic bytes
  ✓ Merkle root matches
  ✓ 42/42 artifacts included
  ✓ timeline ordering valid
  ⚠ 0 malformed events skipped
```

Failure mode: any check fails → the receipt's status visibly downgrades. The receipt's name in the sidebar gets a red dot. The detail header shows the failure prominently. The user doesn't have to dig.

The verifier already produces these checks. The dashboard just renders them.

Important boundary: display parsing can be forgiving, but trust logic cannot. The current TUI decodes payloads for human-friendly display and can fall back when fields are missing or malformed. That behavior is fine for an operator panel. The browser dashboard's trust posture must call the verifier path and render its results directly.

Trust language should be precise:

| Signal | Meaning |
|---|---|
| Stored by Hub | Hub has a copy or index row |
| Verified locally | Local verifier passed the receipt or artifact checks |
| Signature valid | DSSE signature verifies against the expected key material |
| Chain complete | Parent links and referenced artifacts are present |
| Merkle proof valid | Included leaf recomputes to the stored root |
| Approval binding satisfied | Approval nonce and target action match |
| Unsealed | Live state exists, but no final receipt has been closed |
| Unattested | A visible event/action has no corresponding artifact or receipt evidence |

Never render "trusted because Hub says so." Hub can make data easy to find. It cannot make data trustworthy.

## Hub as index, never trust root

Hub stores receipts and serves them via two endpoints:

- `treeship.dev/receipt/<session_id>` — human page; fetches raw JSON, verifies client-side, renders
- `api.treeship.dev/v1/receipt/<session_id>` — raw JSON, unauthenticated, permanent

Hub indexes (recent sessions, agents seen, last activity, session status, receipt URL) are useful for **navigation**. They are not authoritative for **trust**.

When a user opens a session detail page, the dashboard fetches the receipt and renders from the receipt. Hub's session row is a pointer, not a record.

This means the same dashboard works in three places without changing the trust model:

1. **Locally** — read receipt from `~/.treeship/sessions/<id>/`
2. **Hub** — fetch receipt from `api.treeship.dev/v1/receipt/<id>`, verify client-side, render
3. **Shared link** — same as Hub mode; receive URL, fetch raw JSON, verify, render

## What "view from just the receipt" should mean

A receipt-only dashboard works with no account, no database, no Hub trust. Given only:

```
https://treeship.dev/receipt/ssn_xxx
```

or:

```
receipt.json
```

The dashboard renders:

**Overview** — session_id, name, status, start/end timestamps, duration, ship_id, token totals, high-level narrative. All from the `session` block.

**Agent graph** — root agent, spawned subagents, handoffs, returns, collaboration edges, max depth, final output agent. All from the `agent_graph` block (nodes + edges with edge types: parent-child, handoff, collaboration, return).

**Timeline** — every event with sequence number, timestamp, event_id, event_type, agent_instance_id, agent_name, host_id, summary. Session, agent, tool, file, network, port, and process events.

**Side effects** — files read/written, ports opened, network connections, processes, tool invocations. The `side_effects` block is a convenience index over the timeline, grouped by kind, with back-references to the agent that performed each.

**Artifacts and proofs** — artifact_ids, payload_types, digests, signed timestamps, Merkle inclusion proof status. Merkle tree built over content-addressed artifact_ids; anyone can recompute and check the stored root.

## Recommended v1 dashboard shape

### Default home: Receipt Feed

Each row is a receipt or artifact projection:

- id
- type
- actor
- action
- timestamp
- parent
- verification status
- Hub URL
- Rekor or Merkle badge
- approval-required, approved, denied, failed, or unattested badges

### Detail page: Artifact/Receipt Inspector

For a selected `art_...` or `ssn_...`:

- canonical JSON
- decoded statement
- signature details
- chain position
- parent and children
- verification checks
- Hub or public URL
- proof bundle export action

This extends the current TUI artifact detail surface, but uses verifier output for trust posture.

### Provenance Graph

Build graph edges from:

- artifact `parentId`
- approval/action nonce links
- session `agent_graph`
- session timeline
- handoff artifacts

### Approval Queue

The browser version should show:

- risk label
- actor
- command or tool request
- affected files and resources
- previous approvals
- policy badge
- approve or deny action that creates its own signed artifact

### Trust Posture View

The trust posture should be loud and binary:

- chain complete
- signature valid
- Merkle inclusion valid
- deterministic receipt round-trip valid
- broken parent link
- signature mismatch
- modified receipt
- unsealed live session
- out-of-band action

## Three-piece architecture

```
Local agent / session
  → events.jsonl while active
  → artifacts in .treeship/artifacts
  → session close
  → receipt.json + proofs + preview.html
  → optional hub upload

Browser dashboard
  live mode:
    localhost server reads events.jsonl + local artifacts
    labels view as unsealed
  sealed mode:
    reads receipt.json only
    runs verifier
    renders timeline, graph, effects, proofs

Hub control plane
  indexes sessions and agents from uploaded receipts
  serves raw receipt JSON
  renders public receipt page from receipt JSON
  never becomes the trust root
```

## CLI surface

```
treeship dashboard open [session_id]   # active session if omitted
treeship dashboard list                # recent sessions, formatted for terminal
treeship dashboard verify <receipt-url-or-path>   # run the verifier, output trust panel
```

Each maps to existing primitives. `open` launches the daemon's HTTP server if not running, serves `preview.html` + verifier bundle, opens the browser. `list` reads `~/.treeship/sessions/` index. `verify` runs the WASM verifier against a remote URL or local file.

## Hermes-style plugin model (out of v0, named here)

Treeship can adopt Hermes's plugin pattern when there's a real need. The shape:

- **Themes** — YAML files in `~/.treeship/themes/` that repaint palette, typography, layout
- **UI plugins** — `~/.treeship/plugins/<name>/manifest.json` + IIFE JS bundle (no build step)
- **Backend plugins** — Rust trait that plugins implement, dynamically loaded at daemon startup (or, simpler: subprocess plugins that the daemon proxies to)
- **Plugin SDK** at `window.__TREESHIP_PLUGIN_SDK__` exposing typed API client, slot registration, helper components

Explicitly out of v0. The pattern is recorded so contributors don't reinvent it later.

## What's explicitly NOT v0

- Remote / cloud-hosted dashboard (the Hub dashboard is its own product)
- Multi-user / RBAC (single-user local tool)
- Editing trust roots, certs, or workflows from the UI (UI is observational; CLI/SDK is the write path)
- Alerting / notifications / email (separate scope)
- Mobile / PWA (desktop browser only)
- Public exposure (binds 127.0.0.1; refuses non-localhost connections)
- Telemetry / usage tracking (local-only ethos)
- Plugin system (named above as roadmap)
- Receipt diffing (good idea; later release)
- Policy overlays (undeclared tool use, suspicious network, file write outside workspace, missing approvals — derivable from the receipt but not v0)

## Implementation phases

**Phase 1 — sealed mode against preview.html (~2 days)**

- New daemon HTTP route: `GET /session/<id>` serves `preview.html` for the requested session's package
- `GET /api/receipt/<id>` returns the raw `receipt.json`
- `GET /api/verify/<id>` runs the verifier and returns the trust-panel JSON
- New CLI: `treeship dashboard open [session_id]` starts daemon if needed, opens browser
- Verifier bundle: client-side WASM call to `verify_receipt` that produces the trust panel rows
- Default home: receipt feed over closed local packages
- Detail route: artifact/receipt inspector backed by canonical JSON and verifier checks

**Phase 2 — live mode (~3 days)**

- `events.jsonl` is tailed; new lines emit SSE events to the browser
- "Unsealed" badge on the trust panel
- Verification checks that can run on partial state are shown; full-seal checks marked `pending close`
- Browser auto-switches to sealed mode when the package directory appears
- Approval queue mirrors current TUI state and creates signed approval/denial artifacts for control actions

**Phase 3 — receipt URL deep links (~1 day)**

- `treeship dashboard verify <url>` works on remote URLs
- Browser receives a `?receipt=<url>` query param, fetches, verifies, renders
- Same UI as local sealed mode
- Hub verification is displayed as a convenience signal only; local/WASM verification remains the trust source

**Phase 4 — Hub-side preview page (~separate scope)**

- `treeship.dev/receipt/<id>` server-renders the same `preview.html` with the fetched receipt
- Client-side verifier runs after load
- Same UI as the local dashboard

After all four phases, the same `preview.html` renders the receipt in three contexts: locally, on shared URLs, on Hub. One UI, three deployment surfaces, one trust model.

## Open questions

**Q1: Does `treeship daemon` host the dashboard HTTP, or a separate `treeship dashboard-server` process?**

Recommendation: extend `treeship daemon`. It already runs a 2s file-watcher loop (the natural slot for an SSE pump). Two processes mean two `flock` contenders on `events.jsonl.lock` and two PIDs. Single process wins.

**Q2: TUI keep its 2s poll, or refactor to share the SSE pipeline?**

Recommendation: keep the TUI on 2s poll. It shares the process with the daemon; there's no socket to push over. Refactoring to use an internal channel is a needless rewrite.

**Q3: How does the dashboard discover the daemon's port?**

Recommendation: `~/.treeship/daemon.port` file written on daemon startup. CLI reads it. No discovery beacons, no `--port` flag required (configurable for advanced cases).

**Q4: What does v0 do if no session is closed yet (no receipt exists)?**

Recommendation: empty state with a hint to run `treeship wrap -- <cmd>` and `treeship session close`. Don't lazy-construct a synthetic receipt from live events; that would blur the live/sealed boundary.

## How this composes with other in-flight work

- **PR #107 workflow declarations** — when those land, the dashboard adds a "Workflow Conformance" row to the trust panel (per-action: was this in the authorized workflow?). New page possibly.
- **PR #109 invitations/rooms** — when rooms land, the session detail page shows participants[] with their join events and signing keys. Multi-agent dashboards become non-trivial; the agent_graph already exists in receipts so the render is straightforward.
- **PR #111 invitations Phase 1 (real code)** — the dashboard can show invitations issued and consumed once participant events appear in receipts.

The dashboard doesn't need any of these to ship. Sealed mode against existing single-agent receipts is enough for Phase 1. Later phases gain new views as the underlying artifacts gain new fields.

## What this proposal explicitly rejects

- **Building a new SPA from scratch.** The `preview.html` artifact is the dashboard. Replacing it with a Next.js app or similar requires authentication, server state, and centralization that breaks Treeship's trust model.
- **Conflating the dashboard with Treeship Hub Saas.** Hub stores and serves receipts. The dashboard renders them. They are not the same product.
- **Making the dashboard authoritative.** It is a view. The receipt is the artifact. If the dashboard disagrees with the verifier, the verifier is right.
- **Making Hub authoritative.** Hub indexes are derived. The receipt is the source of truth. A dashboard that "trusts the Hub" stops being a Treeship dashboard.

## What this proposal accepts

- **Localhost server + browser on localhost** is the right deployment shape. Hermes proves it works.
- **Two modes** is the right architectural axis. Live mode for in-progress sessions; sealed mode for receipts.
- **`preview.html` is the dashboard UI**. The most leveraged decision in the design.
- **Trust panel is the most important panel**. Everything else is secondary.
- **Same UI everywhere**. Local, Hub, shared links — one renderer, three deployment surfaces.

## Next concrete moves

1. **Settle the four open questions** (Q1–Q4 above).
2. **Sketch the trust panel UX** as a short markdown or ASCII mockup. Load-bearing surface; getting it right matters more than any other UI decision.
3. **Phase 1 implementation** (~2 days) once Q1–Q4 land.

End.
