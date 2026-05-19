# Local Dashboard — design draft

**Status:** draft, not implemented
**Pairs with:** [workflow-declarations.md](workflow-declarations.md) (PR #107), [agent-invitations-rooms.md](agent-invitations-rooms.md) (PR #109)
**Last updated:** 2026-05-18

## The shift

Treeship today gives **point-in-time answers** through the CLI:

- `treeship status` — what's the current ship / hub / session state?
- `treeship session report` — render this one session as a receipt
- `treeship log` — what artifacts have been signed?

Every answer is a snapshot. To watch a session unfold you re-run the command. To compare two sessions you open two terminals. To see how an agent_graph is shaped you read JSON and squint.

This spec describes the **continuous, multi-perspective view**: a local dashboard that renders the same data the CLI produces, but as a live surface you can keep open while agents work.

| Layer | Question it answers |
|---|---|
| CLI (today) | "What is the state of X **right now**?" |
| Dashboard (this spec) | "What is happening across the trust surface **as it happens**?" |
| Both together | CLI is the write path and scripting surface; dashboard is the watch path. |

For single-agent sessions a dashboard is convenient. For multi-agent sessions — the case PR #109 introduces — it becomes essential. The `agent_graph` and `timeline` are inherently 2D structures. Streaming them through stdout loses the shape every time. A live SVG of the graph with color-coded actors, refreshed as participants join and hand off, is a different kind of legibility than a JSON dump.

The shift is not about adding a new trust primitive. It is about making the existing ones **visible**.

## What's already in the box

Before specifying anything new, here is exactly which data sources exist today and where they live on disk. The dashboard's job is to surface these — not invent new ones.

| Existing primitive | On-disk location | Read API | Dashboard section it feeds |
|---|---|---|---|
| **Session manifest** (`v0.10.x`) | `.treeship/session.json` (active) and `.treeship/sessions/<id>/` (historical) | `treeship_core::session::manifest::SessionManifest` (Serde) | Sessions list, session header |
| **Event log** (`v0.10.x`) | `.treeship/sessions/<id>/events.jsonl` (JSONL, append-only with flock-protected counter sidecar) | `treeship_core::session::event_log::EventLog::open` → `read_all()` | Timeline, agent_graph derivation, live SSE stream |
| **Agent graph** (`v0.10.x`) | Derived from `events.jsonl` (not stored) | `treeship_core::session::graph::AgentGraph::from_events` | The agent_graph view itself (the headline visual) |
| **Artifact storage** (`v0.9.x`) | `~/.treeship/artifacts/` plus `.last` pointer | `ctx.storage.list()` / `ctx.storage.read(id)` | Artifacts panel inside session detail, parent_id chain rendering |
| **Approval Use Journal** (`v0.9.9`) | `.treeship/journals/approval-use/<index>-approval-{use,revocation}-<digest>.json` | `treeship_core::statements::approval_use::*` digests + record iteration | (Future page) Approvals inbox; v0 only renders count on session detail |
| **Pending approvals** (`v0.10.x`) | `.treeship/pending/*.json` | `crate::commands::approve::PendingApproval` (already deserialized by TUI) | Header badge + (future) approvals page |
| **Keystore** (`v0.9.x`) | `~/.treeship/keys/` (AES-256-GCM, manifest at `manifest.json`) | `treeship_core::keys::Store::open` → `list() / default_key_id() / public_key(id)` | Identity strip in header (key fingerprint, default) — never the private bytes |
| **Trust roots** (`v0.10.3`) | `~/.treeship/trust_roots.json` (perms-gated, 0600 enforced) | `treeship_core::trust::TrustRootStore::open_default_or_empty` | Health card (`N trust roots loaded`), session detail (which root verified this session) |
| **Hub status** (`v0.9.x`) | `.treeship/config.yaml` + in-memory connection state from `ctx.config.active_hub_connection()` | `cli/commands/hub.rs::status` | Health card: hub attached / endpoint / last successful publish |
| **`treeship daemon`** (`v0.10.x`) | PID + epoch at `.treeship/daemon.pid`, log at `.treeship/daemon.log`, proof queue at `.treeship/proof_queue/` | `cli/commands/daemon.rs::daemon_info()` (already public, returns `(running, pid, uptime_secs)`) | Health card: daemon running indicator, uptime, last attestation |
| **Merkle checkpoints** (`v0.10.3`) | `~/.treeship/merkle/checkpoints/latest.json` (and historical) | `treeship_core::merkle::checkpoint::Checkpoint` (Serde) | Session detail: last checkpoint, ZK proof status if present |
| **`treeship ui` (Ratatui TUI)** | Implemented at `packages/cli/src/tui/` with views `dashboard`, `log`, `artifact`, `approve` | Already wired to `Cmd::Ui` in `main.rs:1740`, 2s poll cycle | Same data sources the web dashboard will use; the two front-ends share a backend |

Three observations the inventory makes obvious:

1. **The hard work is already done.** Every datum the dashboard would render is already either signed-on-disk or derivable from signed-on-disk. The dashboard is a render layer, not a new source of truth.
2. **The TUI already exists** (`packages/cli/src/tui/` is real code, not aspirational). Its `App::refresh` is a 2-second poll over the same surfaces a web dashboard would hit. Whatever we build for web should share that backend.
3. **The daemon is already running.** It owns the file watcher loop, holds the PID lock, and appends `AgentReadFile` events to the active session. Adding an HTTP listener to the existing daemon process is materially cheaper than spinning up a new long-lived process.

## What to build

Three pieces. None of them invent crypto, define wire formats, or introduce a new trust primitive.

### 1. Daemon HTTP API

A loopback-only HTTP listener inside the existing `treeship daemon` process. Bind `127.0.0.1:<port>` (default `7878`, configurable in `config.yaml` under `daemon.dashboard.bind`). Refuse any connection whose peer address is not `127.0.0.1` or `::1`.

- Crate: extend `treeship-cli`, new module `packages/cli/src/daemon_http/`
- HTTP server: `tiny_http` (Apache-2.0, ~3k LOC, no async runtime, fits the existing thread-based daemon loop). Existing alternatives in the tree (`ureq`) are client-only; adding `tiny_http` is the smallest delta. Reject `axum`/`hyper`/`actix` for v0 — they pull in tokio and balloon the binary.
- SSE: hand-rolled `text/event-stream` over the same `tiny_http` listener. The daemon already has a 2s polling loop that observes filesystem changes; SSE events are emitted on the same tick.

Endpoints, all `GET`, all JSON-or-SSE, all read-only:

| Endpoint | Returns |
|---|---|
| `GET /api/health` | daemon uptime, hub status, trust root count, key fingerprint |
| `GET /api/sessions` | array of session summaries (active + recent) |
| `GET /api/sessions/:id` | full session detail: manifest, participant list, agent_graph, timeline |
| `GET /api/sessions/:id/events` | raw events from `events.jsonl` (paginated) |
| `GET /api/sessions/:id/stream` | SSE: new events appended since the connection opened |
| `GET /api/agents` | aggregate across sessions: which agent identities have signed recently |
| `GET /api/approvals/pending` | from `.treeship/pending/` |
| `GET /api/trust/roots` | from `~/.treeship/trust_roots.json` (public keys, kinds, ids — never the private side) |

All endpoints mirror what `treeship <cmd> --format json` already produces. The dashboard MUST NOT have a strictly-larger field set than the CLI; if a field is in the dashboard JSON, it should also be in the CLI JSON (or get added to the CLI in the same patch). One source of truth.

### 2. Bundled static SPA

Single-page app served by the daemon from embedded assets.

- Build artifact (`dashboard.html` + bundled CSS + bundled JS) is `include_bytes!`'d into the `treeship` binary at compile time. No `npm install` for users. No second process. No reading from `~/.treeship/dashboard/` at runtime.
- Stack: see Q4 below. The recommendation is **vanilla JS + small render helpers**. No build step on the user's machine; the developer-side build (whatever it is) lives in `packages/cli/dashboard/` and produces a single concatenated file that's checked into the repo or rebuilt by `build.rs`.
- Bundle budget: hard cap **256 KB gzipped** for v0. The `agent_graph` SVG renderer is the only non-trivial piece. If we cannot fit it in the budget with the chosen stack, we revisit Q4.
- No external CDN, no fonts loaded from the web, no analytics, no service worker. The page loads on a laptop in airplane mode and renders.

### 3. Two entry points, shared backend

- `treeship ui` — existing TUI, kept as-is for v0. Same backend (file watchers, event log readers), in-process.
- `treeship dashboard` — new command. Starts the daemon if not running, then `xdg-open` / `open` / `start` the dashboard URL. Prints the URL and a token (if Q3 settles on tokens) to stdout if the browser-open call fails.

Both front-ends read the same files. The TUI does it via in-process `EventLog::open`; the web SPA does it via the daemon HTTP API. The data model is identical; only the renderer differs.

## Pages in v0

A deliberately tiny set. Every additional page is risk; v0 ships what makes the demo land, then we add based on what users ask for.

### 1. Sessions list (`/`)

Active sessions at the top, recent closed sessions below. For each:

- session id, name (if set), actor URI, started_at, duration, status
- participant count (for multi-agent sessions; 1 for single-agent)
- artifact count
- visual indicator: green dot active, gray dot closed, red dot failed/abandoned

Click a row → session detail.

### 2. Session detail (`/sessions/:id`)

Three regions, top to bottom:

- **Header strip.** Session id, actor URI, status, started/closed timestamps, link to manifest JSON, link to receipt (if closed).
- **Agent graph.** SVG rendering of `AgentGraph::from_events`. Nodes colored by `agent_id` (deterministic palette by hash). Edges labeled with `AgentEdgeType` (parent_child / handoff / collaboration / return). Hover a node → tool call count, model, provider, tokens.
- **Timeline.** Chronological event list from `events.jsonl`, grouped by `agent_instance_id` in swim-lane style. Identity tags on every row: actor URI, model, provider, host. Live-updates from `/api/sessions/:id/stream` SSE without page reload.

### 3. Health (`/health`)

Single page, six cards:

- Daemon: running / stopped, pid, uptime
- Hub: attached / not, endpoint, last successful publish
- Trust roots: count, kinds, modification time of `trust_roots.json`
- Keystore: default key id (short), key count, last rotation
- Storage: artifact count, storage_dir path, last `.last` advancement
- Approvals: pending count, oldest pending age

That's it for v0. Future pages — approvals inbox, trust panel, cross-session activity feed, workflow conformance view (PR #107), participant list view (PR #109) — get prioritized based on what users actually request once v0 is in their hands.

## Design principles

A numbered set the implementer can refer back to mid-build:

1. **Local-only.** The dashboard never calls out to a remote service. The Hub-status card reads cached state from `ctx.config`, not from a live Hub request. (The CLI's `treeship hub status` is still the way to actively probe the Hub.)
2. **Read-only by default.** The UI displays. The CLI/SDK is the only write path. No "approve from dashboard" button in v0 — clicking pending approvals copies the `treeship approve <id>` command to clipboard.
3. **Multi-agent first.** The `agent_graph` is the centerpiece of session detail, not an afterthought. For single-agent sessions it collapses to a trivial one-node view; the data model and renderer do not branch on participant count.
4. **Real-time without polling.** SSE stream from daemon, driven by the existing file-watcher tick. Browser doesn't poll. (The TUI keeps its 2s poll because it shares the process, not the network.)
5. **Identity tags everywhere.** Every row in every list carries actor URI, model/provider, and cert issuer (when available). The dashboard's value over the CLI is precisely the density of context per row.
6. **No accounts.** Same keystore as CLI. No login. The "user" is whoever is logged into the OS shell that started the daemon. (Q3 discusses what happens if that's wrong.)
7. **Bundled, not installed.** `cargo install treeship-cli` (or the npm-wrapper equivalent) gives you the dashboard. No `treeship dashboard install` step. No `~/.treeship/dashboard/` directory to keep in sync.

## What's explicitly NOT v0

To keep the spec falsifiable, the things we are choosing *not* to do:

- **No remote / cloud-hosted dashboard.** Hub UI is a separate product surface with separate trust semantics. This spec is strictly local.
- **No multi-user / RBAC.** Single-user local tool. If two humans share a workstation they share the dashboard, the same way they share `~/.treeship`.
- **No editing trust roots, certs, or workflows from the UI.** The UI is observational. `treeship trust add`, `treeship keys rotate`, `treeship workflow declare` remain CLI-only.
- **No alerting / notifications / email.** Separate scope; if needed it composes on top of the SSE stream.
- **No mobile / PWA.** Desktop browser only. The agent_graph renderer assumes pointer hover.
- **No public exposure.** Binds `127.0.0.1`; refuses non-loopback connections at the socket layer. There is no `--bind 0.0.0.0` flag.
- **No telemetry / usage tracking.** Local-only ethos. The dashboard never phones home, not even to count installs.

## Four open questions for the maintainer

The hard calls. Each has implications; each has a recommended default with the tradeoff named.

### Q1: TUI + web both, or pick one?

The TUI exists today (`packages/cli/src/tui/`). The web dashboard is new. Maintaining both costs ongoing work — every session-event shape change touches both renderers.

- **(a) Both.** TUI for `ssh` sessions and minimal environments; web for the rich `agent_graph` view. Shared backend in `packages/core` keeps drift minimal.
- **(b) Web only.** Deprecate `treeship ui`. Hide it but don't delete it; remove after one minor version.
- **(c) TUI only, scrap the web plan.** Ratatui can render an `agent_graph` with box-drawing characters. The result is uglier but the dependency surface is zero.

Recommendation: **(a) both, with the web dashboard as the primary surface.** The TUI is already written, tested, and 2s-poll fast; deleting working code to reduce maintenance is a false economy when the maintenance is "update one View enum when an event field changes." Keep both, share the backend at `treeship_core::session::*`.

### Q2: where does the daemon HTTP API live?

- **(a) Extend the existing `treeship daemon`.** Add an HTTP listener thread to the loop. One process, one PID file, one log.
- **(b) New `treeship dashboard-server`.** Independent binary, independent lifecycle.
- **(c) Make HTTP part of the SDK and let any process embed it.** Most flexible; most pieces to coordinate.

Recommendation: **(a) extend the existing daemon.** The daemon already holds the file-watcher loop that the SSE stream depends on. Two processes would mean two file watchers, two flock contenders on `events.jsonl.lock`, and two things for the operator to start. The HTTP listener is ~200 LOC sitting on the existing tick. `treeship dashboard` becomes "ensure daemon running, then open browser at its URL."

### Q3: auth on the API?

Loopback binding is the first line of defense. But on a shared workstation, any local process running as the same user can hit `127.0.0.1:7878` and read every session.

- **(a) Loopback-only, no auth.** Same trust posture as the CLI: anything that can read `~/.treeship/` can read the dashboard.
- **(b) Random session token printed at daemon start, required as `?token=` or `Authorization: Bearer`.** Token persisted to `.treeship/daemon.dashboard.token` with 0600 perms.
- **(c) Signed-request auth keyed off the keystore.** Heaviest; reuses existing crypto.

Recommendation: **(a) loopback-only, no auth, for v0.** The threat model of "another process running as me can read my files" is already lost the moment that's true — `~/.treeship/keys/` is right there and contains the private bytes. Adding token auth to read-only public-data endpoints is security theater. **However:** if the dashboard ever gains a write path (Q1 says it shouldn't in v0; if that flips, this answer flips with it), tokens become mandatory.

### Q4: SPA framework choice?

- **(a) Vanilla JS** + small render helpers. Smallest bundle, no build step on the user's machine. Most stable. The agent_graph is the only complex piece and a hand-rolled SVG renderer fits in <200 LOC.
- **(b) htmx + small JS islands.** Server-renders the structure from the daemon, client-side enhances the graph view. Cuts JS but couples the daemon to HTML rendering.
- **(c) Vue / Svelte / Preact.** Richer, more reactive, but adds a build pipeline, framework version churn, and bundle size.

Recommendation: **(a) vanilla JS with a deliberate render helper.** The 256 KB budget is generous for the v0 page set. Frameworks become attractive once the page count and interaction model grow past v0; cross that bridge when v0 ships and we know which interactions actually matter. The agent_graph SVG is the only non-trivial render and it benefits more from a focused hand-roll than from a framework abstraction.

## Implementation phases

If the four questions settle, the build is small:

**Phase 1: daemon HTTP API + health page (2-3 days)**
- `packages/cli/src/daemon_http/` module
- `tiny_http` dependency, loopback-bind, refuse non-loopback peers
- `GET /api/health`, `GET /api/sessions`, `GET /api/sessions/:id`
- Bundled `dashboard.html` with just the health page and sessions list
- `treeship dashboard` command (starts daemon if needed, opens browser)

**Phase 2: session detail + SSE (3-5 days)**
- `GET /api/sessions/:id/stream` SSE endpoint, hooked into daemon's existing tick
- Session detail page: header strip + agent_graph SVG + timeline
- Hand-rolled SVG layout for `AgentGraph` (force-directed is overkill; a simple layered layout by depth is enough for v0)
- Live timeline updates

**Phase 3: polish + composition with #107 and #109 (separate scope, not estimated)**
- Workflow conformance row on session detail (when #107 lands)
- Participant list view (when #109 lands)
- Approvals inbox page (only after operators ask for it)
- Trust panel page (same)

## How this composes

This spec intentionally does not depend on PR #107 or PR #109. The dashboard ships against the data sources that already exist today.

When the other two specs land:

- **PR #107 (workflow declarations).** The session detail page gains a "workflow conformance" panel: which declared nodes have been executed, which deviations were recorded, which gaps remain. Data source is the new `workflow_conformance` row in the receipt — the dashboard renders what's already there.
- **PR #109 (invitations + rooms).** The session detail page's participant list becomes meaningful (more than one participant per session). The agent_graph SVG gains explicit "joined via invitation" edges. The sessions list grows a "room" facet.

Phase ordering: dashboard v0 → workflow-declarations Phase 1 → invitations Phase 1 → dashboard Phase 3 (polish that depends on the other two). The dashboard's value lands before either of the other two specs is fully built, which is the point: it makes the *existing* primitives visible. The new primitives extend the dashboard rather than enable it.

## What to look at before committing to this

1. Run `treeship ui` against an active session. Confirm what data it surfaces today. The web dashboard must not regress what the TUI already shows.
2. Read `packages/cli/src/commands/daemon.rs` — specifically the main loop at line ~607 — to see where the HTTP listener thread would slot in without breaking the file-watcher cadence.
3. Open `~/.treeship/sessions/<some_id>/events.jsonl` from a recent session. Confirm the event shapes match what `EventType` declares. (If they don't, that's a higher-priority bug than the dashboard.)
4. Sanity-check Q3 against the threat model. If the answer is "loopback is enough," document it explicitly so the next person who proposes adding write paths is forced to revisit.
5. Decide whether `treeship ui` and `treeship dashboard` are sibling commands or whether `treeship ui --web` is the right surface. The former is clearer; the latter saves a name.

---

*If this direction is right, the next move is to settle Q1–Q4 and let me draft Phase 1 in a non-draft PR.*
