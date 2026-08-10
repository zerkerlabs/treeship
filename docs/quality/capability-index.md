# The capability index

`docs/feature-inventory.yml` is the **source of truth for what Treeship ships
today**. CI keeps it honest against the Rust and Go source, so it cannot quietly
drift into fiction.

**Before proposing that we build something, check here first.**

## Why this exists

Treeship's capabilities were discoverable only by reading Rust and Go source.
Everyone who planned work — partners, external reviewers, automated agents, and
us — planned from docs and specs instead. So we repeatedly proposed building
things that already existed.

Three from a single day:

| Proposed | Reality |
|---|---|
| "Build client-side receipt verification" | `/v1/artifacts/{id}` already served full DSSE envelopes; the WASM verifier already shipped, wired to a playground page |
| "Extract a Go DPoP client from `internal/` — a move, not a build" | Only the *server* half existed. The client half was net-new |
| "Design an append-safe checkpoint API" | `merkle_checkpoints` + `merkle_consistency` already existed, signature-verified, with append-only consistency proofs |

The last one is the sharpest: two independent integration specs were scoped
around checkpoint infrastructure neither knew existed.

**The failure was never stale docs. It was that "does X exist?" had no cheap,
trustworthy answer.** Now it does.

## What the index covers

Each entry declares what a feature ships, and CI verifies each claim against
source:

| field | verified against |
|---|---|
| `cli` | subcommands in `packages/cli/src` |
| `api` | chi route registrations in `packages/hub` |
| `types` | `pub struct/enum/type/fn/const` in `packages/core/src` |
| `docs` | files on disk |
| `tests` | files on disk |
| `packages` | manifests under `packages/`, `bridges/`, `npm/` |
| `status` | a fixed taxonomy — see the header of the YAML |

```yaml
- id: session-reports
  name: Session reports
  section: core
  status: stable
  api:
    - PUT /v1/receipt/{session_id}
    - GET /v1/receipt/{session_id}
  types:
    - SessionReceipt
    - Custody
  cli:
    - treeship session start
```

## Drift is caught in both directions

Forward drift — the index claims something that isn't there:

```
warn  feature 'hub-transport' api 'GET /v1/imaginary' -- route not registered in packages/hub
warn  feature 'session-reports' type 'CustodyRenamed' -- no `pub struct/enum/...` in packages/core/src
```

Reverse drift — source ships something nobody wrote down:

```
warn  drift: hub endpoint '/v1/artifacts/{id}' not in any feature entry
```

**Reverse drift is the direction that actually cost us.** A capability nobody
recorded gets rebuilt. The forward check keeps the index truthful; the reverse
check keeps it *complete*, and only a complete index is safe to plan against.

## Using it

```bash
# does an endpoint exist?
grep -n "v1/artifacts" docs/feature-inventory.yml

# what does a feature actually ship?
grep -A15 "^- id: merkle-checkpoints" docs/feature-inventory.yml

# is the index honest right now?
python3 scripts/check-feature-inventory.py --strict
```

The human-readable matrix at `docs/content/docs/reference/feature-matrix.mdx` is
**generated** from this file. Edit the YAML, never the MDX, then:

```bash
cd docs && npm run sync:feature-matrix
```

## Adding a capability

When you add a CLI command, Hub endpoint, or public core type, add it here in
the same PR. CI runs `--strict`, so a new endpoint with no entry fails the
build. That is deliberate: the cost of one YAML block is much lower than the
cost of someone rebuilding your work in six months.

## The standing rule

> **Assume it exists. Check the source before scoping.**

For specs and proposals — internal or partner-facing — a section that proposes
building something should name what it checked. *"This does not exist"* is a
claim requiring evidence, exactly like any other. Cite the grep.

## Limits

The index records **what exists**, not **what it guarantees**. An endpoint being
listed says nothing about whether it verifies signatures, enforces
monotonicity, or is safe to depend on — see
[what a receipt proves](/docs/concepts/what-receipts-prove) for that distinction
applied to receipts.

Route scanning matches chi registrations by literal string. A route built at
runtime from a variable will not be found, and will surface as reverse drift
only if it is *also* undocumented. Adding one is fine; it just needs its entry.
