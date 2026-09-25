# Treeship SDK & CLI Reference

This file is a quick reference. It is kept short on purpose: a hand-copied
command or route table is exactly what let this file drift out of sync with
the CLI before (fictional `dock_push`, `expires_in`, `treeship inspect`,
`treeship attach <agent>`, `TREESHIP_API_KEY`, and more, none of which exist).
For anything not covered here, read the source or the canonical docs instead
of copying a new list into this file:

- CLI surface: `treeship --help` / `treeship <command> --help` (or
  `packages/cli/src/main.rs`)
- Python SDK: `packages/sdk-python/treeship_sdk/client.py`
- TypeScript SDK: `packages/sdk-ts/src/*.ts`
- Full docs: <https://docs.treeship.dev>

## Python SDK (`treeship-sdk`)

```bash
pip install treeship-sdk
```

Requires the `treeship` CLI binary on PATH, initialized once with
`treeship init`.

```python
from treeship_sdk import Treeship, TreeshipError

ts = Treeship()

# attest_action(actor, action, parent_id=None, approval_nonce=None,
#               meta=None, subject=None) -> ActionResult(artifact_id: str)
result = ts.attest_action(
    actor="agent://coder",
    action="tool.call",
    parent_id="art_abc123",
    meta={"tool": "read_file", "path": "src/main.rs"},
)

# attest_approval(approver, description, allowed_actions=None,
#                 allowed_actors=None, allowed_subjects=None, max_uses=None,
#                 unscoped=False, expires_at=None) -> ApprovalResult
# A scope is required: pass at least one of allowed_actions/allowed_actors/
# allowed_subjects/max_uses, or unscoped=True to mint a bearer approval
# deliberately. expires_at is an RFC 3339 timestamp, not a duration --
# there is no expires_in.
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment to production",
    max_uses=1,
    expires_at="2026-03-26T11:00:00Z",
)

# attest_handoff(from_actor, to_actor, artifacts, approvals=None)
#   -> ActionResult

# attest_decision(actor, model=None, tokens_in=None, tokens_out=None,
#                 summary=None, confidence=None, ...) -> ActionResult

# verify(artifact_id) -> VerifyResult(outcome, chain, target)
verified = ts.verify(result.artifact_id)

# hub_push(artifact_id) -> PushResult(hub_url, rekor_index)
# The method is hub_push. There is no dock_push -- it was renamed.
push = ts.hub_push(result.artifact_id)

# wrap(command, actor=None, *, timeout=None) -> ActionResult
# command is a Sequence[str] (preferred) or a str split with shlex.
result = ts.wrap(["npm", "test"], actor="agent://ci")

# session_event(event_type, *, tool=None, file=None, destination=None,
#               actor=None, agent_name=None, duration_ms=None,
#               exit_code=None) -> SessionEventResult

# session_report(session_id=None) -> SessionReportResult(session_id,
#               receipt_url, agents=0, events=0)
report = ts.session_report()
```

All methods raise `TreeshipError` (a `RuntimeError` subclass) on CLI failure.

## TypeScript SDK (`@treeship/sdk`)

There is no `Treeship` class and no flat `attestAction`/`dockPush` methods.
The SDK shells out to the CLI; get an instance with the `ship()` factory
and call through its modules:

```typescript
import { ship } from "@treeship/sdk";

const s = ship();
const { artifactId } = await s.attest.action({ actor, action, meta });
const verified = await s.verify.verify(artifactId);
const push = await s.hub.push(artifactId);          // s.hub, not dockPush
```

`s.attest.approval()` does not yet accept a scope; use the Python SDK or
the CLI directly (`treeship attest approval`) for scoped approvals.

## CLI Reference

### Core workflow

```bash
treeship wrap -- <command>      # flags: --actor --action --parent --push
treeship verify <artifact_id>
treeship verify last
treeship hub push <artifact_id>
treeship hub push last
```

### Session management

```bash
treeship session start --name "..."
treeship session close
treeship session status
treeship session report [<session_id>]
```

There is no `session list`.

### Keys (the noun is `keys`, plural -- there is no `key show`/`key rotate`/`key import`)

```bash
treeship init                   # generate a keypair
treeship keys list
treeship keys export [--agent <uri>] [--key <key_id>]
treeship keys rotate [--grace-hours N]
```

### Agent instrumentation

```bash
treeship add                    # auto-detect and instrument
treeship add claude-code hermes # instrument specific agents
```

There is no top-level `attach <agent>` and no top-level `list`. Hub
connection is `hub attach`/`hub detach`/`hub status` (below).

### Inspection, bundles, verification

```bash
treeship verify <artifact_id>   # no separate "inspect" command
treeship bundle create --artifacts art_a1b2,art_c3d4
treeship bundle export <artifact_id> --out release.treeship
treeship bundle import release.treeship
treeship package verify <path.treeship>
```

There is no `bundle verify` and no `chain show`/`chain verify`.

### Hub

```bash
treeship hub attach
treeship hub detach
treeship hub status
treeship hub push <artifact_id>
treeship hub pull <artifact_id>
```

### Attesting directly

```bash
treeship attest action --actor agent://name --action tool.call \
  --input-digest sha256:abc123 --parent art_xxx --approval-nonce nonce_xyz
```

`attest` is a subcommand group (`attest action`/`approval`/`handoff`/
`decision`/`receipt`) -- there is no bare `treeship attest`.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `TREESHIP_ACTOR` | Default actor URI |
| `TREESHIP_PARENT` | Default parent artifact ID |
| `TREESHIP_MODEL`, `TREESHIP_TOKENS_IN`, `TREESHIP_TOKENS_OUT`, `TREESHIP_PROVIDER` | Model/token metadata |
| `TREESHIP_APPROVAL_NONCE` | Approval nonce read by the MCP bridge |
| `TREESHIP_DISABLE` | Disables the MCP bridge's capture |
| `TREESHIP_STRICT` | MCP bridge: fail closed on a signing failure or active halt |

There is no `TREESHIP_API_KEY`, `TREESHIP_AGENT` or `TREESHIP_HUB_ID`. Hub
auth is DPoP, not an API key.

### Global flags

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Config file (default `~/.treeship/config.json`) |
| `--format <text\|json>` | Output format (default `text`) |
| `--quiet` | Suppress all output except errors |
| `--no-color` | Disable color output |

There is no `--ship`, `--json` or `--verbose` -- use `--format json`.
