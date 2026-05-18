# Treeship SDK & CLI Reference

## Python SDK (`treeship-sdk`)

### Installation

```bash
pip install treeship-sdk
```

Requires the `treeship` CLI binary in PATH, initialized with `treeship init`.

### Treeship Class

All methods raise `TreeshipError` on CLI failure.

#### `attest_action(actor, action, parent_id=None, approval_nonce=None, meta=None)`

Create a signed action receipt.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `actor` | `str` | Yes | Actor URI, e.g. `"agent://my-agent"` |
| `action` | `str` | Yes | Label for the action |
| `parent_id` | `Optional[str]` | No | Parent artifact ID for chain linking |
| `approval_nonce` | `Optional[str]` | No | Nonce from an existing approval |
| `meta` | `Optional[Dict[str, Any]]` | No | Arbitrary metadata dictionary |

**Returns:** `ActionResult(artifact_id: str)`

**Example:**
```python
result = ts.attest_action(
    actor="agent://coder",
    action="tool.call",
    parent_id="art_abc123",
    meta={"tool": "read_file", "path": "src/main.rs"}
)
print(result.artifact_id)  # art_f7e6d5c4...
```

#### `attest_approval(approver, description, expires_in=None)`

Create a signed approval receipt with a single-use nonce.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `approver` | `str` | Yes | Approver URI, e.g. `"human://alice"` |
| `description` | `str` | Yes | What is being approved |
| `expires_in` | `Optional[int]` | No | Expiry in seconds |

**Returns:** `ApprovalResult(artifact_id: str, nonce: str)`

**Example:**
```python
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment to production",
    expires_in=3600
)
print(approval.nonce)  # Single-use nonce for binding to action
```

#### `attest_handoff(from_actor, to_actor, artifacts, approvals=None)`

Create a signed handoff receipt between agents.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `from_actor` | `str` | Yes | Source actor URI |
| `to_actor` | `str` | Yes | Destination actor URI |
| `artifacts` | `List[str]` | Yes | Artifact IDs being handed off |
| `approvals` | `Optional[List[str]]` | No | Approval nonces to include |

**Returns:** `ActionResult(artifact_id: str)`

#### `attest_decision(actor, model=None, tokens_in=None, tokens_out=None, summary=None, confidence=None, meta=None)`

Create a signed decision receipt capturing LLM reasoning context.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `actor` | `str` | Yes | Actor URI |
| `model` | `Optional[str]` | No | LLM model name |
| `tokens_in` | `Optional[int]` | No | Input token count |
| `tokens_out` | `Optional[int]` | No | Output token count |
| `summary` | `Optional[str]` | No | Decision summary |
| `confidence` | `Optional[float]` | No | Confidence score (0-1) |
| `meta` | `Optional[Dict]` | No | Additional metadata |

**Returns:** `ActionResult(artifact_id: str)`

#### `verify(artifact_id)`

Verify an artifact and walk its chain.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `artifact_id` | `str` | Yes | Artifact ID to verify |

**Returns:** `VerifyResult(outcome: str, chain: int, target: str)`

- `outcome`: `"pass"`, `"fail"`, or `"error"`
- `chain`: Number of linked artifacts in the chain
- `target`: The artifact ID that was verified

**Example:**
```python
result = ts.verify("art_abc123")
if result.outcome == "pass":
    print(f"Chain length: {result.chain}")
```

#### `dock_push(artifact_id)`

Push an artifact to the configured hub.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `artifact_id` | `str` | Yes | Artifact ID to push |

**Returns:** `PushResult(hub_url: str, rekor_index: Optional[int])`

#### `wrap(command, actor=None)`

Wrap a shell command with a signed receipt.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | `str` | Yes | Shell command to execute |
| `actor` | `Optional[str]` | No | Actor URI |

**Returns:** `ActionResult(artifact_id: str)`

**Example:**
```python
result = ts.wrap("npm test", actor="agent://ci")
```

#### `session_report(session_id=None)`

Upload a closed session's receipt to the configured hub and return the permanent public URL.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | `Optional[str]` | No | Session ID. Defaults to most recently closed session. |

**Returns:** `SessionReportResult(session_id, receipt_url, agents, events)`

The returned `receipt_url` is permanent and public. No auth required to fetch it.

### Result Types

All results are dataclasses exported from `treeship_sdk`.

```python
@dataclass
class ActionResult:
    artifact_id: str

@dataclass
class ApprovalResult:
    artifact_id: str
    nonce: str

@dataclass
class VerifyResult:
    outcome: str       # "pass", "fail", or "error"
    chain: int
    target: str

@dataclass
class PushResult:
    hub_url: str
    rekor_index: Optional[int] = None

@dataclass
class SessionReportResult:
    session_id: str
    receipt_url: str
    agents: List[str]
    events: int
```

### Error Handling

All methods raise `TreeshipError` (subclass of `RuntimeError`) on CLI failure.

```python
from treeship_sdk import Treeship, TreeshipError

ts = Treeship()
try:
    result = ts.attest_action(actor="agent://test", action="test")
except TreeshipError as e:
    print(f"Attestation failed: {e}")
```

---

## CLI Reference

### Core Workflow Commands

```bash
treeship wrap -- <command>              # Wrap command with attestation
treeship verify <artifact_id>            # Verify artifact chain
treeship verify last                     # Verify most recent artifact
treeship hub push <artifact_id>          # Push artifact to Hub
treeship hub push last                   # Push most recent artifact
```

### Session Management

```bash
treeship session start --name "..."      # Start a named session
treeship session close                   # Close current session
treeship session list                    # List sessions
treeship session report                  # Upload session receipt
treeship session report <session_id>     # Upload specific session
```

### Key Management

```bash
treeship init                            # Initialize ship with Ed25519 keypair
treeship key show                        # Display public key
treeship key rotate                      # Rotate to new keypair
treeship key export                      # Export public key
treeship key import <key_file>           # Import key
```

### Agent Instrumentation

```bash
treeship add                             # Auto-detect and configure agents
treeship attach claude                   # Attach to Claude Code
treeship attach cursor                   # Attach to Cursor
treeship attach hermes                   # Attach to Hermes
treeship attach openclaw                 # Attach to OpenClaw
treeship list                            # List attached agents
```

### Inspection and Verification

```bash
treeship inspect <artifact_id>           # Inspect artifact details
treeship inspect last                    # Inspect most recent
treeship bundle create                   # Create portable bundle
treeship bundle verify <bundle.json>     # Verify bundle offline
treeship chain show <artifact_id>        # Show chain from artifact
treeship chain verify <artifact_id>      # Verify chain integrity
```

### Hub Management

```bash
treeship hub attach                      # Connect to Treeship Hub
treeship hub detach                      # Disconnect from Hub
treeship hub status                      # Check hub connection
treeship hub push <artifact_id>          # Push artifact to Hub
treeship hub pull <artifact_id>          # Pull artifact from Hub
```

### Receipts and Attestation Direct

```bash
treeship attest \
    --agent "my-agent" \
    --action "description of action" \
    --inputs-hash "sha256:..." \
    [--metadata '{"key": "value"}']
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `TREESHIP_API_KEY` | Hub API key for SDK direct API calls |
| `TREESHIP_AGENT` | Default agent slug for CLI |
| `TREESHIP_HUB_ID` | Hub workspace ID |

### Flags (Global)

| Flag | Description |
|------|-------------|
| `--ship <path>` | Path to ship directory (default: `~/.treeship`) |
| `--json` | Output JSON format |
| `--quiet` | Suppress non-essential output |
| `--verbose` | Detailed output |
