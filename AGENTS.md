# TREESHIP --AGENT INSTRUCTIONS

> **Read this file first. Every time. It is the single source of truth.**
> Last updated: April 2026 · 161 core lib tests passing · CLI + Hub + SDK + MCP + Claude Code plugin shipped (v0.9.4).

---

## 1. WHAT TREESHIP IS

Treeship is a portable trust layer for AI agent workflows. Every action, approval, and handoff gets a **cryptographically signed artifact** --a tamper-proof receipt verifiable by anyone, anywhere, without trusting any infrastructure.

**The loop:** `treeship wrap -- your-agent-command` → signed artifact → `treeship hub push` → `https://treeship.dev/verify/art_xxx` --shareable proof that something happened.

**Four properties that never change:**
- **Local-first.** Every operation works offline. Hub adds shareability, never trust.
- **Self-contained.** A signed artifact is a JSON file. Verifies without database, API, or account.
- **Deterministic.** Same content always produces the same artifact ID.
- **Open.** Verifier is open source. Anyone can verify without trusting Treeship.

---

## 2. REAL CURRENT STATE

### What exists and works

| Component | Location | Status |
|-----------|----------|--------|
| Rust core library | `packages/core/` | 161 tests passing |
| Rust CLI binary | `packages/cli/` | 25+ commands |
| TUI (Ratatui) | `packages/cli/` | Interactive terminal dashboard (`treeship ui`) |
| OTel export | `packages/cli/` | OpenTelemetry span export (feature-flagged) |
| Go Hub server | `packages/hub/` | 12 API endpoints |
| WASM verifier | `packages/core-wasm/` | 167KB gzipped, Merkle + Ed25519 verify |
| TypeScript SDK | `packages/sdk-ts/` | @treeship/sdk, 5 tests |
| MCP bridge | `bridges/mcp/` | @treeship/mcp, 3 tests |
| Fumadocs site | `docs/` | 45 pages |
| Website | (separate repo) | 8 pages |

### What is NOT built yet

1. **ZK TLS (TLSNotary)** -- fully specced, feature-flagged, TLSNotary still alpha
2. **`treeship attach claude/cursor`** -- agent process detection
3. **npm/crates.io publishing** -- packages ready, not yet published
4. **Install script** -- `curl treeship.dev/install | sh` not yet wired
5. **Hub Merkle Rekor anchoring** -- Rekor integration is best-effort, not yet live

---

## 3. REPO STRUCTURE

```
treeship/                           # monorepo root
├── Cargo.toml                      # Rust workspace
├── go.work                         # Go workspace
├── AGENTS.md                       # this file
│
├── packages/
│   ├── core/                       # Rust library (120 tests)
│   │   └── src/
│   │       ├── attestation/        # DSSE, PAE, Ed25519, content-addressed IDs
│   │       ├── statements/         # 8 statement types (action, approval, handoff, endorsement, receipt, bundle, decision, declaration), nonce binding
│   │       ├── keys/               # AES-256-CTR + HMAC encrypted keystore
│   │       ├── storage/            # local artifact store
│   │       ├── bundle/             # pack/export/import .treeship files
│   │       ├── merkle/             # tree, checkpoint, proof
│   │       ├── rules.rs            # rules engine
│   │       └── verifier/           # chain verification, TrustPolicy
│   │
│   ├── cli/                        # Rust binary (25+ commands)
│   │   └── src/
│   │       ├── main.rs             # clap command tree
│   │       ├── config.rs           # ~/.treeship/config.json
│   │       ├── ctx.rs              # opens config+keys+storage
│   │       ├── printer.rs          # colored output, json mode, hints
│   │       └── commands/
│   │           ├── init.rs         # treeship init
│   │           ├── attest.rs       # treeship attest action|approval|handoff|receipt
│   │           ├── verify.rs       # treeship verify <id>
│   │           ├── bundle.rs       # treeship bundle create|export|import
│   │           ├── status.rs       # treeship status
│   │           ├── wrap.rs         # treeship wrap -- <cmd>
│   │           ├── keys.rs         # treeship keys list
│   │           ├── session.rs      # treeship session start|status|close
│   │           ├── approve.rs      # treeship approve|deny|pending
│   │           ├── hook.rs         # treeship hook (shell integration)
│   │           ├── install.rs      # treeship install|uninstall
│   │           ├── log.rs          # treeship log [--tail N] [--follow]
│   │           ├── daemon.rs       # treeship daemon start|stop|status
│   │           ├── doctor.rs       # treeship doctor
│   │           ├── merkle.rs       # treeship checkpoint, merkle proof|verify|status|publish
│   │           ├── dock.rs         # treeship hub attach|push|pull|status|undock
│   │           ├── ui.rs           # treeship ui (Ratatui interactive dashboard)
│   │           └── otel.rs         # treeship otel test|status|export|enable|disable (feature-flagged)
│   │
│   ├── hub/                        # Go HTTP server (12 endpoints)
│   │   ├── main.go
│   │   ├── go.mod
│   │   └── internal/
│   │       ├── db/                 # SQLite setup + queries
│   │       ├── dock/               # challenge/authorize handlers
│   │       ├── artifacts/          # push/pull handlers
│   │       ├── verify/             # runs treeship verify subprocess
│   │       ├── dpop/               # DPoP JWT verification middleware
│   │       ├── merkle/             # Merkle checkpoint + proof endpoints
│   │       └── rekor/              # Rekor anchoring (best-effort)
│   │
│   ├── core-wasm/                  # WASM verifier (167KB gzipped, Merkle + Ed25519)
│   └── sdk-ts/                     # @treeship/sdk (5 tests)
│
├── bridges/
│   └── mcp/                        # @treeship/mcp (3 tests)
│
├── docs/                           # Fumadocs site (45 pages)
│
└── web/                            # Next.js -- hub.treeship.dev
    └── app/
        ├── verify/[id]/            # public artifact verification page
        ├── dock/activate/          # device flow auth page
        └── workspace/              # logged-in artifact browser
```

### Separate repos

```
treeship-dev/
├── treeship/           # monorepo above -- all code
└── treeship-site/      # static site -- marketing, blog, docs
    ├── index.html      # landing page
    ├── blog/           # 8 posts Jul 2025 -> Feb 2026
    └── architecture/   # visual posters
```

---

## 4. DOMAINS

| Domain | What | Hosting |
|--------|------|---------|
| `treeship.dev` | Marketing site + public /verify/:id | Vercel --treeship-site repo |
| `hub.treeship.dev` | Next.js workspace app | Server --web/ in monorepo |
| `api.treeship.dev` | Go Hub API | Server --packages/hub/ in monorepo |

The `/verify/:id` public page lives at `treeship.dev/verify/:id` and calls `api.treeship.dev` for artifact data. The WASM verifier runs client-side in the browser --Hub cannot forge a passing result.

---

## 5. CRYPTOGRAPHIC INVARIANTS --NEVER CHANGE THESE

### PAE format (DSSE spec --exactly this)
```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```
Example: `"DSSEv1 39 application/vnd.treeship.action.v1+json 52 {...}"`
The trailing space before the payload is required.

### Artifact ID derivation
```
artifact_id = "art_" + hex(sha256(PAE_bytes)[..16])
```
- Derived from PAE bytes, NOT stored inside the statement struct
- `id` field does NOT exist in statement structs --lives on `Record` and `SignResult` only
- Same content → same ID always

### payloadType MIME strings
```
application/vnd.treeship.action.v1+json
application/vnd.treeship.approval.v1+json
application/vnd.treeship.handoff.v1+json
application/vnd.treeship.endorsement.v1+json
application/vnd.treeship.receipt.v1+json
application/vnd.treeship.bundle.v1+json
```

### Statement type field values
```
treeship/action/v1
treeship/approval/v1
treeship/handoff/v1
treeship/endorsement/v1
treeship/receipt/v1
treeship/bundle/v1
```

### Envelope JSON (camelCase --DSSE spec)
```json
{
  "payload":     "base64url(statement_bytes)",
  "payloadType": "application/vnd.treeship.action.v1+json",
  "signatures":  [{ "keyid": "key_...", "sig": "base64url(ed25519_sig)" }]
}
```

### Approval nonce binding
```
action.approvalNonce == approval.nonce
```
Enforced at verify time. Prevents approval reuse. Do not remove this check.

### Rust dependency pins (Rust 1.75 compat)
```toml
ed25519-dalek = "=2.1.0"
sha2          = "=0.10.8"
base64        = "=0.21.7"
base64ct      = "=1.6.0"
serde         = "1"
serde_json    = "1"
rand          = "0.8"
```

---

## 6. DOCK + HUB SPEC (BUILT)

### 6.1 packages/hub/ -- Go HTTP server

**Language:** Go
**Module:** `github.com/treeship/hub`
**Dependencies:** `github.com/go-chi/chi/v5 v5.0.12`, `modernc.org/sqlite v1.29.5`

**SQLite file:** `/var/lib/treeship/hub.db` --chmod 600, owned by process user.

**Tables:**
```sql
CREATE TABLE ships (
  dock_id         TEXT PRIMARY KEY,
  ship_public_key BLOB NOT NULL,
  dock_public_key BLOB NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE TABLE artifacts (
  artifact_id   TEXT PRIMARY KEY,
  payload_type  TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  digest        TEXT NOT NULL,
  signed_at     INTEGER NOT NULL,
  parent_id     TEXT,
  hub_url       TEXT NOT NULL,
  rekor_index   INTEGER,
  dock_id       TEXT REFERENCES ships(dock_id)
);

CREATE TABLE dock_challenges (
  device_code     TEXT PRIMARY KEY,
  nonce           TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  approved        INTEGER DEFAULT 0,
  dock_public_key BLOB,
  ship_public_key BLOB
);

CREATE TABLE dpop_jtis (
  jti      TEXT PRIMARY KEY,
  seen_at  INTEGER NOT NULL
);
```

**Endpoints:**

```
GET /v1/dock/challenge
  Generate: nonce = hex(rand 16 bytes), device_code = hex(rand 8 bytes)
  Store in dock_challenges with expires_at = now + 300
  Return: { "nonce": "...", "device_code": "...", "expires_at": "..." }

GET /v1/dock/authorized?device_code=XXX
  Not found or expired → 404
  approved=0 → 202 { "status": "pending" }
  approved=1 → 200 { "dock_id": "..." }

POST /v1/dock/authorize
  Body: { "ship_public_key": "hex", "dock_public_key": "hex", "device_code": "..." }
  Verify device_code exists and not expired
  Generate dock_id = "dck_" + hex(rand 8 bytes)
  Insert into ships, set dock_challenges.approved = 1
  Return: { "dock_id": "..." }

POST /v1/artifacts  [DPoP authenticated]
  Body: { artifact_id, payload_type, envelope_json, digest, signed_at, parent_id }
  Verify DPoP (see DPoP section below)
  Insert into artifacts
  hub_url = "https://treeship.dev/verify/" + artifact_id
  Anchor to Rekor (best-effort, don't fail push if Rekor is down)
  Return: { "artifact_id": "...", "hub_url": "...", "rekor_index": 1234 }

GET /v1/artifacts/:id
  Return artifact record as JSON. 404 if not found.

GET /v1/verify/:id
  Look up artifact, 404 if not found
  Run subprocess: treeship verify {id} --format json
  Return the JSON output directly
  If treeship binary not found: { "outcome": "error", "message": "verifier unavailable" }

GET /v1/workspace
  List artifacts for the authenticated dock. DPoP required.
  Return: { "artifacts": [...] }

POST /v1/merkle/checkpoint  [DPoP authenticated]
  Body: { checkpoint_json, signature }
  Store signed Merkle checkpoint.

GET /v1/merkle/checkpoint/:id
  Return a stored checkpoint by ID.

POST /v1/merkle/proof  [DPoP authenticated]
  Body: { artifact_id, proof_json }
  Store an inclusion proof for an artifact.

GET /v1/merkle/proof/:artifact_id
  Return inclusion proof for an artifact.

GET /v1/merkle/latest
  Return the latest checkpoint for the authenticated dock.

GET /.well-known/treeship/revoked.json
  Return: { "revoked": [], "signed_at": "...", "version": "1" }
  Cache-Control: max-age=86400
```

**DPoP verification (every authenticated request):**
```
1. Parse Authorization header: must be "DPoP {dock_id}"
2. Parse DPoP header: base64url(header).base64url(payload).base64url(sig)
3. Decode payload: { iat, jti, htm, htu }
4. Check iat: within 60 seconds of now → 401 if not
5. Check jti: look up in dpop_jtis → 401 if seen. Insert if new.
6. Check htm: must match request HTTP method → 401 if not
7. Check htu: must match request URL → 401 if not
8. Look up dock_public_key from ships by dock_id → 401 if not found
9. Verify JWT signature: crypto/ed25519.Verify(dock_public_key, message, sig)
10. 401 on any failure with JSON { "error": "..." }
Clean up dpop_jtis WHERE seen_at < now-300 on each request.
```

**Rekor anchoring:**
```
POST https://rekor.sigstore.dev/api/v1/log/entries
Body:
{
  "kind": "hashedrekord",
  "apiVersion": "0.0.1",
  "spec": {
    "data": {
      "hash": { "algorithm": "sha256", "value": "{digest without sha256: prefix}" }
    },
    "signature": {
      "content": "{first sig from envelope_json}",
      "publicKey": { "content": "{ship_public_key base64}" }
    }
  }
}
On success: store logIndex in artifacts.rekor_index
On failure: log error, continue --Rekor is best-effort
```

**main.go:** chi router, all routes wired, DB init on startup, listen on :8080 (PORT env var), log every request.

### 6.2 packages/cli/src/commands/dock.rs

**Add to config.rs HubConfig:**
```rust
pub status:          String,          // "docked" | "undocked"
pub endpoint:        Option<String>,  // "https://api.treeship.dev"
pub dock_id:         Option<String>,  // "dck_..."
pub dock_public_key: Option<String>,  // hex encoded
pub dock_secret_key: Option<String>,  // hex encoded, same encryption as ship key
```

**treeship hub attach [--endpoint <url>]**
```
Default endpoint: https://api.treeship.dev
1. GET {endpoint}/v1/dock/challenge → { device_code, nonce }
2. Generate fresh Ed25519 dock keypair (NOT the ship signing key)
3. Print:
     visit {endpoint}/dock/activate
     code: {device_code as XXXX-XXXX}
     waiting...
4. Poll GET {endpoint}/v1/dock/authorized?device_code={dc} every 2 seconds
   Timeout after 5 minutes
5. POST {endpoint}/v1/dock/authorize
   body: { ship_public_key: hex, dock_public_key: hex, device_code: dc }
6. Store in config: dock_id, dock_public_key, dock_secret_key, endpoint, status: "docked"
7. Print:
     ✓ docked
       dock id:   dck_...
       endpoint:  {endpoint}
       → treeship hub push <artifact-id>
```

**treeship hub push <id>**
```
1. Load artifact from local storage. Error if not found.
2. Build DPoP proof JWT:
   header:  { "alg": "EdDSA", "typ": "dpop+jwt" }
   payload: { "iat": now_unix, "jti": hex(rand 16 bytes), "htm": "POST",
              "htu": "{endpoint}/v1/artifacts" }
   Sign with dock private key (Ed25519)
   Encode: base64url(header).base64url(payload).base64url(signature)
3. POST {endpoint}/v1/artifacts
   Headers: Authorization: DPoP {dock_id}
            DPoP: {proof_jwt}
   Body: { artifact_id, payload_type, envelope_json, digest, signed_at, parent_id }
4. Parse response: { hub_url, rekor_index }
5. Update local record with hub_url (storage.set_hub_url)
6. Print:
     ✓ pushed
       url:    {hub_url}
       rekor:  rekor.sigstore.dev #{rekor_index}
       → treeship open {hub_url}
```

**treeship hub pull <id>**
```
GET {endpoint}/v1/artifacts/{id}   (no auth --public artifacts)
Store to local storage
Print: ✓ pulled  {id}
```

**treeship hub status**
```
Undocked: print "○ undocked" + hint "→ treeship hub attach"
Docked:   print "● docked"
            endpoint: {endpoint}
            dock id:  {dock_id}
```

**treeship hub detach**
```
Clear hub section from config (status: "undocked", clear all dock fields)
Print: ✓ undocked
```

**Wire into main.rs** under the existing Command enum.

### 6.3 Test the full loop locally

```bash
# Terminal 1 --start Hub
cd packages/hub && go run . &

# Terminal 2 --test
treeship hub attach --endpoint http://localhost:8080
# (for local testing, manually approve via curl:)
curl -X POST http://localhost:8080/v1/dock/authorize \
  -d '{"device_code":"...","ship_public_key":"...","dock_public_key":"..."}'

treeship attest action --actor agent://test --action tool.call
treeship hub push art_xxxxx

# Should return passing ChainResult:
curl http://localhost:8080/v1/verify/art_xxxxx
```

---

## 7. SECURITY MODEL --NON-NEGOTIABLE

### DPoP --no session tokens ever
- Dock keypair is SEPARATE from ship signing keypair
- `config.json` stores `dock_id` only --never a session token
- Every API request carries a fresh DPoP proof JWT signed by dock key
- Stolen `config.json` is useless without the encrypted dock private key

### Rekor anchoring --default ON
- Every `treeship hub push` anchors to Rekor automatically
- The anchor receipt is stored as `treeship/receipt/v1` locally
- Hub cannot retroactively modify anchored chains

### SQLite security
- File at `/var/lib/treeship/hub.db`
- chmod 600, owned by process user
- No passwords or private keys in the database --only public keys and signed JSON
- Clean `dpop_jtis` older than 5 minutes on every request

### Revocation
- `GET /.well-known/treeship/revoked.json` --signed list of revoked key fingerprints
- Verifiers fetch and cache 24h

### Honest boundary
- Trust root is the machine. Root access breaks all guarantees.
- YubiKey/Secure Enclave support in v1.5 via the existing `Signer` trait.
- Document this clearly --don't pretend the chain is unconditionally unforgeable.

---

## 8. CLI UX RULES --FOLLOW IN EVERY COMMAND

- Every success prints a dim hint: `→ treeship <next-logical-command>`
- Errors include the fix: `treeship not initialized\n  run: treeship init`
- `--format json` on every command, stable schema
- Exit codes: `0` = ok, `1` = error, `3` = not initialized, `4` = usage
- No interactive prompts. Agents can't handle them.
- `TREESHIP_ACTOR`, `TREESHIP_PARENT`, `TREESHIP_TOKEN` env vars as flag fallbacks
- Respect `NO_COLOR` and `--no-color`
- `treeship wrap` always propagates subprocess exit code

---

## 9. STATEMENT TYPES --FIELD REFERENCE

All signed via `attestation::sign()`. The `id` field does NOT exist in statement structs.

```rust
// ActionStatement --the most common type
pub struct ActionStatement {
    pub type_:          String,         // "treeship/action/v1"
    pub timestamp:      String,         // RFC 3339
    pub actor:          String,         // "agent://researcher"
    pub action:         String,         // "tool.call"
    pub subject:        SubjectRef,
    pub parent_id:      Option<String>, // links into chain
    pub approval_nonce: Option<String>, // must match approval.nonce
    pub meta:           Option<serde_json::Value>,
}

// ApprovalStatement --gates actions via nonce
pub struct ApprovalStatement {
    pub type_:       String,   // "treeship/approval/v1"
    pub timestamp:   String,
    pub approver:    String,   // "human://alice"
    pub nonce:       String,   // random --must be echoed in action.approval_nonce
    pub expires_at:  Option<String>,
    pub delegatable: bool,
    pub scope:       Option<ApprovalScope>,
}

// HandoffStatement --agent-to-agent transfer
pub struct HandoffStatement {
    pub type_:        String,
    pub timestamp:    String,
    pub from:         String,
    pub to:           String,
    pub artifacts:    Vec<String>,
    pub approval_ids: Vec<String>,
}
```

---

## 10. FIXED BUGS --DO NOT REINTRODUCE

1. **Double-sign circular dependency** --Statement structs have NO `id` field. Sign once. ID lives on `Record` and `SignResult` only.

2. **Nonce binding not enforced** --`verify.rs` checks `action.approval_nonce == approval.nonce`. Do not remove or skip this.

3. **Session token in config** --`config.json` stores `dock_id` only. No tokens. DPoP proofs generated on-the-fly.

4. **Subprocess attack surface** --TypeScript SDK embeds `@treeship/core-wasm` directly. Does NOT spawn `treeship` as subprocess.

5. **WASM binary trust** --CLI embeds expected WASM hash at compile time. Browser verifies before executing. Do not skip the hash check.

---

## 11. WHAT TO READ IN THE CODEBASE FIRST

Read in this order:
1. `packages/core/src/attestation/pae.rs` --the PAE format
2. `packages/core/src/attestation/sign.rs` --how an artifact is created
3. `packages/core/src/attestation/verify.rs` --how an artifact is verified
4. `packages/core/src/statements/mod.rs` --all statement types
5. `packages/cli/src/main.rs` --command structure
6. `packages/cli/src/commands/wrap.rs` --the most important user command

---

## 12. AGENT ORCHESTRATION RULES

1. Read this file first, every time, before writing any code.
2. Never write to files outside your assigned scope.
3. The only inter-agent coupling is JSON schemas --agree on those first.
4. Revaz reviews and merges each wave before the next starts.
5. When in doubt about a design decision, check the cryptographic invariants in §5 --if it breaks those, don't do it.

---

## 13. CONTEXT

- **Zerker** is the company. **Treeship** is the open-source protocol and CLI. **treeship.dev Hub** is the hosted service.
- **SRI International and DARPA** are aligned research partners.
- Writing style: no em dashes, direct and concise, no corporate phrasing.
- The feature branch `feature/treeship-verify-v1` has the Rust rewrite --push and merge to main before any new agent work.
