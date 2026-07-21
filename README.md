<div align="center">

# Treeship

**Verifiable work history for AI agents.**

[![Crates.io](https://img.shields.io/crates/v/treeship-core.svg)](https://crates.io/crates/treeship-core)
[![npm](https://img.shields.io/npm/v/treeship.svg)](https://www.npmjs.com/package/treeship)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk.svg)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml/badge.svg)](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml)

Treeship is an open-source trust layer that records agent actions as signed artifacts,
binds them to per-agent keys and capability cards, and lets **each verifier apply its
own trust policy, offline**. Local capture works without any server; publishing is a
separate, explicit step. **The receipts are yours, not ours.**

</div>

---

## The problem

AI agents are doing real work — deploying code, processing transactions, making decisions. When someone asks *"what did the agent actually do, and was it allowed to?"*, the answer is usually a chat log. Chat logs are editable, screenshottable, deniable. They're a story, not evidence.

Treeship produces evidence: every **captured** action becomes a signed, timestamped, portable artifact that anyone can verify against their own trust roots — without trusting Treeship's servers and without a network connection. What Treeship can and cannot prove is spelled out [below](#what-treeship-proves--and-what-it-cannot); we'd rather you know the boundary than assume one.

## The 60-second local demo

No account, no server — and after the install, no network. Every output block below is real, captured from v0.20.

```bash
npm install -g treeship
treeship init
```

Wrap any command to get a signed artifact:

```bash
treeship wrap --action test.run -- npm test
```

```
+ receipt sealed
  ----------------------------------------
  id:       art_6df021803b626b1c2e0face3b53b7208
  command:  npm test
  exit:     0  passed
  elapsed:  398ms
  output:   sha256:183d9040996  (ok)
  files:    none detected
  chain:    root
  signed:   key_0ea751c13673b32c  (ed25519)
```

Verify it offline:

```bash
treeship verify last
```

```
✓ verified  (1 artifact . chain intact)
  target:        art_6df021803b626b1c
  actor:         ship://ship_7256c8d04a2e6ec3
  actor proof:   asserted
  action:        test.run
  time:          2026-07-16T17:20:01Z
```

Note the honest verdict: `actor proof: asserted`. A wrapped command proves *a specific key signed this record at this point in a hash chain* — it does not yet prove *which agent* was behind the key. That's what identity onboarding adds.

## Prove who did it

Give an agent its own key and a signed capability card in one command:

```bash
treeship onboard deployer --tools 'deploy.*,git.push'
```

```
✓ agent certificate created
  agent:      deployer
  valid:      365 days (until 2027-07-16T17:15:58Z)
  agent key:  key_97fe3be93ca7e2b7 (pinned under AgentCert)
✓ capability card attested
  agent:       agent://deployer
  key-bound:   yes (AgentCert)
  tools:       deploy.*, git.push
[4/4] trust bundle — hand these to a counterparty:
    treeship trust add key_97fe3be93ca7e2b7 ed25519:K8V6D33O1k2LsQY5y9i2WTigc2CoYvIwdT_-yGgDbPQ --kind agent_cert --yes
```

From then on, that agent's actions verify as **proven**, not asserted:

```
✓ verified  (1 artifact . chain intact)
  actor:         agent://deployer
  actor proof:   proven (key-bound)
  action:        deploy.production
```

And the agent can hand any counterparty a **presentation** — card, certificate chain, revocations — that verifies fully offline, revealing only the capabilities that verifier needs (selective disclosure, new in v0.20):

```bash
treeship present agent://deployer --disclose 'deploy.*' --out deployer.presentation.json
# counterparty runs, against THEIR pinned trust roots:
treeship verify-presentation deployer.presentation.json
```

```
✓ presentation
  agent:       agent://deployer
  signature:   verified (trusted key)
  key-bound:   yes (AgentCert)
  reveals:     selective — revealed 1 of 2 capabilities: [deploy.*]
  status:      verified (key-bound; staple unverified)
```

A static presentation proves the record, not the bearer; add `--challenge <nonce>` on both sides to prove live key control. Beyond this: `treeship history` (an agent's re-verified work log), `treeship profile` (a checkpoint-pinned track record where every number recomputes or is a provable lie), `treeship resolve` / `publish` / `audit` (network discovery with client-side verdicts), and `treeship match` (find agents by exercised, verified evidence).

## Gate actions on human approval

Approvals are scoped and single-use by default; the nonce binds the human's approval to the specific action it authorized:

```bash
# --expires takes any ISO 8601 timestamp; it must be in the future at attest time
approval=$(treeship attest approval \
  --approver human://alice \
  --description "deploy v2.1" \
  --allowed-actor agent://deployer \
  --allowed-action deploy.production \
  --max-uses 1 \
  --expires 2027-01-01T00:00:00Z \
  --format json | jq -r .nonce)

treeship attest action \
  --actor agent://deployer \
  --action deploy.production \
  --approval-nonce "$approval"

treeship verify last
# → ✓ verified   approved: human://alice
```

An unscoped bearer approval requires saying so explicitly (`--unscoped`). Replay of a consumed approval is rejected.

## Share it (optional, separate step)

Nothing above touched a network. Publishing is its own decision:

```bash
treeship hub attach        # one-time device-flow login (required before push)
treeship hub push last     # → public artifact page
treeship session report    # → shareable session report URL
```

Two honesty notes:

- The public receipt page's in-browser verdict is **structural** (Merkle consistency), not issuer-authenticated. Full signature verification against your trust roots happens locally: `treeship verify <artifact-id>`.
- The Claude Code plugin's SessionEnd hook **automatically runs `treeship session report`** when a hub is attached, which uploads the session receipt. If you want capture without auto-publishing, don't attach a hub (everything stays local), or detach with `treeship hub detach`.

The Hub stores immutable bytes, serves lookup indices and proofs, and enforces write auth ([DPoP](https://docs.treeship.dev/docs/api/overview)) — it never supplies trust verdicts. Server-side verification was deliberately retired (the endpoint returns `410 Gone`): a verifier you don't run yourself is not a verifier.

## What Treeship proves — and what it cannot

**Each verification surface proves:**

- A specific key signed these exact bytes (DSSE envelope, Ed25519).
- A signed child artifact names the parent you walked (hash-chain integrity).
- An artifact is included under a signed Merkle checkpoint.
- A card, certificate, revocation, or presentation satisfies **your pinned trust roots** — never a server's opinion.
- An attested profile recomputes from the log at its pinned checkpoint (or is a provable lie).

**What it cannot prove alone:**

- That an uncaptured action never happened. Capture is at the harness/wrapper boundary; completeness is not a cryptographic property.
- That a self-asserted actor label is an identity (`actor proof: asserted` vs `proven (key-bound)` — the CLI always tells you which).
- That the unsigned narrative parts of a session package are authentic. In a `.treeship` package, **only the artifacts and the Merkle root are cryptographically bound**; the timeline/side-effects/narrative come from the unsigned event log, and `treeship package verify` says so explicitly. The authenticated record of a session is the actor-signed `session.v1` record.
- That a signer's local clock is trusted time. Timestamps are claims by the signer; Merkle checkpoints order artifacts relative to each other.

Privacy is likewise scoped, not absolute: wrapped commands store SHA-256 digests of outputs, but the signed artifact also records the (sanitized) command line, exit code, the last output line as a summary, and modified file paths. Don't wrap commands whose *names* are secret. The full field-by-field capture inventory is in [`TREESHIP.md`](./TREESHIP.md).

## Trust model

Treeship doesn't decide trust globally. Each verifier decides, using pinned trust roots and local policy:

- Trust roots are per-power (v0.19 split): `agent_cert`, `cert_issuer`, `hub_checkpoint`, `hub_org`, `revoker`, `session_host`. You pin exactly which keys may vouch for what.
- Certificates are never accepted on their embedded key alone — verification fails closed until you pin an issuer.
- Receipts and presentations are portable bundles — verify anywhere, no callback to a Treeship API.
- The strongest path removes the registry entirely: `present --challenge` / `verify-presentation --challenge` is a direct, offline handshake between two parties.

## How it works

```
Agent / human action
        │
        ▼
  Treeship core (Rust)
        │
        ├─ Serialize statement (compact JSON, deterministic field order)
        ├─ Sign DSSE PAE bytes with Ed25519 (per-agent or ship key)
        ├─ Link to parent artifact (hash chain)
        └─ Append to Merkle log (inclusion + consistency proofs, signed checkpoints)
        │
        ▼
  Local store (.treeship/)
        │
        ├─ Session packages (.treeship bundles) + signed session.v1 records
        ├─ Cards / certificates / revocations / presentations
        ├─ Verifiers: CLI (full), WASM (structural receipt + certificate/capability)
        └─ Optional: hub publish, transparency anchoring, resolver
```

There is no single universal "verify" — different surfaces check different things, and each reports its own scope honestly:

| Surface | What it checks | Trust input |
|---|---|---|
| `treeship verify <artifact-id>` | Signatures + parent chain + approval binding | Local keys + pinned roots |
| `treeship verify <URL or package>` | Structure only → verdict is `structural-pass`, never `pass` | None (no issuer trust) |
| `treeship package verify` | Artifact + Merkle integrity; warns that narrative is unsigned | Local keys + pinned roots |
| `treeship verify-presentation` | Card + cert chain + revocations + staple, fully offline | **Your** pinned roots |
| `treeship verify-capability` | Card/action signatures + scope cross-check | Your pinned roots |
| `treeship verify-profile` | Envelope signature + field-by-field recomputation | Local keys + pinned roots |
| `@treeship/verify` (WASM) | Receipt structure, certificates, capabilities, cross-verify | `trustRoots` you pass (fails closed) |

## Install

### CLI

```bash
# One-liner: installs the CLI, runs treeship init, instruments detected agents
# (Claude Code, Codex, Kimi Code, Cursor, Hermes, OpenClaw)
curl -fsSL treeship.dev/setup | sh

# Or via npm (inspectable, signed package, no shell pipe)
npm install -g treeship
```

macOS arm64/x64 and Linux x86_64 (any distro, glibc or musl, single statically linked binary) are supported. Linux ARM64 is not yet shipped. Windows: use WSL. Full matrix: [install guide](https://docs.treeship.dev/guides/install#supported-platforms).

### Claude Code plugin

```bash
claude plugin marketplace add zerkerlabs/treeship
claude plugin install treeship@treeship
```

Every Claude Code session in a `.treeship/`-initialized project auto-records to a signed session package via SessionStart / PostToolUse / SessionEnd hooks. **Disclosure:** with a hub attached, the SessionEnd hook also auto-publishes the session report (see [Share it](#share-it-optional-separate-step)). Design: [`integrations/claude-code-plugin/`](./integrations/claude-code-plugin/).

### Other agent integrations

| Path | Description |
|---|---|
| `integrations/claude-code/` | Manual Claude Code wiring (no plugin) |
| `integrations/cursor/` | Cursor MCP wiring |
| `integrations/hermes/` | Hermes skill |
| `integrations/openclaw/` | OpenClaw skill |

Codex and Kimi Code are detected and instrumented by `treeship add` / the setup script (see [`integrations/agents.json`](./integrations/agents.json)).

## Packages

| Package | Registry | Path | Description |
|---|---|---|---|
| `treeship` | npm | `npm/treeship/` | CLI wrapper — auto-installs the right platform binary |
| `@treeship/sdk` | npm | `packages/sdk-ts/` | TypeScript SDK: CLI-backed signing + in-process WASM receipt/certificate verification |
| `@treeship/verify` | npm | `packages/verify-js/` | Zero-dependency verification (WASM + fetch), runs on Node / Deno / browser / edge |
| `@treeship/core-wasm` | npm | `packages/core-wasm/` | Rust core compiled to WebAssembly (~190 KB gzipped) |
| `@treeship/mcp` | npm | `bridges/mcp/` | MCP bridge — signed receipts for any MCP-speaking agent |
| `@treeship/a2a` | npm | `bridges/a2a/` | A2A bridge — attest and verify agent-to-agent task receipts |
| `treeship-sdk` | PyPI | `packages/sdk-python/` | Python SDK (wraps the CLI) |
| `treeship-core` | crates.io | `packages/core/` | Receipt engine, signing, Merkle tree, verification |

The CLI is distributed via npm + [GitHub Releases](https://github.com/zerkerlabs/treeship/releases), not crates.io. The reference Hub server (Go) lives at `packages/hub/`; the hosted instance serves the [Hub API](https://docs.treeship.dev/docs/api/overview) at `api.treeship.dev` (API only — no browsable root page). Self-hosting is supported.

## SDK examples

Both SDKs shell out to the `treeship` binary for signing — install the CLI and run `treeship init` first. These examples run as written against v0.20.

### TypeScript (`@treeship/sdk`)

```typescript
import { ship } from "@treeship/sdk";

const s = ship();

// Sign an action — returns { artifactId }
const { artifactId } = await s.attest.action({
  actor: "agent://researcher",
  action: "tool.call",
  meta: { tool: "search.web", query_digest: "sha256:..." },
});

// Verify the local artifact chain — { outcome: 'pass' | 'fail' | 'error', chain, target }
const result = await s.verify.verify(artifactId);

// Optional: publish (requires a prior `treeship hub attach`)
const { hubUrl } = await s.hub.push(artifactId);
```

For verification without a CLI (browsers, edge), use [`@treeship/verify`](https://docs.treeship.dev/docs/sdk/verify) — remembering that URL-fetched receipts earn `structural-pass`, and certificate checks require the `trustRoots` you pin.

### Python (`treeship-sdk`)

```python
from treeship_sdk import Treeship

ts = Treeship()

result = ts.attest_action(
    actor="agent://deployer",
    action="deploy.production",
    meta={"commit": "abc123", "env": "prod"},
)

verified = ts.verify(result.artifact_id)
print(f"Outcome: {verified.outcome}, chain: {verified.chain} artifacts")
```

## Standards

Treeship builds on existing primitives rather than inventing cryptography:

- **DSSE** (Dead Simple Signing Envelope) with PAE — compatible with the Sigstore / in-toto ecosystem
- **Ed25519** (RFC 8032) for all signatures
- **SHA-256** for content addressing and the Merkle tree
- Signing serializes statements as compact JSON with deterministic (declaration-order) fields — a fixed canonical form, though not full RFC 8785/JCS

## Status and roadmap

Current release: **v0.20.0**. The [`CHANGELOG.md`](./CHANGELOG.md) is the source of truth for what each release shipped; the living roadmap is [`docs/specs/vision.md`](./docs/specs/vision.md).

**Shipped**
- Signed artifacts, hash chains, Merkle inclusion + consistency proofs, signed checkpoints
- Per-agent keys, capability cards, certificates, revocation (v0.13+)
- Agent resolver with client-side verdicts, Hub publish, transparency audit (v0.14+)
- Signed `session.v1` work records; portable receipt export + independent reference verifier (v0.16, v0.19.1)
- Registry-free presentations with certificate chains and nonce challenges (v0.17)
- Work history and checkpoint-pinned, recomputable agent profiles (v0.18); evidence-based agent matching
- Split trust-root powers (v0.19); DPoP hub auth and device-flow login
- **Selective capability disclosure** — present a verifier only the capabilities it needs (v0.20)
- MCP + A2A bridges, Claude Code plugin, TypeScript/Python SDKs, WASM verifier on Node/Deno/browser/edge

**Experimental, explicitly non-authoritative**
- Zero-knowledge proofs: the prior Groth16 path was found unsound and is **quarantined**; a statement-first private-verification design supersedes it. Nothing in the default trust path depends on ZK. [Honest status](https://docs.treeship.dev/docs/concepts/zero-knowledge).

**Open**
- Linux ARM64 binary · transparent MCP forwarder mode · Anthropic plugin-directory listing
- Not planned: native Windows (use WSL) — [open an issue](https://github.com/zerkerlabs/treeship/issues) with a strong use case

## Documentation

- Docs site: **<https://docs.treeship.dev>**
- Capture inventory + agent-readable trust contract: [`TREESHIP.md`](./TREESHIP.md)
- Changelog: [`CHANGELOG.md`](./CHANGELOG.md)

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). All contributions welcome — code, docs, bug reports, security reviews. Security policy: [`SECURITY.md`](./SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2025–2026 Zerker Labs, Inc.
