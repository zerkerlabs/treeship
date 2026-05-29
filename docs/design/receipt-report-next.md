# Receipt and Report Next: signed packages, bounded evidence, verifiable reports

Status: proposal / implementation plan
Owner: revaz
Date: 2026-05-29

This document consolidates the receipt/report redesign after the 0.11.1
session-close hardening release. It is based on the current code paths, the
0.11.1 incident fix, the earlier v2 and 10x design notes, and the Zerker Gateway
/ Zerker Memory integration direction.

The short version:

1. First, make the shared unit a signed package manifest, not just raw
   `receipt.json`.
2. Then make `receipt.json` bounded by moving raw evidence into committed
   sidecars.
3. Then turn the receipt into a verified claim surface: conformance,
   disclosure, lineage, and Gateway/Memory evidence planes.

## 1. Current Design

The current session path has three distinct objects:

- Session event log: `.treeship/sessions/<session_id>/events.jsonl`.
- Session receipt: `.treeship/sessions/<session_id>.treeship/receipt.json`.
- Session package: the `.treeship` directory with `receipt.json`,
  `merkle.json`, `render.json`, per-artifact proofs, `preview.html`, and optional
  approval evidence.

Important current code paths:

- `packages/cli/src/commands/session.rs::close`
- `packages/cli/src/commands/session.rs::report`
- `packages/core/src/session/event_log.rs`
- `packages/core/src/session/receipt.rs::ReceiptComposer::compose`
- `packages/core/src/session/package.rs::build_package_with_approvals`
- `packages/core/src/session/package.rs::verify_package_with_trust`
- `packages/hub/internal/receipts/receipts.go::PutReceipt`
- `packages/hub/internal/receipts/receipts.go::GetReceipt`

The current receipt is useful and deterministic, but it is not yet the final
trust shape:

- Artifact records are DSSE-signed and content-addressed.
- The receipt's Merkle section commits to artifact IDs.
- `package verify` checks parsing, deterministic reserialization, Merkle root,
  inclusion proofs, timeline ordering, approval evidence, and warning markers.
- The session receipt JSON itself is not currently a DSSE-signed envelope over
  the full receipt/package bytes.
- Hub receives only `receipt.json`, not the full `.treeship` package.

That distinction matters. Today `receipt.json` is a deterministic report over a
signed artifact chain. The next design should make the package itself the signed,
content-addressed object.

## 2. What 0.11.1 Fixed

The 0.11.1 hotfix closed the immediate runaway class:

- `session start` refuses a dangerous `$HOME` git root unless
  `--allow-dangerous-root` is passed.
- Close-time untracked reconciliation is bounded.
- Truncated reconciliation is recorded in-band under `proofs`.
- `session abandon` quarantines wedged sessions without deleting evidence.
- `session report` now distinguishes incomplete packages from missing packages.

That is necessary but not sufficient. It protects one input path. It does not
change the output model where full timeline and side-effect detail live inside
`receipt.json`.

## 3. Design Principles

### 3.1 Make trust claims precise

Never let a report imply a stronger claim than verification actually performed.

Use explicit grades:

- `full_package_verified`: signed package manifest verified, all mandatory
  sidecars present, artifact envelopes verify, warning markers understood.
- `bounded_package_verified`: package is signed and internally consistent, but
  one or more bounded/truncated evidence sources are present.
- `summary_verified`: raw `receipt.json` checks pass, but the verifier did not
  have the full package sidecars or artifact envelopes.
- `display_only`: data is rendered from Hub or upstream metadata but has not
  been locally verified.

### 3.2 Keep the receipt small

The receipt is the signed index and human/agent summary. It should not be the
warehouse of every event, file, token, and external packet.

### 3.3 Commit to evidence, do not always reveal it

The package should carry or reference sidecars by digest. A verifier can check
the evidence when available. A report can show a bounded summary when the raw
detail is private or large.

### 3.4 Keep Hub non-authoritative

Hub stores, indexes, and serves bytes. It should derive metadata from uploaded
content and reject mismatches, but it is not the trust root.

### 3.5 Integrate Gateway and Memory at the evidence boundary

Gateway decides. Memory governs recall. Treeship signs, commits, verifies,
transports, and renders their evidence. Treeship should not reimplement Gateway
policy evaluation or Memory authority logic.

## 4. Target Architecture

### 4.1 Package layout

Proposed `.treeship` package v2:

```text
<session_id>.treeship/
  receipt.json
  package-manifest.json
  package-manifest.dsse.json
  evidence/
    events.jsonl
    events.index.json
    side-effects.jsonl
    side-effects.summary.json
    artifacts.jsonl
    approvals/
    gateway/
    memory/
    anchors/
  artifacts/
    <artifact_id>.dsse.json
  proofs/
    <artifact_id>.proof.json
  render.json
  preview.html
```

`receipt.json` remains easy to read and stable for report rendering.

`package-manifest.json` is the canonical file list and evidence-plane index.

`package-manifest.dsse.json` is a DSSE `ReceiptStatement` that signs the
manifest digest. It should use the existing receipt statement machinery unless a
new statement type proves necessary. A minimal signed payload can carry:

```json
{
  "kind": "session_package_manifest",
  "session_id": "ssn_...",
  "schema_version": "2",
  "receipt_digest": "sha256:...",
  "package_manifest_digest": "sha256:...",
  "evidence_root": "sha256:..."
}
```

The DSSE envelope itself is outside the manifest digest to avoid circularity.
Verification recomputes `package_manifest_digest`, verifies the DSSE signature,
then checks every file and evidence-plane digest listed in the manifest.

### 4.2 Manifest shape

```json
{
  "schema": "treeship/session-package-manifest/v1",
  "session_id": "ssn_...",
  "receipt_digest": "sha256:...",
  "created_at": "2026-05-29T00:00:00Z",
  "files": [
    {
      "path": "receipt.json",
      "role": "summary",
      "sha256": "...",
      "size_bytes": 12345,
      "required": true
    }
  ],
  "evidence_planes": [
    {
      "name": "session_events",
      "root": "sha256:...",
      "count": 1204,
      "sidecars": ["evidence/events.jsonl", "evidence/events.index.json"],
      "complete": true
    },
    {
      "name": "artifact_chain",
      "root": "mroot_...",
      "count": 36,
      "complete": true
    },
    {
      "name": "gateway",
      "root": "sha256:...",
      "count": 0,
      "complete": false,
      "reason": "not_configured"
    }
  ],
  "verification_manifest": {
    "raw_receipt_checks": ["type", "merkle_root", "timeline_order"],
    "package_checks": ["manifest_signature", "sidecar_hashes", "artifact_envelopes"],
    "display_only_fields": ["narrative.summary"],
    "warnings": []
  }
}
```

### 4.3 Receipt v2 shape

Keep `type: "treeship/session-receipt/v1"` for compatibility unless we decide a
new top-level type is required. Use `schema_version: "2"`.

Add these sections:

```json
{
  "schema_version": "2",
  "package": {
    "manifest_digest": "sha256:...",
    "manifest_signature_artifact_id": "art_...",
    "package_digest": "sha256:..."
  },
  "evidence": {
    "event_count": 1204,
    "events_root": "sha256:...",
    "events_sidecar": "evidence/events.jsonl",
    "artifact_chain_root": "mroot_...",
    "approval_evidence_root": "sha256:..."
  },
  "coverage": {
    "capture_sources": [
      {"source": "hook", "events": 900},
      {"source": "git-reconcile", "events": 12}
    ],
    "warnings": [
      {
        "kind": "reconcile_completeness",
        "severity": "warn",
        "detail": "untracked reconcile exceeded cap"
      }
    ],
    "grade": "bounded_package_verified"
  },
  "summary": {
    "event_counts": {},
    "side_effect_counts": {},
    "top_files_written": [],
    "processes": [],
    "network": []
  },
  "timeline": []
}
```

`timeline` becomes a bounded embedded sample for v2. The full timeline lives in
`evidence/events.jsonl` and is committed by digest/root.

To prevent old consumers from silently treating the sample as complete, v2 must
also carry:

```json
{
  "timeline_policy": {
    "embedded": "sample",
    "total": 1204,
    "embedded_count": 200,
    "sidecar": "evidence/events.jsonl"
  }
}
```

### 4.4 Event sidecar commitments

The first implementation can keep sidecars simple:

- `events.jsonl`: canonical JSON lines for every sealed event.
- `events.index.json`: counts by type, first/last sequence, byte length,
  `sha256(events.jsonl)`, optional Merkle root over line hashes.

Later selective disclosure can build on the line-hash Merkle root.

### 4.5 Artifact envelopes

Every artifact referenced in `receipt.artifacts` should either have a DSSE
envelope in `artifacts/<artifact_id>.dsse.json`, or the package must explicitly
mark it missing:

```json
{
  "artifact_id": "art_...",
  "envelope_present": false,
  "verification": "not_asserted_by_package"
}
```

This makes package verification honest:

- Merkle membership over artifact IDs can pass with raw receipt JSON.
- DSSE signature verification requires the envelope sidecar.
- A report should not claim artifact signatures were verified unless the
  envelopes were present and checked.

### 4.6 Hub upload model

Keep `PUT /v1/receipt/{session_id}` for backwards compatibility.

Add a package upload endpoint:

```text
PUT /v2/receipt/{session_id}/package
Content-Type: application/vnd.treeship.package+tar
```

or a multipart equivalent.

Hub should:

1. Verify the manifest signature if possible.
2. Recompute manifest/file digests.
3. Derive metadata from content, not client-supplied hints.
4. Store package blobs content-addressed.
5. Serve stable public URLs:
   - `/receipt/<session_id>` human report
   - `/api/receipt/<session_id>` raw summary receipt
   - `/api/receipt/<session_id>/manifest`
   - `/receipt/<session_id>/package`
   - `/api/receipt/<session_id>/agent`

Hub still does not become authoritative. Public UI must say whether verification
ran locally in the browser or whether Hub only indexed the upload.

### 4.7 Gateway and Memory evidence planes

Add generic upstream evidence support before adding product-specific logic:

```json
{
  "upstream_system": "zerker-gateway",
  "upstream_schema": "com.zerker.gateway.treeship.statement",
  "upstream_schema_version": "1",
  "source_bundle_hash": "sha256:...",
  "source_bundle_verified": true,
  "upstream_hashes": {
    "decision_sha256": "...",
    "receipt_sha256": "...",
    "released_tool_call_sha256": "..."
  },
  "summary": {
    "release_status": "allow",
    "risk_tier": "medium",
    "action_class": "filesystem.write"
  }
}
```

For Gateway:

- Commit branch verdicts: ground, verify, remember, constrain, authorize.
- Commit release status: allow, deny, escalate, repair.
- Commit human review and execution confirmation when present.
- Do not re-evaluate policy in Treeship.

For Memory:

- Commit retrieved, injected, withheld memory IDs.
- Commit policy checks and memory Merkle root.
- Commit bundle hash and verification result.
- Do not re-evaluate memory authority in Treeship.

## 5. Implementation Plan

### Phase 0: docs truth pass

Goal: align docs with shipped reality before changing semantics.

Tasks:

- Clarify `/verify/<artifact_id>` vs `/receipt/<session_id>`.
- Update receipt PUT docs to write-once/idempotent semantics.
- Clarify raw receipt checks vs full package verification.
- Clarify WARN vs FAIL trust posture.
- Mark stale local-dashboard spec sections as historical or update them.

Verification:

- `python3 scripts/check-docs-routes.py`
- docs build if this branch touches generated docs config

### Phase 1: signed package manifest

Goal: make the `.treeship` package a signed, content-addressed object.

Core work:

- Add `PackageManifest`, `PackageFile`, `EvidencePlane`, and
  `VerificationManifest` structs in `packages/core/src/session/package.rs` or a
  new `manifest.rs`.
- Build canonical manifest bytes deterministically.
- Add package digest computation to core instead of CLI-only helper.
- Add verification checks:
  - manifest parses
  - manifest file digests match
  - receipt digest matches
  - manifest DSSE envelope verifies
  - package signature artifact ID matches

CLI work:

- During `session close`, sign a `ReceiptStatement` for the manifest digest.
- Write `package-manifest.json` and `package-manifest.dsse.json`.
- Print the package manifest digest in close output.

Tests:

- Tampering with any listed file fails manifest verification.
- Tampering with manifest fails DSSE verification.
- Removing `package-manifest.dsse.json` downgrades to legacy v1 verification with
  a warning, not a false pass.
- v1 packages still verify byte-identically.

### Phase 2: artifact envelopes in packages

Goal: make offline package verification able to verify artifact signatures, not
only artifact IDs and Merkle proofs.

Tasks:

- Include every referenced artifact envelope under `artifacts/`.
- If an envelope is missing from local storage, record a missing-envelope marker.
- Add package verifier rows for `artifact_signature:<id>`.
- Update `preview.html` and dashboard to show "signature verified" only when the
  envelope was present and checked.

Tests:

- Package with valid envelopes passes DSSE checks.
- Package with tampered envelope fails.
- Package with missing envelope warns `artifact_signature:not_asserted`.

### Phase 3: bounded receipt v2 sidecars

Goal: make receipt composition cost bounded by caps, not event count.

Core work:

- Add streaming event summarizer.
- Add `timeline_policy`, `summary`, `coverage`, and `evidence` sections.
- Cap embedded timeline and side-effect arrays.
- Write full event/detail sidecars and commit them by digest/root.

CLI close work:

- Seal from a snapshot: line count and byte offset captured under close lock.
- Read only the sealed prefix plus bounded close-generated events.
- Avoid using full `Vec<SessionEvent>` when a streaming summary is enough.

Tests:

- Synthetic 100k event session closes under a fixed time/memory budget.
- Synthetic 1M event event-log package remains small in `receipt.json`.
- Full sidecar digest verifies.
- Truncation markers change verification status to `bounded_package_verified`.

### Phase 4: Hub package upload

Goal: publish the full signed package, not only `receipt.json`.

Hub work:

- Add package upload route.
- Add package blob/session tables or a content-addressed blob store.
- Derive metadata from receipt/manifest.
- Keep v1 raw receipt route working.

CLI work:

- `session report` uses package upload when manifest exists.
- JSON output includes package manifest URL, package URL, verification grade, and
  exact upload mode (`package_v2` or `receipt_v1`).

Tests:

- Upload package, fetch package, local verify fetched package.
- Hub rejects mismatched path/body session ID.
- Hub rejects manifest digest mismatch.
- v1 report remains supported.

### Phase 5: browser/WASM report verification

Goal: the public report verifies before it says "verified."

Work:

- Extend `core-wasm` and `@treeship/verify` for package manifests and sidecar
  digests.
- Report UI distinguishes:
  - locally verified
  - summary verified
  - Hub indexed only
  - failed
- Add embeddable badge that links to a verifiable report.

Tests:

- Browser/worker verifies a real fixture package.
- Badge renders warning state when sidecars are missing.
- Tampered package fixture fails.

### Phase 6: conformance and upstream evidence

Goal: make receipts say "what was allowed" without making Treeship the policy
engine for every product.

Work:

- Add generic `upstream_evidence` evidence plane.
- Add Gateway statement adapter contract.
- Add Memory statement adapter contract.
- Add local conformance section for Treeship-native declarations:
  tool scope, file scope, network scope, approval discipline.
- Make conformance result explicit: `pass`, `fail`, `partial`, `not_evaluated`.

Tests:

- Treeship-native unauthorized tool produces `fail`.
- Missing gateway bundle produces `not_evaluated`, not `pass`.
- Gateway bundle hash mismatch fails closed.
- Memory bundle with withheld IDs renders accurately without re-evaluation.

### Phase 7: selective disclosure and reputation

Goal: turn committed evidence into privacy-preserving proofs and long-term trust
signals.

Work:

- Merkle inclusion proofs over event sidecars.
- Sorted commitment for non-inclusion predicates.
- `treeship disclose` for common predicates.
- Optional ZK circuits over event/gateway/memory roots.
- Recomputable trust score from signed public receipts.

## 6. Sub-Agent Workstreams

Use sub-agents for parallel implementation only after Phase 0 is merged. Keep
write scopes disjoint.

### Agent A: Core integrity

Ownership:

- `packages/core/src/session/package.rs`
- new `packages/core/src/session/manifest.rs` if needed
- core tests under `packages/core/tests/`

Deliverables:

- Package manifest structs.
- Deterministic manifest serialization and digest.
- Manifest verification rows.
- Legacy v1 compatibility tests.

### Agent B: CLI close and report

Ownership:

- `packages/cli/src/commands/session.rs`
- `packages/cli/src/main.rs`
- CLI tests

Deliverables:

- Sign manifest at close.
- Write manifest and DSSE envelope.
- Include artifact envelopes.
- Report JSON v2 fields.
- Snapshot close and sidecar writing in Phase 3.

### Agent C: Hub package storage

Ownership:

- `packages/hub/internal/receipts/`
- `packages/hub/internal/db/`
- `packages/hub/main.go`

Deliverables:

- v2 package upload/fetch endpoints.
- Content-derived metadata.
- Backward-compatible v1 receipt routes.
- Hub tests for write-once and digest mismatch.

### Agent D: Browser verifier and report surface

Ownership:

- `packages/core-wasm/`
- `packages/verify-js/`
- local `preview.html` and dashboard report rendering

Deliverables:

- Package manifest verification in WASM.
- Public/report verification result model.
- Badge contract and fixture tests.

### Agent E: Docs and contracts

Ownership:

- `docs/content/docs/concepts/session-receipts.mdx`
- `docs/content/docs/cli/package.mdx`
- `docs/content/docs/cli/session.mdx`
- `docs/content/docs/api/receipt-*.mdx`
- `AGENTS.md`, `ONBOARDING.md` if needed

Deliverables:

- Truthful trust model docs.
- WARN vs FAIL semantics.
- v1 vs v2 compatibility.
- API contract docs.

### Agent F: Gateway and Memory adapter contracts

Ownership:

- `docs/design/zerker-treeship-integration.md`
- future adapter packages after the package manifest lands

Deliverables:

- Gateway statement schema.
- Memory statement schema.
- Verification manifest language for upstream evidence.
- No in-process coupling.

## 7. Cron and CI Jobs To Add

These should be GitHub Actions or repo scripts, not ad-hoc local automations.

### Nightly large-session regression

Schedule: nightly.

Purpose: prevent another unbounded close/report path.

Command shape:

```bash
scripts/smoke-large-session.sh --events 100000 --files 10000
```

Assertions:

- close finishes under budget
- `receipt.json` stays below size budget
- package verify passes or warns only expected bounded warnings
- no unbounded memory growth

### Nightly public package canary

Schedule: nightly.

Purpose: keep npm, PyPI, GitHub Release, and report semantics honest between
releases.

Command shape:

```bash
.github/scripts/publish-smoke.sh latest
```

or resolve `latest` to the latest GitHub release tag first.

Assertions:

- npm install path works
- PyPI bootstrap path works
- session close/report no-upload works
- public docs session page contains current commands

### Weekly docs truth audit

Schedule: weekly.

Purpose: catch drift between CLI flags, Hub API behavior, and docs.

Checks:

- `scripts/check-docs-routes.py`
- generated CLI help diff against docs snippets
- receipt PUT docs say write-once
- session docs mention `abandon`, dangerous-root guard, and package warnings

### Nightly Hub package canary

Schedule: nightly after Phase 4.

Purpose: verify package upload/fetch from staging Hub.

Flow:

1. Create a synthetic session.
2. Close and build signed package.
3. Upload package to staging Hub.
4. Fetch package.
5. Verify fetched package locally and via WASM.

### Weekly fixture compatibility audit

Schedule: weekly.

Purpose: ensure old receipts/packages keep verifying.

Flow:

- Verify committed v0.7.2 and v0.8.0 fixtures.
- Verify v1 package fixtures.
- Verify v2 signed package fixtures.
- Verify tamper fixtures fail for the expected reason.

## 8. Immediate Next Cut

The next implementation cut should be Phase 0 plus Phase 1:

1. Fix docs truthfulness around raw receipt vs full package trust.
2. Add signed package manifest to new packages.
3. Keep v1 package verification working.
4. Do not change Hub upload yet.
5. Do not start conformance/Gateway work yet.

This gives the product a better trust foundation before making the report more
ambitious.

