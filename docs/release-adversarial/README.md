# Release adversarial review — policy

Treeship's release discipline distinguishes **trust-semantics releases** from **bump-only releases**. The two get different treatment.

## When to run a targeted Codex adversarial review

**Run** the targeted Codex pass before or immediately after release for any change to:

- receipt composition
- approval semantics (grants, scope, nonce binding)
- replay / journal behavior
- package verification
- Hub checkpoint verification
- MCP / A2A bridges (sanitization, command privacy)
- tool authorization
- agent identity / cards
- harness coverage semantics
- public sharing / raw receipt exposure
- installer / bootstrap security

**Skip** the broad Codex pass for:

- CHANGELOG-only changes
- VERSION-only bumps
- package manifest pin updates
- release tag pushes that don't carry product code
- pure docs / website edits that don't change exported claims

For the skip cases, the existing release machinery is enough: `scripts/check-release-versions.py` (preflight + `--consistency`), CI (`version-consistency`, `test`, `hub`, cross-SDK matrix), and post-tag registry install smokes.

## How to run a targeted pass

The pass is **scoped to the actual diff**, not "find anything." The reviewer (Codex CLI in adversarial / "challenge" mode) gets:

1. The exact commit range (e.g. `git diff v0.9.8..v0.9.9 -- packages/ docs/` minus version-bump files).
2. A list of invariants the diff is supposed to maintain.
3. Specific attacks to try against each invariant.
4. A required output shape: BLOCKERS / IMPORTANT NON-BLOCKERS / COPY ISSUES / TESTS TO ADD / FILES / REPRO COMMANDS.

The threat-model template lives in `docs/release-adversarial/<version>.md` for every release that ran one. Reuse the template for the next release; tighten it as new attack classes are found.

## What to do with findings

Findings get triaged on the same scale every time:

| Finding | Severity | Action |
|---|---|---|
| Replay bypass | Blocker | Cut a `vX.Y.Z+1` patch immediately |
| Signature bypass | Blocker | Cut a patch |
| Secret leak (raw nonces, commands, prompts, file contents, bearer tokens) | Blocker | Cut a patch |
| Docs overclaim of a guarantee the code doesn't deliver | Copy issue | Docs patch (can ride next release) |
| Missing test that pins an existing invariant | Tests-to-add | Add in next hardening PR |
| Installer / agent-native UX issue | UX | Fold into next product release |

**Verify before treating as truth.** Codex tools sometimes hallucinate file paths or misread context. Every cited file:line gets independently read and the gap reproduced against the actual code before being recorded as a confirmed blocker. The triage doc should explicitly call out this verification step.

## Save the findings

Every targeted pass that finds anything (or even confirms a clean bill of health) is saved as `docs/release-adversarial/<version>.md`. The file follows the structure the v0.9.9 doc established:

- threat model used
- list of confirmed blockers, each with file:line + repro command + suggested fix
- non-blockers and copy issues
- tests to add post-fix
- triage decision (ship / docs patch / hotfix)
- attestation of the Codex run (CLI version, mode, verification approach)

This is the durable record. New releases reference prior findings to avoid regressing the same invariant twice.

## Re-check on the fix PR

When a hotfix lands the fixes for an adversarial-found blocker, run a **second** targeted Codex pass scoped to the fix diff alone:

1. Did each fix actually close the finding the original repro pinned?
2. Did the fix introduce a new bypass adjacent to the same surface?
3. Are there test coverage gaps that should land before the cutover?

The re-check is appended to the same `docs/release-adversarial/<version>.md` file, not a new file. The re-check is the merge gate for the fix PR.

## Why this exists

The v0.9.9 release published with four real trust-bypass paths in the new Approval Authority surface — a TOCTOU race in the consume path, ignored action↔use binding, an unbound `nonce_digest` field, and an unwalked embedded chain. Each one was a *replay* or *binding* bypass. None of them were caught by CI or by the version-consistency machinery, because none of those were the kind of bug those tools catch. The targeted Codex pass found all four.

The lesson: **trust semantics need an adversarial reader, not just tests.** Tests pin invariants you remembered to write tests for. An adversarial review hunts the invariant you forgot.

The lesson does NOT extend to bump-only releases. Running a broad Codex pass on a CHANGELOG-only PR is wasted budget and noise; that's why the policy is *targeted* and *gated by what changed*.

## Schedule

| Trigger | Adversarial pass? | Notes |
|---|---|---|
| New trust subsystem (e.g. v0.9.9 Approval Authority) | Yes | Pre-cutover or immediately post-tag |
| New bridge / sanitizer / authorization surface | Yes | Same |
| Receipt format change | Yes | Same |
| Package format extension (new fields, new sections) | Yes | Even if "just additive" |
| Bump-only cutover PR | No | Preflight + CI + smokes |
| Pure docs PR | No | Unless docs claim something the code doesn't deliver — then a copy review |
| Hotfix PR for previously-found blockers | Yes (re-check) | Scoped to the fix diff |

Update this table when a release category surfaces that doesn't fit either bucket.
