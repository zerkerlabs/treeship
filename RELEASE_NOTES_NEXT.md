# Next Release: v0.7.0 (staged)

This file is a working doc for the in-progress release. It is read by Claude
sessions across multiple days so they can pick up where the previous session
left off. Append to it as new work lands. Move the contents into `CHANGELOG.md`
and delete this file when the release is cut.

## Headline

`@treeship/a2a` ships. Drop-in Treeship attestation for A2A (Agent2Agent)
servers and clients. The blog post and both doc sites are already live in
the repo (not yet published).

## Current monorepo version

All publishable packages are at **0.6.1**. The next release will be **0.7.0**.
The `CHANGELOG.md` file currently jumps from 0.5.0 to 0.7.0 because the
0.6.x line was not formally documented.

```
core:        0.6.1   (Cargo)
cli:         0.6.1   (Cargo)
sdk-ts:      0.6.1   (npm)
mcp:         0.6.1   (npm)
a2a:         0.6.1   (npm, new)
sdk-python:  see pyproject.toml
npm wrapper: see npm/treeship/package.json
```

## What is already done

- [x] `bridges/a2a` package built (src, tests, README, tsconfig)
- [x] 15 tests passing (`cd bridges/a2a && npx vitest run`)
- [x] CLI-missing path prints one actionable warning per process; tested
- [x] Mintlify docs page (`/Users/zzo/treeship.dev/docs/integrations/a2a.mdx`) and `docs.json` nav entry
- [x] Fumadocs page (`treeship/docs/content/docs/integrations/a2a.mdx`) and `meta.json` entry
- [x] Blog post (`treeship/docs/content/blog/a2a-treeship-the-trust-layer-for-agent-to-agent.mdx`)
- [x] `bridges/a2a` wired into `scripts/release.sh`
- [x] `bridges/a2a` publish step added to `.github/workflows/release.yml`
- [x] `CHANGELOG.md` 0.7.0 (unreleased) entry added

## What still needs to happen before publishing 0.7.0

- [ ] Decide whether 0.7.0 also bumps the Rust crates (`core`, `cli`,
      `core-wasm`) or whether they stay on 0.6.1. If yes, run
      `./scripts/release.sh 0.7.0` from `treeship/`.
- [ ] If only the npm packages bump, run `npm version 0.7.0
      --no-git-tag-version` in each of `packages/sdk-ts`, `bridges/mcp`,
      `bridges/a2a` and update the CHANGELOG date.
- [ ] Verify `release.yml` `publish-npm` step still works after the
      `@treeship/a2a` insertion. The step uses `continue-on-error: true`
      so a failure won't block the rest of the matrix, but check the
      Actions log on the first run.
- [ ] Confirm the `npmjs.com/package/@treeship/a2a` name is reserved
      under the `@treeship` org before tagging.
- [ ] Update `RELEASE_NOTES_NEXT.md` date in CHANGELOG from
      "(unreleased)" to the actual release date.
- [ ] Cross-post the blog: web.treeship.dev mirror, Hacker News, X.
- [ ] Bump `@treeship/sdk-python` if it shares the cadence (TBD).

## How to cut the release

From `/Users/zzo/treeship.dev/treeship/`:

```bash
# 1. Run tests one more time
(cd bridges/a2a && npx vitest run)
(cd bridges/mcp && npx vitest run)

# 2. Bump versions in lockstep
./scripts/release.sh 0.7.0

# 3. Update the CHANGELOG date
#    s/0.7.0 (unreleased)/0.7.0 (YYYY-MM-DD)/

# 4. Re-commit the CHANGELOG fix
git add CHANGELOG.md && git commit --amend --no-edit

# 5. Push and let GitHub Actions handle the rest
git push && git push --tags
```

The release workflow will publish `@treeship/sdk`, `@treeship/mcp`, and
now `@treeship/a2a` to npm in that order, then the CLI binary packages,
then the wrapper.

## Cross-session notes

- Em dashes are banned in user-facing copy (per saved feedback). All new
  docs and blog content already comply. Re-check on any edits.
- The blog post lives in the Fumadocs site (`treeship/docs/content/blog/`),
  not the Mintlify site (`docs/`). Mintlify is for reference docs only.
- The `@treeship/a2a` package is intentionally framework-agnostic. Do not
  add a hard dependency on any specific A2A SDK.
- The CLI-missing warning is gated by a one-time latch (`cliMissingWarned`)
  with a test-only `__resetCliMissingWarning()` reset. Do not export the
  reset from `index.ts`.

## Deferred to a later release (tracked, not started)

### WASM core migration for TS SDK + A2A bridge

Both `@treeship/sdk` and `@treeship/a2a` currently spawn the `treeship`
CLI as a subprocess for every attestation on the hot path. That works
but adds process fork overhead to every task lifecycle event and
breaks in restricted JS runtimes (edge workers, sandboxed CI, lambdas
without shell access).

The fix is to wire the hot path through `packages/core-wasm/`, which
already ships Groth16 verification and has the signing primitives in
place. Keep the CLI subprocess path only for stateful operations that
truly need the full binary (hub push/pull/attach, session close,
daemon).

Scope:

- Audit what `packages/core-wasm/src/` currently exports.
- Add WASM-backed `attestAction`, `attestReceipt`, `attestHandoff`,
  and digest helpers that match the TS shapes.
- Migrate `bridges/a2a/src/attest.ts` and `packages/sdk-ts/src/` to
  prefer the WASM path, fall back to subprocess when WASM is
  unavailable, and drop the subprocess path entirely a release later
  once telemetry shows nobody hits it.
- Do the SDK and A2A bridge migrations TOGETHER, not separately. They
  share the same attestation surface and diverging would force two
  rounds of dogfooding.

Do not start this in the 0.7.0 window. It is 0.8.0-scope.
