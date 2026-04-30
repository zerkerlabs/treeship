# Changelog

## 0.9.8 (2026-04-30)

The agent-legibility release. v0.9.6 made the receipt trustworthy. v0.9.7 made the release process trustworthy. v0.9.8 makes the agent experience obvious: install Treeship, run one command, and immediately see which agents are on this machine, how Treeship is attached to each, what coverage to expect, and what's actually been proven on this workspace.

The framing the rest of the release builds on: **harnesses make agents observable, cards make agents accountable, receipts make their work verifiable**. Cards describe *who* an agent is and *what* it's allowed to do; harnesses describe *how* Treeship attaches and observes; the two stay in separate files (`.treeship/agents/<id>.json` vs `.treeship/harnesses/<id>.json`) so a future surface with multiple harnesses or a harness that instruments many agents doesn't need a schema change. The most important trust-semantics move in this release is the split of `Captures` (what a harness *could* observe if attached and working) into manifest-level `PotentialCaptures` and state-level `VerifiedCaptures` (what's actually been proven by a harness-specific smoke on this machine). Setup's generic round-trip smoke promotes harnesses to `instrumented`, never to `verified`; the latter is reserved for v0.9.9's per-harness smokes that exercise each capture signal individually. UI code physically cannot show one in the other's slot because they are different types.

The "extend, don't fork" architectural call ran through every PR: each addition reused the existing modules (`discovery::discover`, `cards::list`, `harnesses::HARNESSES`, the existing `add` instrumenter, the existing source-provenance fields on `FileAccess`) instead of producing a parallel detector or schema. A new builder running `treeship setup` and reading a session report sees agents found, cards drafted, harnesses instrumented, files tagged with their capture source -- without Treeship having grown two of anything.

### Added (discovery + agent inventory)

- **`treeship add --discover` -- read-only discovery surface.** `packages/cli/src/commands/discovery.rs`. New module with `AgentSurface`, `ConnectionMode`, `CoverageLevel`, `Confidence`, `DiscoveredAgent`. Detects Claude Code, Cursor, Cline, Codex, Hermes, OpenClaw, Ninja Dev (NinjaTech local IDE), generic MCP fallbacks, and shell-wrap custom agents. SuperNinja appears as an always-on low-confidence hint pointing at the (deferred) `treeship agent invite` flow rather than going silent. Read-only, no config writes, stable JSON shape via `--format json` so downstream tooling can consume it.
- **Agent Card store at `.treeship/agents/<id>.json`.** `packages/cli/src/commands/cards.rs`. Per-workspace JSON inventory keyed on a deterministic `agent_id = sha256("<surface>|<host>|<workspace>")[..8]` so re-running discovery is idempotent. Card lifecycle: `Draft` → `NeedsReview` → `Active` → `Verified`. Card provenance: `Discovered` | `Registered` | `Manual`. Capabilities mirror the v0.9.6 ApprovalScope vocabulary (`bounded_tools`, `escalation_required`, `forbidden`).
- **`treeship agents list / review / approve / remove`.** `packages/cli/src/commands/agents.rs`. Text + JSON output. `Verified` is intentionally not exposed as a manual flag; only a smoke session that proves capture writes that status.
- **Certificate-digest drift demotion.** `cards::upsert` compares the incoming card's `certificate_digest` against the stored card; if they differ and the existing status was `Active` or `Verified`, the merged status drops to `NeedsReview`. Re-registering an agent therefore cannot leave a previously-approved card pointing at a certificate the user never saw.
- **`treeship agent register` writes a card alongside the `.agent` package.** `packages/cli/src/commands/agent.rs`. The signed certificate stays the portable artifact; the card is the local trust object that `treeship agents` lists. Same data, two sites, no schema fork.

### Added (setup orchestration)

- **`treeship setup [--yes] [--skip-smoke] [--no-instrument]`.** `packages/cli/src/commands/setup.rs`. Composition over the existing PR 1 / PR 2 modules: `discovery::discover` → `cards::upsert` → confirmation prompt → existing `add::run` instrumenter → smoke session inside an isolated tmpdir → state promotion. Non-interactive without `--yes` defaults to a safe "no" so CI invocations never touch user configs without permission. If no Treeship config exists, setup points at `treeship init` rather than auto-initializing -- silently creating a global config when the user might have expected a project-local one would surprise.
- **Setup's smoke session is the v0.9.7 trust-fabric round-trip in a tempdir.** Runs `init` → `session start` → `wrap` → `session close` → `package verify` against an isolated keystore. Promotes instrumented cards to `Active` and instrumented harnesses to `Instrumented`. **Never** to `Verified` -- the smoke proves Treeship's pipeline works, not that any specific harness's capture path fired.

### Added (Harness Manager)

- **`harnesses::HarnessManifest` -- declarative profile per surface.** `packages/cli/src/commands/harnesses.rs`. Ten manifests (six installable + four honest non-installable). Each carries `harness_id`, `surface`, `display_name`, `connection_modes`, `coverage`, `captures: PotentialCaptures`, `known_gaps`, `privacy_posture`, `recommended_backstops`, and `install: Option<InstallProfile>`. The four "no auto-installer" manifests (SuperNinja remote, Ninja Dev IDE, generic-mcp, shell-wrap) describe surfaces Treeship knows about but cannot auto-attach to today; `treeship harness inspect` is honest about each.
- **`HarnessState` per-workspace store at `.treeship/harnesses/<id>.json`.** Status lifecycle: `Detected` → `Available` → `Instrumented` → `Verified` (with `Drifted` / `Degraded` / `Disabled` reserved for future use). Carries `last_smoke_result`, `last_verified_at`, `linked_agent_ids`, frozen `known_gaps`, and -- the load-bearing v0.9.8 trust field -- `verified_captures`. `upsert_state` merges verified captures monotonically (a smoke that proves `files_read` does not erase a prior run that proved `mcp_call`).
- **`treeship harness list / inspect / smoke`.** `packages/cli/src/commands/harness.rs`. `inspect` shows two distinct rows -- "potential captures (when attached and working)" and "verified captures (proven by harness-specific smoke)" -- so consumers physically can't conflate the two. JSON keys are separate objects (`potential_captures`, `verified_captures`).

### Added (integration template profile table)

- **`harnesses::HARNESSES` table replaces PR 4's branching `add.rs` install dispatch.** What used to be three install functions (`install_mcp_config` for Claude/Cursor/Cline, `install_codex_mcp_config` for Codex, `install_skill` for Hermes/OpenClaw) is now one row per surface with `install_method` (`JsonMcp` | `TomlMcp` | `SkillFile`), `snippet`, `config_path: fn(&Path) -> PathBuf`, and `idempotency: fn(&Path) -> bool`. Adding a new instrumentable surface is one row in `HARNESSES`; nothing in `add.rs` changes. Detection itself moved to `discovery::discover` everywhere, ending the duplicate `detect_agents()` that lived in both `add.rs` and `discovery.rs`.

### Added (session report polish)

- **Files Changed panel with source badges.** `packages/cli/src/commands/package.rs`. `treeship package inspect <pkg>` renders every read/written file with a badge from the existing `FileAccess.source` provenance: `[hook]`, `[mcp]`, `[git-reconcile]`, `[shell-wrap]`, `[session-event-cli]`, `[daemon-atime]`, `[unknown]`. Treeship's own runtime artifacts (`.treeship/session.json`, `.treeship/session.closing`, `.treeship/sessions/**`, `.treeship/artifacts/**`, `.treeship/tmp/**`) are filtered out of the list, with the count shown explicitly so a quiet list never masquerades as complete. User-authored trust files (`.treeship/config.{yaml,json}`, `.treeship/policy.yaml`, `.treeship/agents/**`, `.treeship/harnesses/**`, `.treeship/declaration.json`) are preserved.
- **Agent Cards panel.** Reads `cards::list` against the workspace card store; renders status, surface, harness id, model, host. No schema fork; same data the standalone `treeship agents` command shows.
- **Harness Coverage panel.** Reads `harnesses::list_states` joined with `HARNESSES`; renders status, coverage, two distinct rows for potential vs verified captures (preserving the trust-semantics split), last smoke summary, and the first two `known_gaps` per harness. Surfaces honest gaps in the report rather than burying them in `harness inspect`.

### Added (project-local config discovery and CLI ergonomics)

- **`AgentCard.active_harness_id` and `DiscoveredAgent::recommended_harness_id()`.** Each card points at the harness it's attached through; each discovery output advertises the harness Treeship recommends for that surface. JSON output of `treeship add --discover --format json` includes the recommendation per detection so external orchestration can use it without re-deriving from surface.
- **First-run docs.** `docs/content/docs/guides/first-run.mdx`, `docs/content/docs/concepts/agent-cards.mdx`, `docs/content/docs/concepts/harnesses.mdx`, `docs/content/docs/guides/coverage-levels.mdx`, `docs/content/docs/integrations/ninjatech.mdx`, plus `meta.json` updates so the new pages appear in the docs sidebar. The integration page is explicit about Ninja Dev (local, manual register today) versus SuperNinja (remote, basic coverage until v0.9.9 invite/join).

### Changed (trust semantics)

- **Setup's smoke does not flip cards or harnesses to Verified.** Cards from setup move `Draft → Active`; harnesses move `Detected → Instrumented`. `last_verified_at` stays `None`. The completion summary spells out: "Each harness is now `instrumented`. Per-harness capture is NOT yet verified. Run a real session through each harness to populate verified_captures and reach `verified`." The previous PR 5 first cut promoted everything to Verified after the generic round-trip; that over-claim is fixed before the v0.9.8 release.
- **`PotentialCaptures` and `VerifiedCaptures` are different types.** Bools per signal on the manifest (`PotentialCaptures.files_read: bool`); per-signal `Option<bool>` on state (`VerifiedCaptures.files_read: Option<bool>`). UI cannot render one in the other's slot. `harness inspect` text and JSON show the rows as "potential captures (when attached and working)" and "verified captures (proven by harness-specific smoke)".
- **`HarnessStatus::Verified` is reserved for harness-specific smokes.** v0.9.8 ships the type, the lifecycle, and the file format; the smokes that *populate* `VerifiedCaptures` per-signal are deferred to v0.9.9 alongside the per-harness capture fixtures.

### Intentionally deferred to v0.9.9 / later

- `treeship agent invite` / `treeship join --invite` for remote/VPS/SuperNinja attach. Today the SuperNinja harness is honest about being remote and points users at the future flow.
- GitHub verification surface (PR Check, Actions artifact, sanitized verification manifest).
- Per-harness smokes that exercise specific capture signals (the path to actually populating `verified_captures`).
- Approval Use Journal, Hub/global replay, issuer/registry identity, full AgentGate runtime enforcement. Those compose into the next major release after v0.9.8.

## 0.9.7 (2026-04-29)

The hardening release. v0.9.6 shipped the trust-fabric correctness chain -- scoped approvals, capture-normalize-verify, honest replay posture -- but the v0.9.6 cut itself missed PyPI on the first pass: `packages/sdk-python/pyproject.toml` was 0.9.5 when the v0.9.6 tag fired, so npm and crates published 0.9.6 while PyPI either built the wrong version or skipped publish entirely. A separate batch of internal `@treeship/core-wasm` pins was also stale -- `bridges/mcp` and `bridges/a2a` declared 0.9.4, `packages/verify-js` declared 0.9.5 -- so users installing those packages at 0.9.6 actually pulled an older verifier than the SDK declared. The post-publish per-package version checks already in `release.yml` caught neither failure mode because they ran *after* each publish committed.

v0.9.7 closes that class of bug. A single source-of-truth preflight script now walks every release-version site -- Cargo `[package]` versions, the workspace-internal `treeship-core` pin, every published `package.json`, the npm wrapper's `optionalDependencies` routing to platform CLIs, every `dependencies['@treeship/core-wasm']` pin, `pyproject.toml`, and `treeship_sdk/__version__` -- and either checks them against the explicit tag version (release-time, blocking every publish job) or anchors on `packages/core/Cargo.toml` and asserts internal consistency on every PR. The PyPI publish step refuses to upload artifacts whose filenames don't carry the expected version, so a stray drift between `pyproject` and the tag fails the release before twine touches the registry. The release script itself is split into `prepare` (bump + commit, no tag) and `tag` (explicit subcommand, mandatory `--sha`, refuses dirty trees and pre-existing tags, requires typed confirmation) so accidental tagging is structurally impossible.

The release also makes day-to-day operation kinder. Project-local `.treeship/config.json` discovery means a workspace can keep its own keystore even when the user's global `~/.treeship` is broken; `treeship doctor` now reports which config tier (`explicit (--config)`, `env (TREESHIP_CONFIG)`, `project-local`, or `global`) actually fired, with the resolved path, so debugging "wrong keystore" doesn't require strace. A checked-in trust-fabric acceptance smoke runs in CI on every PR, exercising init → session start → wrap → close → package verify against an isolated keystore.

No new trust subsystem in v0.9.7. The Approval Use Journal remains the v0.10 target; agent discovery, Agent Cards, and NinjaTech onboarding are v0.9.8.

### Added (release machinery)

- **`scripts/check-release-versions.py` -- single-source preflight covering 21 version sites.** Walks Cargo `[package]` versions for `treeship-core` / `treeship-cli` / `treeship-core-wasm`, the workspace-internal `treeship-core` pin in the CLI, every published `package.json` (`@treeship/sdk`, `@treeship/mcp`, `@treeship/a2a`, `@treeship/verify`, `treeship` wrapper, three platform CLIs), every `dependencies['@treeship/core-wasm']` pin, the wrapper's `optionalDependencies` routing, `pyproject.toml`, and `treeship_sdk/__version__`. Two modes: explicit-target (`<version>`) for release time and `--consistency` (anchors on `packages/core/Cargo.toml`) for PR time.
- **`preflight` job in `.github/workflows/release.yml`.** Runs first; every other release job (`build`, `release`, `publish-npm`, `publish-crates`, `publish-pypi`) is a transitive `needs:` of it, so a manifest mismatch blocks the entire pipeline before any registry sees a publish.
- **`version-consistency` job in `.github/workflows/ci.yml`.** Runs the preflight in `--consistency` mode on every PR. Catches drift weeks before a release tag would have.
- **`tests/acceptance/trust-fabric.sh` -- checked-in acceptance smoke + T1-T9 scaffolding.** Drives the CLI through a real session round-trip (`init`, `session start`, `wrap`, `session close`, `package verify`) inside an isolated tmpdir keystore. Wired into `ci.yml` after the build step. T1-T9 from the v0.9.6 trust-fabric run remain documented as scaffolds for a follow-up port.

### Added (CLI ergonomics)

- **Project-local `.treeship/config.json` discovery.** `packages/cli/src/config.rs::resolve_config_path()`. Walks up from cwd looking for `.treeship/config.json` before falling back to `~/.treeship`, with one safety rail: a hit at exactly `$HOME/.treeship/config.json` is *not* labelled project-local (that path *is* the global, and labelling it otherwise would mislead users running from `$HOME`). A corrupt global config no longer blocks a project-local config from working.
- **`ConfigSource` enum with four tiers and an explicit precedence.** `Explicit (--config)` > `Env (TREESHIP_CONFIG)` > `ProjectLocal` (walk-up) > `Global` (fallback). `Ctx` carries the resolved source so any command can report it.
- **`treeship doctor` reports config source and path.** New line: `config source   project-local -- /path/to/.treeship/config.json`. v0.9.6 had no signal here; a user with a misbehaving keystore had to grep code to figure out which lookup tier fired.

### Changed (release tooling)

- **`scripts/release.sh` split into `prepare` and `tag` subcommands.** `prepare <version>` bumps every version site, runs preflight, commits -- and stops. It contains no `git tag`, `git push --tags`, or `git push origin v*` invocation. `tag <version> --sha <sha> [--yes]` is the only path that can create a tag, and it requires: an explicit subcommand, a mandatory `--sha` (no implicit HEAD), a clean working tree, no pre-existing local or remote tag, and either `--yes` or an interactive `type 'tag <version>' to confirm` gesture. The legacy `scripts/release.sh <version>` form is removed -- it errors out with an explanation rather than silently falling through to the old behavior, which previously produced an accidental local tag during v0.9.7 cutover preparation.
- **PyPI publish step refuses wrong-version artifacts.** `.github/workflows/release.yml`. The step now (1) cleans `dist/`, `build/`, and `*.egg-info/` before `python -m build`, (2) computes `EXPECTED_WHEEL=dist/treeship_sdk-${VERSION}-py3-none-any.whl` and `EXPECTED_SDIST=dist/treeship_sdk-${VERSION}.tar.gz` and refuses to continue if either is missing, (3) refuses to continue if any unexpected artifact is in `dist/`, (4) runs `twine check` on the exact expected paths to catch metadata problems server-PyPI would also reject, and (5) calls `twine upload --skip-existing "$EXPECTED_WHEEL" "$EXPECTED_SDIST"` instead of a blind `dist/*` glob. With this chain, a `pyproject.toml` drift can no longer land the wrong version on PyPI.
- **`config::default_config_path()` preserved as a thin wrapper.** Existing callers keep working; the source-aware lookup goes through the new `resolve_config_path()` which returns `(PathBuf, ConfigSource)`.

### Fixed

- **Stale `@treeship/core-wasm` pins aligned with the current release.** `bridges/mcp/package.json` (was 0.9.4), `bridges/a2a/package.json` (was 0.9.4), `packages/verify-js/package.json` (was 0.9.5), and `packages/sdk-ts/package.json` (was `^0.9.4`) now pin exactly to the published `@treeship/core-wasm`. Surfaced by the new preflight; `release.sh prepare` now sweeps these forward at every bump.

## 0.9.6 (2026-04-27)

The trust-fabric release. v0.9.5 shipped *receipts* with cryptographic integrity but no comparison surface: a session could attest "the agent called Read 14 times" without anyone checking whether Read was even on the agent's authorized tool list, and a receipt's `files_written` could quietly omit anything that escaped the captured tool channel (a `sed -i` inside a Bash command, a build output, a manual edit). v0.9.6 closes both holes by building out the full capture-normalize-verify chain: every file the agent touches is captured by at least one of three layers (hook, MCP, or git reconciliation), every tool call is normalized through canonical aliases so cross-verification can compare claimed authorization against actual usage, and the receipt now signals when capture itself was incomplete instead of silently truncating.

It also tightens the **approval grant** model. v0.9.5 approvals carried only a nonce -- the cryptographic binding was real, but the same nonce could be replayed across unlimited actions and across different actions entirely. An approval to `deploy.production` could authorize a `deploy.staging` action; verify still printed `single-use enforced` because the binding was intact. v0.9.6 adds an `ApprovalScope` object that signs *who* (`allowed_actors`), *what* (`allowed_actions`), *where* (`allowed_subjects`), and *how many times* (`max_actions`) into the grant; verify now checks actor / action / subject statelessly and refuses the actions that don't match. The verify output is rewritten to report **only what was actually checked** -- three separate lines for binding, scope, and replay posture -- with explicit ⚠ warnings instead of false confidence claims.

The "trust fabric" framing is now load-bearing: an audit reader looking at a v0.9.6 receipt can answer *did this agent stay inside its bounds* with the same confidence they could already answer *was this signature valid*.

### Added (approval grant model)

- **`ApprovalScope` carries actor / action / subject allow-lists and max-uses.** `packages/core/src/statements/mod.rs`. `ApprovalScope` previously held only `max_actions`, `valid_until`, and `allowed_actions`; v0.9.6 adds `allowed_actors` and `allowed_subjects`. The grant now answers "who may consume this approval, to do what, against which subject, how many times." `is_unscoped()` returns true when no axis is populated -- verify uses this to emit a warning instead of a false authorization claim. New fields default-empty and `skip_serializing_if`-omitted, so a 0.9.5 approval payload deserializes cleanly into a 0.9.6 `ApprovalScope` (legacy roundtrip test pinned).

- **`treeship attest approval` flags: `--allowed-actor`, `--allowed-action`, `--allowed-subject`, `--max-uses`, `--unscoped`.** `packages/cli/src/main.rs`, `packages/cli/src/commands/attest.rs`. Each `--allowed-*` flag is repeatable. `--max-uses N` is signed into the grant for future ledger enforcement (verify reports replay posture honestly and does not yet claim global single-use). `--unscoped` is the explicit opt-in for bearer approvals -- without any scope axis AND without `--unscoped`, the CLI now refuses to mint the approval (defaults to safe).

- **`treeship attest action --subject <URI>` for symmetric scope binding.** Alias for the existing `--content-uri`. Lets callers naturally write `attest approval --allowed-subject env://prod` and `attest action --subject env://prod` and have the verifier match them.

- **`packages/core/src/statements/mod.rs::ApprovalScope::is_unscoped()`.** Public predicate exposed so SDK consumers and the verify pass agree on the same definition of "unscoped."

### Changed (verification surface)

- **Verify output rewritten to stop overclaiming.** `packages/cli/src/commands/verify.rs`. The single line `✓ nonce binding   approval nonce matched, single-use enforced` is replaced with three precisely-scoped lines:
  - `✓ approval binding   nonce matched a signed approval` (cryptographic only)
  - `✓ approval scope     actor / action / subject matched approval scope` (when scope present and matched), OR
  - `⚠ approval scope     approval is unscoped -- proves binding only, not actor/action/subject authorization` (when no scope was signed in)
  - `⚠ replay check       package-local only -- no global ledger consulted` (always; honest about what stateless verify can and can't do)
- **`verify_nonce_bindings` enforces `allowed_actors` and `allowed_subjects`.** Was already enforcing `allowed_actions`; now covers all three axes plus a separate `valid_until` on the scope itself. First-violation-wins ordering: actor → action → subject → scope expiry, so a wrong-actor failure isn't masked by a wrong-action one.
- **Package-local replay observation.** When two actions in the same verified bundle claim the same approval nonce, the second is rejected with `nonce already consumed by <id> in this package (package-local replay)`. Not a global ledger -- the CHANGELOG and verify text are explicit about this scope -- but catches the obvious in-package replay pattern.
- **`treeship attest approval` defaults to scoped.** Without any `--allowed-*` / `--max-uses` and without `--unscoped`, the command refuses with a message pointing at the right flags. Bearer approvals are now opt-in, not the default.

### Added (capture layer)

- **MCP-routed tool calls promote into typed file/process events.** `packages/core/src/session/`. Generic `agent.called_tool` events emitted by the MCP bridge previously stayed generic -- they appeared in the timeline but never landed in `files_read`, `files_written`, or `processes` on the receipt's side-effects block. New promotion pass at receipt composition inspects each `agent.called_tool` event's `meta.tool_input` and synthesizes the matching specialized event (`AgentReadFile`, `AgentWroteFile`, `AgentExecutedCommand`) when a known tool name + path are present. The synthetic event carries `meta.source = "mcp"` for provenance. Treeship can now serve as a generic MCP-routing fabric and the receipt still answers "what files did this agent touch" correctly. (#11)

- **Git reconciliation as the file-capture backstop.** `packages/core/src/session/git.rs`. Runs at session close: shells out to `git diff HEAD --name-status`, `git diff <since>..HEAD --name-status`, and `git ls-files --others --exclude-standard`, deduplicates against files already captured by hook or MCP, and synthesizes `AgentWroteFile` events for everything else. The synthetic events are appended to `events.jsonl` BEFORE the merkle root is sealed, so backstop-discovered changes are cryptographically committed alongside the rest of the session evidence -- not patched into the receipt as out-of-band claims. Closes the long-standing trust gap: an agent that ran `sed -i` inside a Bash command, a build tool that modified files, or any other untracked side effect would otherwise have vanished from the receipt. Fail-open by design: if the working dir isn't a git repo, the git binary is missing, or any git command errors, returns an empty Vec and the receipt is still produced -- reconciliation is best-effort enhancement, never a gate. (#29, #30, #20, #24, #25)

- **`session-event-cli` source-of-truth attribution for hook events.** Every `treeship session event` invocation now stamps `meta.source = "session-event-cli"` on the event it emits. The Claude Code plugin's `post-tool-use.sh` hook calls this for every tool use Claude makes, so the source label flows from "agent emitted a tool event" all the way through to receipt composition and cross-verification. Without this provenance label, every Claude tool call was indistinguishable from a generic event in the receipt and thus invisible to cross-verification.

### Added (cross-verification layer)

- **Cross-verification: receipt vs certificate, with canonical tool aliases.** `packages/core/src/session/receipt.rs`. The receipt's `tool_usage` block now carries both `declared` (what the agent's certificate authorized) and `actual` (what the agent actually called), and the verifier diffs them with `TOOL_ALIASES` mapping snake_case CLI names (`read_file`, `write_file`, `bash`, `web_fetch`) to TitleCase Claude tool names (`Read`, `Write`, `Bash`, `WebFetch`). Without alias normalization, a Claude session would always have `actual: ["Read","Write","Bash"]` while the certificate declared `["read_file","write_file","bash"]`, and cross-verification would falsely flag every authorized call as unauthorized. (#31, #32)

- **`source_attributes_a_tool()` filter so backstop sources don't get counted as direct tool calls.** Cross-verification's `actual` list aggregates `AgentReadFile`, `AgentWroteFile`, and `AgentExecutedCommand` events -- but only when their `meta.source` is `hook`, `mcp`, `shell-wrap`, `session-event-cli`, or absent. Events synthesized by `git-reconcile` or the `daemon-atime` channel are excluded; they're Treeship's own backstop layers, not the agent calling tools, and counting them as direct tool use would inflate `actual` against the agent's certificate. (#32)

- **In-band incompleteness signal: `proofs.event_log_skipped`.** `packages/core/src/session/receipt.rs`. When the event log reader skips a malformed JSON line, the count is now stamped on the sealed receipt as `proofs.event_log_skipped: N`. A downstream verifier can tell at a glance whether a receipt represents a clean session or one where some events were dropped during parsing. Defaults to `0` and is `skip_serializing_if`-omitted from canonical JSON, so receipts produced when the event log was clean stay byte-identical to v0.9.5 receipts. (#26)

### Added (model + provider attribution)

- **`agent.decision` event at session start records the model.** `integrations/claude-code-plugin/scripts/session-start.sh` now emits an `agent.decision` event carrying `meta.model` so the receipt records what model the agent ran on. Pairs with the CLI surface that plumbs model/provider/token-budget through the `treeship session event` command. Receipt readers can now answer "which model produced this work" without inferring from event timing. (#28, #6)

### Changed (trust gates)

- **Provenance source labels are no longer downgraded to `"hook"` when unknown.** `packages/core/src/session/receipt.rs`. Side-effect entries in the receipt now preserve the exact `meta.source` value they were stamped with, instead of falling back to `"hook"` for any unrecognized label. Caller-asserted provenance is now visible to the audit reader as written. (#20)

- **Git reconcile dedupes against writes only, never reads.** `packages/cli/src/commands/session.rs`. Previous logic suppressed reconciled writes whenever the same path had been read earlier in the session, producing a confidently incomplete audit trail (read + process recorded; the write that the process performed silently dropped). Reads do not change files; only writes belong in the dedup set. Trust-fabric Codex finding #2. (#30)

- **Git reconcile records destination path on rename/copy.** `packages/core/src/session/git.rs`. `parse_name_status_line` now returns the destination path for `R`/`C` codes instead of the source. `git mv old new` previously surfaced "old" (which no longer exists on disk) instead of "new" (which the agent created). Trust-fabric Codex round-2 finding. (#24)

- **Git reconcile filters Treeship's own runtime artifacts.** `packages/core/src/session/git.rs`. `.treeship/sessions/*`, `.treeship/artifacts/*`, `.treeship/tmp/*`, `.treeship/proof_queue/*`, `.treeship/session.closing`, and `.treeship/session.json` are now excluded from `files_written` because they're Treeship's own bookkeeping touched by the very session that's closing -- noisy and misleading in a receipt. User-authored files under `.treeship/` (`config.yaml`, `declaration.json`, `agents/*`, `policy.yaml`) are preserved -- those ARE the operator's own changes that an audit reader cares about. (#25)

### Changed (security)

- **MCP bridge sanitizer no longer leaks `command` / `cmd` into receipts.** `bridges/mcp/src/client.ts`. The `__sanitizeToolInput` whitelist is now strictly path-only (`file_path`, `path`, `notebook_path`, `target_file`). The earlier whitelist accepted `command` and `cmd`, which would have shipped raw shell-arg secrets (Bearer tokens passed inline to curl, AWS credentials passed inline to aws CLI) into `meta.tool_input` and ultimately the receipt. Caught by Codex round-2 trust-fabric review. (#19, #27)

### Fixed

- **`ctx::open` no longer overwrites a project-local `config.json` with a global-extends marker.** `packages/cli/src/ctx.rs`. `treeship init` previously wrote the marker even when the directory already had a populated `config.json` from a separately-managed setup, silently breaking that project's keystore reference. (#15)

- **`machine_seed` is co-located with the keystore for project-local isolation.** `packages/core/src/keys/`. Was previously written to a global path (`~/.treeship/machine_seed`), which meant two projects on the same host shared a derivation and a keystore-MAC failure in one project could surface as a decryption failure in the other. Now lives in the project's `.treeship/machine_seed`. (#16)

- **Event log: one malformed line no longer drops the whole receipt.** `packages/core/src/session/event_log.rs`. Previously a single bad JSON line in `events.jsonl` made `read_all()` short-circuit and return an empty Vec; the receipt then composed against zero events and looked like an empty session. Now skips the malformed line, increments a `skipped` counter, and continues. The skipped count surfaces in the sealed receipt via `proofs.event_log_skipped` (see Added). (#8)

- **Preview UI no longer crashes when `tool_usage.declared` or `tool_usage.actual` is absent.** `docs/components/receipt-preview.tsx`. Receipts produced by clients that pre-date the cross-verify block were rendering as a blank panel because the preview component dereferenced both arrays without a guard. (#9)

- **Docs install button no longer advertises the orphaned `cargo install treeship-cli`.** `docs/components/install-button.tsx`. The `crates.io` upload was yanked weeks ago in favor of the npm path; the docs hadn't caught up. (#5)

- **CI: cross-SDK matrix no longer wipes `/usr/bin` from PATH.** `.github/workflows/ci.yml`. Workflow expression `${{ env.PATH }}` resolves to empty string at workflow context, so `PATH: ./node_modules/.bin:${{ env.PATH }}` left PATH as just `./node_modules/.bin:`, and `/usr/bin/env: 'bash': No such file or directory` killed every cross-SDK matrix entry with exit 127. Replaced with the canonical `$GITHUB_PATH` mechanism. (#33)

- **CI: `tests/cross-sdk/` parses as ESM.** `tests/cross-sdk/package.json`. `verify-vectors.ts` uses `import.meta.url` and top-level await (added in v0.9.5 for cross-SDK roundtrip Phase B), both ESM-only. Without `"type": "module"` somewhere up the tree, tsx defaulted to CJS and esbuild rejected the file. Local package.json scopes the ESM treatment to this directory. (#33)

### Added (integrations)

- **Codex CLI integration.** `treeship add codex` now detects the Codex CLI and installs an MCP block in `~/.codex/config.toml` so Codex sessions flow through the same trust-fabric channels as Claude Code. (#10)

### Added (docs)

- **Trust-fabric concept overview.** `docs/content/docs/concepts/trust-fabric.mdx`. Explains the three-axis separation (agent surface / model+provider / tool channel) and the three-layer file capture stack as a single mental model. (#14)

- **Universal MCP attach guide.** `bridges/mcp/ATTACHING.md`. Step-by-step for wiring any MCP-speaking agent runtime (Codex, Cursor, Cline, Continue, custom) through the Treeship MCP bridge so the same trust-fabric behavior applies regardless of which agent surface is in use. (#13)

### Notes

- **All 234 unit tests + 10 bridge tests + 8 cross-SDK matrix entries pass on main.** Verified after the fix to `.github/workflows/ci.yml` landed.
- **No keystore format change.** v0.9.6 reads and writes the same encrypted entries as v0.9.5; no rotation or rekey required.
- **No SDK API breakage.** The cross-verification block is purely additive on the receipt side; existing SDK consumers continue to work without changes. The `tool_usage` block was already present in v0.9.5 receipts -- v0.9.6 just makes its `actual` list useful by populating it from the specialized event types and normalizing tool names through aliases.

## 0.9.5 (2026-04-25)

The performance and key-lifecycle release. Closes the two technical debts called out in the v0.9.4 "Known limitations" -- the O(N) event-log append, and the absence of any rotation primitive in a keystore where every key was meant to live forever. Also adds the first cross-SDK contract tests so TypeScript and Python can no longer drift apart silently, and unbreaks the docs site, which had been 404'ing in production since the 4906398 commit landed an invalid fumadocs `root` field.

### Added

- **`Store::rotate(predecessor, grace_period, set_default) -> RotationResult`.** The first lifecycle surface on the keystore. Mints a freshly generated Ed25519 successor, links the predecessor forward via a new `successor_key_id` field, and stamps it with `valid_until = now + grace_period`. Write order is successor-entry first, then stamped predecessor entry, then manifest -- so a partial-failure crash leaves either nothing observable (clean retry) or an orphan successor key file (harmless; not in manifest, retry generates a fresh one). The predecessor remains usable for signing during its grace window so an in-flight session that already started signing under the old key can finish; verifiers that honor `valid_until` can refuse the predecessor on lifecycle. Refuses to rotate an already-rotated key (caller must rotate the chain head). Backed by `Store::successor_chain(id) -> Vec<KeyId>` for forward walks and `Store::valid_keys_at(at_unix_secs) -> Vec<KeyInfo>` for building a verifier's accept-set as of a given time.

- **`treeship keys rotate` CLI surface.** `treeship keys rotate [--key id] [--grace-hours 24] [--no-default]`. Default 24h grace matches a typical client-cache TTL for fetched public-key bundles. `treeship keys list` is enriched to show rotation status inline (`rotated -> key_xxx, valid until 2026-04-26T...`).

- **`KeyInfo.valid_until` and `KeyInfo.successor_key_id`.** Lifecycle metadata threaded through the public `KeyInfo` shape and the on-disk encrypted entry. Both `Option<String>` and `Option<KeyId>`. Pre-0.9.5 entry files lack these fields entirely; they're `#[serde(default)]` and `skip_serializing_if = "Option::is_none"`, so legacy files load with `None` and never-rotated entries don't grow new fields on disk -- a 0.9.5 keystore is on-disk byte-identical to a 0.9.4 keystore until you actually rotate something.

- **Cross-SDK contract suite at `tests/cross-sdk/`.** Generates a scratch corpus of signed artifacts (action, decision, approval, plus one DSSE-tampered variant with a flipped signature byte), invokes the **actual SDK public API** -- `ship().verify.verify(id)` and `Treeship().verify(id)` -- against the same corpus, diffs `{outcome, chain}` per vector. Any divergence fails CI. The runners point both SDKs at the corpus's scratch keystore via the new `TREESHIP_CONFIG` env var honored by the CLI binary, so neither SDK needed an API change to participate. The suite caught and forced the fix of two real Python SDK contract bugs on its first green run (see "Fixed: Python SDK"). Local run: `./tests/cross-sdk/run.sh`. CI matrix: `{ubuntu, macos} x {Node 20, 22} x {Python 3.11, 3.12}` -- eight cells so platform-specific divergences (different `fetch` implementations, different subprocess line endings) surface immediately.

- **`TREESHIP_CONFIG` env var honored by the CLI.** The binary's config-path resolution now consults `TREESHIP_CONFIG` before falling back to `~/.treeship/config.json`. `--config` still wins over the env var. Designed for SDK consumers and CI runners that need to target an isolated keystore without forcing every SDK to add a per-call config option -- setting one env var redirects every read and write into the scratch directory regardless of which language the caller is using. Empty string is treated as unset to avoid a `export TREESHIP_CONFIG=` footgun.

### Changed

- **Event log append is now O(1) in session length.** `packages/core/src/session/event_log.rs`. The previous implementation re-streamed the entire `events.jsonl` on every append to derive the next `sequence_no`. That made each PostToolUse hook O(N) in session length and dominated end-to-end latency on long sessions; a typical Claude Code session of 200-500 events meant each later append re-read 200+ lines under the lock. A new 16-byte `events.jsonl.count` sidecar (`[count: u64 LE, byte_size: u64 LE]`) replaces the rescan with two 16-byte file ops in the steady state. The byte_size field is the crash detector: if a writer wrote `events.jsonl` but crashed before fsyncing the counter (or vice versa), the actual file size and the recorded size disagree -- mismatch, recount once, rewrite. Self-heals on the next append/open without ever assigning a duplicate sequence_no. Counter writes go through write-temp-then-rename so a reader that catches us mid-update sees either the old 16 bytes or the new 16 bytes, never a torn write.

### Changed (BREAKING for SDK consumers)

- **TS SDK: `s.dock.*` → `s.hub.*`; class `DockModule` → `HubModule`.** Both surfaces previously shelled out to `treeship dock push|pull|status`, which the CLI removed during the dock→hub rename in the v0.7.x line. The SDK call therefore failed against any current binary -- this is a bug fix as much as a rename. Pure rename, no aliases (we're not yet live with external SDK consumers, so the rename ships clean rather than carrying compat shims forever). `s.hub.status()` now returns `{ connected, endpoint?, hubId? }` (was `{ docked, endpoint?, dockId? }`); the `dock_id` field on the wire is still read as a fallback for older Hub responses.

- **Python SDK: `Treeship.dock_push()` → `Treeship.hub_push()`.** Same rename, same underlying bug fix (the old method called the removed `treeship dock push` subcommand and silently failed). Pure rename, no alias.

### Added (testing)

- **Cross-SDK suite Phase B: roundtrip attest+verify.** Phase A (the existing vector-parity check) only catches drift in how each SDK interprets the CLI's verify output. Phase B catches the deeper drift: TS attests an artifact, Python verifies it; Python attests an artifact, TS verifies it. All four legs must pass. If TS ever produces an envelope whose digest scheme, payload type, or signature encoding diverges from what Python expects, the suite fails. Two tiny dispatchers (`_sdk-helper.mjs` and `_sdk_helper.py`) expose `attest-action` / `verify` over argv so the orchestrator can sequence the four legs cleanly.

### Fixed

- **Python SDK `Treeship.verify()` now returns structured failures instead of raising.** Previously `verify()` shelled out via the generic `_run` helper, which raised `TreeshipError` on any non-zero CLI exit. But `treeship verify` exits 1 on a *legitimate* verify failure -- "the signature didn't check out" is a structured outcome, not a fault. The TypeScript SDK has always handled this correctly: catch the exec error, parse stdout, return `outcome=fail`. Python now matches: the outcome is in the returned `VerifyResult`, and `TreeshipError` is reserved for cases where verification couldn't even be attempted (binary missing, malformed JSON, keystore inaccessible). Caught by the cross-SDK suite on its first green run.

- **Python SDK `chain` field semantics now match TypeScript.** TS's `chain` reports `parsed.passed` on `outcome=pass` and `parsed.failed` on `outcome=fail`; the previous Python implementation always reported `passed`, so a failed verification reported `chain=0` while TS reported the failure count. The two now agree on every vector. Caught by the cross-SDK suite -- exactly the kind of silent drift the suite exists to surface.

- **Docs site restored.** Commit 4906398 set `"root": "overview"` in `docs/content/docs/cli/meta.json` to (purportedly) fix `/cli` 404'ing. fumadocs-mdx schema actually rejects it (`expected boolean, received string`), which crashed mdx generation, which made every docs URL return 500. `treeship.dev/cli` and even `treeship.dev/cli/init` were 404 in production until this release. Replaces the broken approach with explicit Next.js redirects from `/cli`, `/sdk`, `/api`, `/commerce`, `/reference` to their respective first-page targets, plus a permanent `/cli/dock -> /cli/hub` redirect for the long-pending CLI rename.

- **`cli/dock` resolved to `cli/hub`.** The CLI command has been `treeship hub` since v0.7.x; the doc page lived at `/cli/dock` under the legacy URL with its title set to "hub". Renamed `dock.mdx -> hub.mdx`, updated the section meta, added the permanent redirect.

### Added (docs surface)

- **SEO surfaces.** `docs/app/robots.ts` (with sitemap pointer), `docs/app/sitemap.ts` (generated from `source.getPages()` and `blogSource.getPages()` so all 87 docs + 18 blog URLs appear), and metadata export in `docs/app/layout.tsx` with `metadataBase`, OG tags, and Twitter card defaults so social previews stop falling back to bare URLs.

- **`llms.txt` rewritten.** `docs/public/llms.txt` now uses canonical paths (no `/docs/` prefix that depended on the old redirect), correct host (`treeship.dev`, not the imagined `docs.treeship.dev`), and lists every current page including `/cli/hub`, `/cli/log`, `/cli/merkle`, `/cli/otel`, `/cli/ui`, `/cli/install-cmd`, `/cli/approve`, `/cli/bundle`, `/sdk/verify`, `/sdk/mcp`, the full `/api/*` and `/commerce/*` sections.

### Notes

- No on-the-wire schema changes. Receipts and certificates produced by 0.9.4 verify identically under 0.9.5; receipts produced by 0.9.5 verify identically under 0.9.4 (the new key-lifecycle fields are scoped to the keystore, not the signed envelope).
- Workspace crates bumped together per the lockstep convention. Full `treeship-core` lib suite: 177/177 passing (was 161 in 0.9.4; +5 counter-sidecar tests, +8 key-rotation tests, +3 unrelated). Cross-SDK contract suite: 4/4 vectors agree across both SDKs on this release after the two Python SDK fixes the suite forced. The release went through three review rounds (self-review, then two parallel Codex adversarial passes); each round produced a real fix that's now landed. The `Store::rotate` cache update was reordered to happen BEFORE the manifest write so a same-process retry sees consistent state on a manifest-write failure, and the cross-SDK runners now also assert `expected_chain` per vector (not just `expected_outcome`) so a same-direction regression in both SDKs can no longer silently pass.

### Known limitations

- **Verifier-side enforcement of `valid_until` is NOT in this release.** Adding the metadata is half the work; making the receipt-verify path refuse signatures whose key has expired is the other half, and it's a behavior change that would silently invalidate in-flight receipts if shipped in a patch. Slated for v0.10.0 behind an opt-in feature flag, with a migration window measured in releases not days.
- **Compromise-revocation primitive is not in this release.** `rotate` is a graceful primitive (predecessor remains usable through its grace window); it's the wrong primitive for "this key is compromised, distrust it immediately." That needs its own design (revocation list distribution, verifier-side lookup latency, threat model). Tracked separately.
- **`Store::rotate` and `Store::generate` are not safe under concurrent invocation.** Both write to `manifest.json` without a flock, so two processes calling `rotate` at the same instant can produce two successors, only one of which ends up in the manifest. This is the same race that already existed for `generate` since 0.9.0 -- not a regression introduced by `rotate`, but worth flagging now that more callers may invoke the keystore concurrently. Workaround for operators running rotation from multiple machines: serialize externally (single CI job, or a lease in your secrets store). Real fix is a flock on `manifest.json` parallel to the one already in `event_log.rs`; tracked for the next keystore touch.
- **`verifyReceipt(json)` parity in the cross-SDK suite is missing.** The TS SDK exposes it via WASM; Python doesn't have a JSON-receipt entry point yet. The current suite locks down `verify(artifact_id)` -- the LCD surface -- and is structured so adding `verifyReceipt` later is a one-line addition to `gen-vectors.sh` plus a method call swap in each runner.

## 0.9.4 (2026-04-21)

Closes the v0.9.3 launch gaps surfaced during live plugin testing: the plugin now has a real install path without waiting for Anthropic marketplace approval, keystore-migration failures produce actionable errors instead of cryptic ones, and the plugin's SessionStart hook no longer silently swallows errors.

### Added

- **Zerker Labs Claude Code plugin marketplace.** The treeship monorepo now ships `.claude-plugin/marketplace.json` at the repo root so any user can install the plugin tonight with:
  ```
  claude plugin marketplace add zerkerlabs/treeship
  claude plugin install treeship@treeship
  ```
  Installs to `~/.claude/plugins/cache/treeship/treeship/<version>/`. Every subsequent Claude Code session auto-loads the plugin — SessionStart / PostToolUse / SessionEnd hooks fire, sealed receipts land in `.treeship/sessions/<id>.treeship`, `treeship package verify` passes all integrity checks. Independently verified end-to-end on a fresh scratch project. Anthropic's official-marketplace submission remains a separate track.

- **Actionable keystore migration error.** When `Store::signer()` can't MAC-verify a key (typical cause: upgrading from a pre-0.9.x Treeship whose machine-key derivation has since changed), the error now includes a diagnosis and a copy-pasteable recovery path instead of just "MAC verification failed — key file may be corrupt or wrong machine". Detection is best-effort: presence of a legacy `.machineseed` or `machine_seed` file inside the keys dir upgrades the diagnosis from "could be many causes" to "this is specifically a version upgrade". The recovery path explicitly notes non-destructive move semantics and that prior sealed `.treeship` packages remain verifiable (their receipts embed the old public key, so signatures still check out offline).

- **Plugin SessionStart hook surfaces failures to Claude Code.** `integrations/claude-code-plugin/scripts/session-start.sh` previously redirected stderr to `/dev/null` and silently exited 0 on any session-start error. With a broken keystore, that meant a user got no signal that recording wasn't happening — the worst possible failure mode. The hook now captures stderr, and on failure emits an `additionalContext` JSON envelope with the full diagnostic (built via python3 so newlines and quotes escape correctly) so Claude sees the recovery commands inline.

### Fixed

- **`fchmod`-on-fd eliminates TOCTOU in lock-file perm re-tightening.** The sidecar-lock-file open path (`open_lock_file` in `packages/core/src/session/event_log.rs`) previously re-chmodded existing files via `set_permissions(path, ...)` after an `file.metadata()` check. That's a TOCTOU: between the metadata read and the path-based chmod, an attacker could swap the inode. Now we call `fchmod(fd)` on the already-open file descriptor, so the target is pinned to the inode we hold. FFI wrapped locally to avoid adding a full `libc` dep for one symbol.

- **NFS chmod warning.** If `fchmod` returns non-zero (NFS mount with restricted metadata, some filesystems without full POSIX perm support), we now emit a one-line stderr warning instead of silently ignoring the failure. The lock itself still functions; operators just gain visibility into perms that weren't tightened.

- **Crates verify-script hardening.** `wait-for-crates-version.sh` now queries the sparse index (`https://index.crates.io/...`) first, falls back to the api/v1 endpoint with a policy-compliant User-Agent, and treats 403 as transient throttle rather than a hard failure. Fixes the ~5 minute verify-timeout false alarm we saw during the v0.9.3 release (the crate itself published successfully; only the verify gate was broken). Also avoids a SIGPIPE interaction where `grep -q` exiting early under `set -o pipefail` made successful matches look like network failures.

- **`status_check` dead `_config` arg removed.** Cosmetic cleanup from the v0.9.3 Codex review punch list. `treeship session status --check` no longer takes a dead config argument because `load_session()` reads the project-local session marker from cwd directly.

### Notes

- No schema or API-surface changes. Workspace crates bumped together per the lockstep convention established in v0.9.2.
- All 161 `treeship-core` lib tests pass, including the race-safety regression (`concurrent_appends_have_unique_sequence_numbers`), the lock-perm regression (`lock_file_has_owner_only_permissions`), and the upgrade-path regression (`existing_lock_file_is_re_tightened`).

### Known limitations

- **Append is still O(N)** in the on-disk event count. The counter-sidecar optimization noted as a v0.9.4 target in the v0.9.3 CHANGELOG is deferred again; for typical session lengths (50-500 events) this is negligible, and the current implementation is correct. Scheduled for v0.9.5 alongside the `treeship wrap`-vs-plugin-hooks architectural discussion.

## 0.9.3 (2026-04-20)

Trust onboarding for AI agents. The motivating problem: developers attempting to install Treeship would land on `treeship.dev/setup` (404, missing rewrite) and, even after installing, Claude Code would refuse to attach the MCP server because it had no in-context explanation of what `@treeship/mcp` captures or where data goes. v0.9.3 fixes both halves.

### Added

- `treeship add` (any framework) now drops a single `./TREESHIP.md` into the project root if one isn't already there. The file is framework-agnostic and answers the trust question for Claude Code, Cursor, Cline, Hermes, OpenClaw, and any future MCP-aware agent in one place: what gets captured (tool name, **SHA-256 digest of arguments** — not raw args, **SHA-256 digest of output** — not raw content, exit code, duration, raw error message text on failure), what does NOT get captured (file contents, env values, secrets), when data leaves the machine (only on explicit `treeship session report` / `hub push` / `auto_push: true`), and how to use the wrap/session lifecycle.
- The TREESHIP.md template ships embedded in the CLI binary via `include_str!` so the drop works offline and never fetches over the network.
- **Official Claude Code plugin** at `integrations/claude-code-plugin/`. Marketplace-ready (`.claude-plugin/plugin.json`). Mounts `@treeship/mcp` via `npx -y`, wires SessionStart/SessionEnd/PostToolUse hooks for deterministic auto-recording (no model-prompted lifecycle), ships a live monitor for receipt/event counters, and ships three skills (`treeship-session`, `treeship-verify`, `treeship-report`) for the moments that need agent agency. PostToolUse exists because Claude Code's built-in tools (Read, Write, Edit, Bash, Grep, Glob) bypass MCP and would otherwise be missing from the receipt timeline. Hooks fail open: missing CLI or missing `.treeship/` makes the plugin a silent no-op. Submit at <https://claude.ai/settings/plugins/submit>.

### Changed

- `treeship add` no longer touches framework-specific files (CLAUDE.md, .cursorrules, skill files) for trust purposes. Those stay focused on framework-specific instructions; the trust block lives in TREESHIP.md instead. One file, one source of truth, any agent.
- `integrations/claude-code/CLAUDE.md` template gains the trust block (what's captured, what isn't, when data leaves) above the existing wrapping rules — so users who copy the template manually also get the trust context, not only those who go through `treeship add`.
- `bridges/mcp/README.md` reframed: the inspect-before-trust path now leads with `treeship package verify` (offline, WASM, no hub required), with a clear pointer to the bridge source. Removed the previous "Verify our own development" section pending the flagship release receipt.

### Fixed (post-Codex-review, two passes)

- **`treeship session event` is now race-safe across processes.** Each invocation acquires an exclusive advisory file lock (`fs2::FileExt::try_lock_exclusive` in a 500ms bounded retry loop, backed by `flock(2)` on Unix and `LockFileEx` on Windows) on a sidecar `.lock` file before re-deriving `sequence_no` from the on-disk JSONL line count. Previously, parallel writers (e.g. concurrent PostToolUse hook invocations from a Claude Code plugin) each had their own `AtomicU64` initialized from a stale snapshot of the file and would assign duplicate sequence numbers, silently breaking Merkle chain ordering. The retry path is bounded so a wedged or crashed writer cannot freeze hook-driven invocations forever — after 500ms of contention, the append falls through with a stderr warning rather than blocking the agent. New regression test `concurrent_appends_have_unique_sequence_numbers` spawns 16 racing writers and asserts uniqueness.
- **Sidecar lock file is created mode `0o600`** (owner-only) on Unix via `OpenOptionsExt::mode`. Atomic at file creation so the file can never exist on disk with a more permissive mode. Regression test `lock_file_has_owner_only_permissions` asserts this.
- **`treeship session status --check`** added: prints nothing, exits `0` if a session is active, exits `1` if not. Shell-script-friendly gate for hooks and monitors. The default `treeship session status` still always exits `0` (it's a human-facing report), so existing scripts that gated on it are unchanged — but the Claude Code plugin's hooks now use `--check` so they actually run when a session is active. Without this, the plugin's `SessionStart`, `SessionEnd`, and `PostToolUse` hooks would have no-op'd in every real-world session.
- **Trust documentation rewritten to match the bridge source.** The previous `TREESHIP.md` / `CLAUDE.md` trust block claimed `@treeship/mcp` captured "arguments passed to the tool". The bridge actually captures the **SHA-256 digest** of arguments and output, never raw values. The first-pass fix narrowed that wording but still omitted other emitted fields (`action`, `approval_nonce`, `server`, `agent_name`, `artifact_id`, `meta.source`, etc.). The trust block is now organized by attestation type (intent attestation / result receipt / session event) and enumerates every field the bridge writes, with each field cross-referenced against `bridges/mcp/src/client.ts` and `attest.ts`. Conditional fields (e.g. `artifact_id` is omitted if the receipt write failed; `payload.output_digest` uses `result.content ?? result` so the fallback is documented) are flagged as conditional. `payload.error_message` carries the raw `Error.message` string on thrown errors — flagged so users treat it like a logged stack trace if their tools can leak in error text.
- **Plugin `post-tool-use.sh` no longer regex-extracts `tool_name`** from the PostToolUse JSON payload (a greedy `sed` would pull the wrong value when `tool_input` itself contained a `"tool_name":"foo"` substring — confirmed reproducible). It now tries `jq`, then `python3`, then `node` for JSON parsing, falling back to `"unknown"` only if all three are absent.
- **`npm install -g treeship` now fails loudly on Windows** instead of silently installing a wrapper without a binary. Added `npm/treeship/scripts/check-platform.js` wired as a `preinstall` hook, plus an `os: ["darwin", "linux"]` field in `package.json` so npm itself rejects the install. Windows users get a clear "use WSL or wait for v0.10" message.
- **Setup script version gate uses strict semver when possible.** Primary path: a node-based parser that treats any prerelease of `0.9.3` as `< 0.9.3` per semver.org §11.4. Smoke-tested against `0.9.2`, `0.9.3-rc.1`, `0.9.3`, `0.9.3-alpha`, `0.9.4`, `0.10.0`, and `1.0.0`. Fallback path (when `node` isn't on PATH): `sort -V` with a softer warning that notes prerelease detection is not strict. If `treeship --version` returns a string we can't parse as semver at all, the gate emits a "could not verify CLI version" warning rather than silently skipping. Upgrade hint also softened: no more `rm $(command -v treeship)` — points at package-manager reinstall instead.
- **`setup.sh` adapts the trailing hint** based on whether `./TREESHIP.md` actually exists after `treeship add` runs. If the CLI is too old to drop the file, the hint now points at the GitHub raw `TREESHIP.md` URL instead of a nonexistent local file.

### Notes

- Same safety guards as the rest of `treeship add`: refuses to write outside a `.treeship/`-initialized project, refuses through symlinks, never overwrites an existing `./TREESHIP.md`.
- The website's `setup.sh` one-liner is unchanged in spirit — `treeship add --all` (which it already calls) now drops TREESHIP.md automatically once v0.9.3 is published. Step 4 from the previous diff (a runtime `curl` of CLAUDE.md from GitHub raw) is removed; the embedded `include_str!` template is the source of truth.
- Website-side fix for the original `treeship.dev/setup` 404 is in the `treeship-website` repo (added a Next.js rewrite for `/setup` → `/setup.sh` mirroring the existing `/install` rewrite). Independent of this CLI release; deploys with the website.
- **Platform support: macOS and Linux only at v0.9.3.** The CLI ships binaries for `darwin-arm64`, `darwin-x64`, and `linux-x64`. The website's setup script is POSIX shell, the plugin's hook scripts are POSIX shell, and `treeship add`'s file-drop semantics rely on POSIX `rename` overwrite behavior. A native Windows binary, Windows-aware filesystem path, and PowerShell setup script are planned for v0.10.0. Use WSL on Windows today.

### Known limitations

- **`session event` append is O(N) in the on-disk event count.** The cross-process safe re-derivation of `sequence_no` rescans the full `events.jsonl` file on every append. For a typical session of 50–500 events this is negligible (microseconds). For sessions with 10k+ events it begins to surface as user-visible latency under rapid PostToolUse bursts. Deferred to v0.9.4: replace the rescan with a tiny locked counter sidecar so append becomes O(1). Tracked separately; flagged here so anyone writing high-throughput agent integrations against v0.9.3 can plan around it.

## 0.9.2 (2026-04-20)

All packages realigned at 0.9.2 after a partial v0.9.1 npm publish. v0.9.1 landed successfully on crates.io, PyPI, and for the `treeship` wrapper + platform binaries on npm, but the new `@treeship/core-wasm` and `@treeship/verify` packages failed to bootstrap (scope permissions for new package names), which cascaded failure to `@treeship/sdk`, `@treeship/mcp`, and `@treeship/a2a`. The release workflow has been hardened to fail loud on publish failures, pre-flight every expected package on the `@treeship` scope, and verify each package post-publish.

**v0.9.2 is the first version where every package lands cleanly on every registry together. Install v0.9.2 everywhere; do not mix with 0.9.1.**

### Release workflow hardening

- Every `npm publish` / `cargo publish` / `twine upload` step has `continue-on-error` removed. A failure in any one now fails the workflow — no more silent partial releases.
- New pre-flight step on the `publish-npm` job enumerates every expected package on the `@treeship` scope and fails fast if any is missing. New scoped packages must be bootstrapped once with a web-auth `npm publish` from an account that owns the scope; thereafter the workflow's OIDC trusted publisher handles all future versions.
- New `.github/scripts/wait-for-{npm,crates,pypi}-version.sh` helpers poll each registry after publish and fail the workflow if the expected version does not appear within 30 seconds. Catches partial propagation, transient registry errors, and accidentally-skipped publish steps.

### Contents of this release

All v0.9.1 work below. Semantically identical; the only difference is the version string and that every package actually lands on its registry this time.

#### Added

- `@treeship/core-wasm` npm package. The Rust core compiled to WebAssembly with 10 exported functions (`verify_envelope`, `artifact_id`, `digest`, `decode_payload`, `verify_merkle_proof`, `verify_zk_proof`, `version`, plus the three new high-level ones below). Bundle size: **167 KB gzipped** (target was under 250 KB). First-class published npm package; pinned to exact versions across all dependents to prevent silent drift.
- `@treeship/verify` zero-dependency verification package at `packages/verify-js/`. Install alone, verify receipts and certificates in any runtime with WebAssembly + `fetch`. Only dependency is `@treeship/core-wasm`. This is what Witness, dashboards, and third-party consumers install.
- High-level WASM exports: `verify_receipt`, `verify_certificate`, `cross_verify`. Previously only low-level envelope and Merkle primitives were exposed. Each returns JSON in / JSON out with an error shape on malformed input rather than panicking.
- Reusable library primitive `treeship_core::verify::verify_receipt_json_checks` — lifted from the CLI's URL-fetch path so CLI and WASM share one implementation. Same checks (Merkle root recomputation, inclusion proofs, leaf count, timeline ordering, chain linkage) produce the same result across every runtime.
- `treeship_core::agent::verify_certificate` — Ed25519 signature check against the certificate's embedded public key. Exposed so the CLI, `@treeship/verify`, and future WASM consumers share one implementation.
- Runtime compatibility: **Node.js 18+, Deno, browser (bundler), Vercel Edge, Cloudflare Workers, AWS Lambda**. Edge runtime deploy harnesses at `tests/runtime-acceptance/{vercel-edge,cloudflare-worker,aws-lambda}/` — runnable projects with per-runtime READMEs.
- New docs: `sdk/verify.mdx`, `guides/edge-runtime.mdx`. Runtime compatibility matrices added to `@treeship/sdk`, `@treeship/a2a`, and `@treeship/mcp` READMEs. `reference/schema.mdx` gains a "Parity between CLI and WASM" section.
- Command-line build pipeline: `packages/core-wasm/build-npm.sh <version>` runs `wasm-pack build --target bundler`, optionally `wasm-opt -Oz`, then rewrites `pkg/package.json` with scoped name + license + repo + keywords. Release workflow installs wasm-pack + binaryen and runs this before the other npm publish steps so dependents resolve against the fresh core-wasm.

#### Changed

- `@treeship/sdk` verification path migrated from CLI subprocess to direct WASM calls. `ship.verify.verify(id)` (legacy artifact-ID form) still subprocesses; new `verifyReceipt` / `verifyCertificate` / `crossVerify` methods run in-process via WASM. Stateful operations (attest, session, dock, agent register) still use subprocess.
- `@treeship/a2a` `verifyReceipt` now performs real cryptographic verification (was previously network-only structural summary). `VerifiedReceipt.cryptographicallyVerified` surfaces the WASM result; `verifyChecks` carries the per-step breakdown. Graceful fallback: if `@treeship/core-wasm` can't load in the runtime, returns the pre-v0.9.1 summary with `cryptographicallyVerified: false`.
- `@treeship/mcp` gains WASM-backed verification helpers alongside its attestation surface. Attest paths remain subprocess-based.
- `scripts/release.sh` now pins `@treeship/core-wasm` to the exact release version across all dependent packages (sdk-ts, a2a, mcp, verify-js) at tag time. No caret ranges for this dependency — drift would break the schema-rules parity guarantee.
- Workspace `Cargo.toml` adds `[profile.release.package.treeship-core-wasm]` with `opt-level = "z"` and `codegen-units = 1`. CLI release tuning unchanged.
- `treeship_core` `hostname` dep moved to `target.'cfg(not(target_family = "wasm"))'`. WASM builds fall back to `"host_unknown"` in `default_host_id`; WASM contexts consume receipts rather than author them, so the fallback is benign.

#### Notes

- All packages that depend on `@treeship/core-wasm` pin to exact version `0.9.2` (no caret). `release.sh` enforces this at tag time.
- Subprocess fallback was not implemented for WASM. The SDK's `verifyReceipt` / `verifyCertificate` / `crossVerify` functions require a runtime that can load the bundled WebAssembly. Runtimes without WASM support can continue using the legacy `verify(id)` subprocess path.
- WASM imports are lazy: the SDK and bridge modules can load in environments where `@treeship/core-wasm` is not yet resolvable (early-bootstrap CI, non-verification code paths). The first verification call pays the load cost; subsequent calls reuse cached bindings.

#### Release-window follow-ups

- Edge runtime acceptance deploys to Vercel Edge, Cloudflare Workers, and AWS Lambda are **code-complete** in `tests/runtime-acceptance/` but the actual deploys + cold-start measurements run out-of-band. Acceptance criteria are documented in each subdirectory's README; rerun to reproduce.
- Comprehensive Codex adversarial review of the v0.9.x WASM migration surface is planned before v0.10.0 cuts. 174+ unit / integration tests pass workspace-wide, but a formal adversarial pass adds a second set of eyes.

#### Not in this release (coming in v0.10.0)

- Approval loop primitives (5 new Hub endpoints + `--require-approval` flag on `treeship wrap` + `treeship approver` CLI)
- `treeship.dev/verify` browser drag-and-drop page (unblocked now that v0.9.2 publishes `@treeship/core-wasm` and `@treeship/verify`)
- Command-artifact CLI surfaces to issue `KillCommand` / `TerminateSession` / etc. — the schemas exist as of v0.9.0

#### Rollback

Previous stable is v0.9.0 and remains published on every registry. **Do not roll back to v0.9.1** — the npm side of that tag is partial and will leave installs in an inconsistent state. Downgrade straight to v0.9.0:

```bash
npm install @treeship/sdk@0.9.0 @treeship/a2a@0.9.0 @treeship/mcp@0.9.0 treeship@0.9.0
cargo install treeship-core@0.9.0
pip install treeship-sdk==0.9.0
```

v0.9.0 verification uses the CLI subprocess — less portable, but still correct. `@treeship/core-wasm` and `@treeship/verify` are new in v0.9.2 and have no v0.9.0 counterpart to roll back to.

## 0.9.1 (2026-04-18)

> **Partial publish; superseded by 0.9.2. Do not install 0.9.1 npm packages.** This entry remains as a historical record. On npm, only `treeship`, `@treeship/cli-linux-x64`, `@treeship/cli-darwin-arm64`, and `@treeship/cli-darwin-x64` reached 0.9.1. `@treeship/core-wasm` and `@treeship/verify` never published, which cascaded install failures to `@treeship/sdk`, `@treeship/mcp`, and `@treeship/a2a`. `treeship-core` (crates.io) and `treeship-sdk` (PyPI) did reach 0.9.1 cleanly. v0.9.2 realigns everything.

Verification runs anywhere. WASM migration of the core verification surface, published as an npm package, and rewired through the SDK and bridge packages. Second of three planned releases in this window; see v0.9.0 for the schema foundation and v0.10.0 (upcoming) for the approval loop and drag-drop verifier.

### Added

- `@treeship/core-wasm` npm package. The Rust core compiled to WebAssembly with 10 exported functions (`verify_envelope`, `artifact_id`, `digest`, `decode_payload`, `verify_merkle_proof`, `verify_zk_proof`, `version`, plus the three new high-level ones below). Bundle size: **167 KB gzipped** (target was under 250 KB). First-class published npm package; pinned to exact versions across all dependents to prevent silent drift.
- `@treeship/verify` zero-dependency verification package at `packages/verify-js/`. Install alone, verify receipts and certificates in any runtime with WebAssembly + `fetch`. Only dependency is `@treeship/core-wasm`. This is what Witness, dashboards, and third-party consumers install.
- High-level WASM exports: `verify_receipt`, `verify_certificate`, `cross_verify` (item 1). Previously only low-level envelope and Merkle primitives were exposed. Each returns JSON in / JSON out with an error shape on malformed input rather than panicking.
- Reusable library primitive `treeship_core::verify::verify_receipt_json_checks` — lifted from the CLI's URL-fetch path so CLI and WASM share one implementation. Same checks (Merkle root recomputation, inclusion proofs, leaf count, timeline ordering, chain linkage) produce the same result across every runtime.
- `treeship_core::agent::verify_certificate` — Ed25519 signature check against the certificate's embedded public key. Exposed so the CLI, `@treeship/verify`, and future WASM consumers share one implementation.
- Runtime compatibility: **Node.js 18+, Deno, browser (bundler), Vercel Edge, Cloudflare Workers, AWS Lambda**. Edge runtime deploy harnesses at `tests/runtime-acceptance/{vercel-edge,cloudflare-worker,aws-lambda}/` — runnable projects with per-runtime READMEs.
- New docs: `sdk/verify.mdx`, `guides/edge-runtime.mdx`. Runtime compatibility matrices added to `@treeship/sdk`, `@treeship/a2a`, and `@treeship/mcp` READMEs. `reference/schema.mdx` gains a "Parity between CLI and WASM" section.
- Command-line build pipeline: `packages/core-wasm/build-npm.sh <version>` runs `wasm-pack build --target bundler`, optionally `wasm-opt -Oz`, then rewrites `pkg/package.json` with scoped name + license + repo + keywords. Release workflow installs wasm-pack + binaryen and runs this before the other npm publish steps so dependents resolve against the fresh core-wasm.

### Changed

- `@treeship/sdk` verification path migrated from CLI subprocess to direct WASM calls. `ship.verify.verify(id)` (legacy artifact-ID form) still subprocesses; new `verifyReceipt` / `verifyCertificate` / `crossVerify` methods run in-process via WASM. Stateful operations (attest, session, dock, agent register) still use subprocess.
- `@treeship/a2a` `verifyReceipt` now performs real cryptographic verification (was previously network-only structural summary). `VerifiedReceipt.cryptographicallyVerified` surfaces the WASM result; `verifyChecks` carries the per-step breakdown. Graceful fallback: if `@treeship/core-wasm` can't load in the runtime, returns the pre-v0.9.1 summary with `cryptographicallyVerified: false`.
- `@treeship/mcp` gains WASM-backed verification helpers alongside its attestation surface. Attest paths remain subprocess-based.
- `scripts/release.sh` now pins `@treeship/core-wasm` to the exact release version across all dependent packages (sdk-ts, a2a, mcp, verify-js) at tag time. No caret ranges for this dependency — drift would break the schema-rules parity guarantee.
- Workspace `Cargo.toml` adds `[profile.release.package.treeship-core-wasm]` with `opt-level = "z"` and `codegen-units = 1`. CLI release tuning unchanged.
- `treeship_core` `hostname` dep moved to `target.'cfg(not(target_family = "wasm"))'`. WASM builds fall back to `"host_unknown"` in `default_host_id`; WASM contexts consume receipts rather than author them, so the fallback is benign.

### Notes

- All packages that now depend on `@treeship/core-wasm` pin to exact version `0.9.1` (no caret). `release.sh` enforces this at tag time.
- Subprocess fallback was not implemented for WASM. The SDK's `verifyReceipt` / `verifyCertificate` / `crossVerify` functions require a runtime that can load the bundled WebAssembly. Runtimes without WASM support can continue using the legacy `verify(id)` subprocess path.
- WASM imports are lazy: the SDK and bridge modules can load in environments where `@treeship/core-wasm` is not yet resolvable (early-bootstrap CI, non-verification code paths). The first verification call pays the load cost; subsequent calls reuse cached bindings.

### Release-window follow-ups

- Edge runtime acceptance deploys to Vercel Edge, Cloudflare Workers, and AWS Lambda are **code-complete** in `tests/runtime-acceptance/` but the actual deploys + cold-start measurements run out-of-band (this session cannot authenticate to any of the three providers). Acceptance criteria are documented in each subdirectory's README; rerun to reproduce.
- Comprehensive Codex adversarial review of the v0.9.1 WASM migration surface is planned before v0.10.0 cuts. v0.9.0 carried the same note and the same plan holds here: 174+ unit / integration tests pass workspace-wide, but a formal adversarial pass adds a second set of eyes.

### Not in this release (coming in v0.10.0)

- Approval loop primitives (5 new Hub endpoints + `--require-approval` flag on `treeship wrap` + `treeship approver` CLI)
- `treeship.dev/verify` browser drag-and-drop page (unblocked now that v0.9.1 publishes `@treeship/core-wasm` and `@treeship/verify`)
- Command-artifact CLI surfaces to issue `KillCommand` / `TerminateSession` / etc. — the schemas exist as of v0.9.0

### Rollback

Previous stable is v0.9.0 and remains published on every registry. Downgrade:

```bash
npm install @treeship/sdk@0.9.0 @treeship/a2a@0.9.0 @treeship/mcp@0.9.0 treeship@0.9.0
cargo install treeship-core@0.9.0
pip install treeship-sdk==0.9.0
```

v0.9.0 verification uses the CLI subprocess — less portable, but still correct. `@treeship/core-wasm` and `@treeship/verify` are new in v0.9.1 and have no v0.9.0 counterpart to roll back to.

## 0.9.0 (2026-04-18)

Verification UX is now complete and future-proofed. v0.9.0 is the first of three planned releases in this window; see the roadmap at the bottom of this entry for the story.

### Added

- `treeship verify <url-or-path-or-artifact-id>` accepts three target shapes: HTTPS/HTTP URL fetched as receipt JSON, path to a local `.treeship` or `.agent` package directory, or a local artifact ID (the original v0.1 form). The URL and file paths produce the full checkmark-style output specified for the release. (item 1)
- `treeship verify --certificate <path-or-url>` cross-verifies a receipt against an Agent Certificate. Pass or fail is a roll-up of three checks: ship IDs match, certificate is valid at verify time, every tool the session called is authorized by the certificate. (item 1 + item 2)
- New exit codes on `verify`: `0` success, `1` verification failed, `2` cross-verification failed, `3` network or filesystem error. Documented in `docs/cli/verify.mdx`. (item 1)
- Reusable library primitive `treeship_core::verify::cross_verify_receipt_and_certificate(receipt, certificate, now_rfc3339)` returning `CrossVerifyResult` with authorized / unauthorized / never-called tool lists, ship-ID status, and certificate validity. Explicit `now` argument keeps the function deterministic for testing and for future edge-runtime callers. (item 2)
- `schema_version` field on Session Receipts and Agent Certificates. New documents emit `"1"`; documents without the field are treated as `"0"` (legacy) and verified under existing rules. Optional `Option<String>` with `#[serde(skip_serializing_if = "Option::is_none")]` so legacy documents round-trip byte-identical. Full semantics in `docs/reference/schema.mdx`. (item 3)
- `session.ship_id` field on Session Receipts, parsed from the manifest's `actor` URI when it starts with `ship://`. Absent on pre-v0.9.0 receipts and on non-ship actors (`human://alice`, bare `agent://`). Cross-verification uses it to check receipt and certificate reference the same ship. (item 2)
- `treeship_core::artifacts` module with five DSSE-signed command artifact schemas for supervisor → ship control-plane messaging: `KillCommand`, `ApprovalDecision`, `MandateUpdate`, `BudgetUpdate`, `TerminateSession`. Plus `verify_command(envelope, &authorized_keys)` helper. Ship as primitives in v0.9.0; CLI surfaces that issue and consume them ship in v0.10.0. (item 7)
- `treeship_core::agent::verify_certificate` validates the embedded Ed25519 signature on an `AgentCertificate` against its embedded public key. Exposed as a public library API so the CLI, `@treeship/verify` (v0.9.1), and third parties share one implementation. (item 1)
- `treeship_core::agent::effective_schema_version` helper resolves `Option<String>` to its effective string (`"0"` default). Use this over manual `Option` checks so the legacy default flows from one place.
- New docs: `cli/verify.mdx` rewrite, `concepts/cross-verification.mdx`, `concepts/command-artifacts.mdx`, `reference/schema.mdx`. `concepts/session-receipts.mdx` updated to mention the new fields. (item 11)
- Backwards-compatibility regression suite at `packages/core/tests/legacy_receipt_fixtures.rs` with synthesized + hand-curated v0.7.2 and v0.8.0 fixtures. Every future release must keep these fixtures verifying cleanly; if the schema changes in a way that breaks them, it must be documented here first. (item 9)

### Changed

- `treeship verify` dispatcher: URL-shaped and existing-path-shaped targets, or any invocation with `--certificate`, go through the new external path. Bare artifact IDs (including `"last"`) fall through to the original local-storage verify path unchanged.
- `ArtifactEntry` re-exported from `treeship_core::session` so downstream code can construct receipts without reaching into the package module.
- Legacy `Option<String>` defaults on `schema_version` and `session.ship_id` are deliberately informational in v0.9.0: `schema_version: "1"` and `"0"` both select the same ruleset. Future versions that diverge will bump to `"2"` and move the field inside the signed payload. See `reference/schema.mdx`.

### Explicitly deferred

Not hidden, not quiet. Each of these was in the original v0.9.0 draft; each got moved because shipping it with a cohesive announcement beats burying it in a release note. Three releases, three stories.

- **v0.9.1 — Runs everywhere.** WASM migration of `@treeship/sdk` and `@treeship/a2a` from CLI subprocess to direct `packages/core-wasm` calls, and the new `@treeship/verify` standalone npm package (zero `@treeship/sdk` dependency, pure WASM, for Vercel Edge / Cloudflare Workers / AWS Lambda / browser). The `@treeship/verify` package uses the same `cross_verify_receipt_and_certificate` implementation that ships in v0.9.0 — no semantic drift.
- **v0.10.0 — Live management primitives.** Approval-loop Hub endpoints (5 new routes), `--require-approval` flag on `treeship wrap`, `treeship approver add / list / remove` CLI. `treeship.dev/verify` browser-based drag-and-drop verifier (uses the WASM bundle from v0.9.1). The command artifact schemas are already in v0.9.0 (`ApprovalDecision`, etc.) so Witness can start consuming them before v0.10.0 lands.
- **v1.0.** API stability guarantee, `treeship upgrade` self-update, additional platform support and polish.

### Follow-ups in this release window

- Comprehensive Codex adversarial review: v0.9.0 included a scoped review item that was deferred on shipping constraints. The v0.9.0 surface is tested (165+ unit/integration tests across the workspace, including every legacy fixture), but a formal adversarial pass on the URL fetch / certificate cross-verify / command-artifact code paths will be run before v0.9.1 cuts.
- Page-by-page docs audit for feature status (AUTO / EXPLICIT / NOT YET CAPTURED) is partial. v0.9.0-specific pages are complete and the most-read concept page (`session-receipts.mdx`) is current; the remaining pages will be audited before v0.10.0.
- Clean-room VM acceptance tests on macOS arm64 / macOS x64 / Linux x64 run out-of-band.

### Rollback

Previous stable is v0.8.0 and remains published on every registry.

```bash
npm install -g treeship@0.8.0
npm install @treeship/sdk@0.8.0 @treeship/mcp@0.8.0 @treeship/a2a@0.8.0
cargo install treeship-cli@0.8.0 treeship-core@0.8.0
pip install treeship-sdk==0.8.0
```

No breaking wire-format changes between v0.8.0 and v0.9.0. A v0.9.0 verifier reads v0.8.0 receipts cleanly (regression suite enforces this). A v0.8.0 verifier reads v0.9.0 receipts cleanly as long as the new optional fields are ignored, which they are by default.

## 0.8.0 (2026-04-18)

### Added
- `treeship add` -- auto-detect and instrument installed agent frameworks (Claude Code, Cursor, Cline, Hermes, OpenClaw)
- `treeship quickstart` -- guided interactive setup from zero to receipt in under 90 seconds
- `treeship agent register` -- Agent Identity Certificate (.agent package with certificate.html)
- `treeship session event` -- append structured events to the active session's event log (used by MCP/A2A bridges)
- `treeship session status --watch` -- live terminal TUI showing agents, events, security, and verification progress
- `treeship declare` -- create .treeship/declaration.json with tool authorization scope
- `TREESHIP_PROVIDER` environment variable for provider attribution (anthropic, openrouter, bedrock)
- Setup one-liner at treeship.dev/setup (installs, initializes, instruments agents)
- Integration packages for Claude Code, Hermes, OpenClaw in integrations/ with skill files and MCP configs
- TREESHIP.md universal skill file for any agent that reads markdown instructions
- Production-quality preview.html: three-panel narrative, trust chain visual, agent cards, timeline grouping, retry detection, approval gates, honest empty states, sidebar IntersectionObserver, print stylesheet, copy buttons
- Tool authorization in receipts: declared vs actual tool usage, unauthorized calls flagged
- Self-contained Merkle verification in preview.html via Web Crypto API

### Changed
- `treeship init` output simplified to Ship ID + Key ID + next step hints
- `treeship wrap` without active session shows warning with fix instructions
- `treeship session close` auto-opens preview.html on macOS/Linux terminals
- All error messages now tell the user what command to run to fix the issue
- Root help text shows quick-start workflow first
- MCP bridge (@treeship/mcp) now emits session events so tool calls appear in receipt timeline
- Failed MCP tool calls are now audited (previously vanished from the audit trail)

### Removed
- `TREESHIP_COST_USD` environment variable and cost_usd field. Cost is a consumer concern (Witness dashboards, billing tools). Receipts store verifiable token usage only.
- RELEASE_NOTES_NEXT.md

### Fixed
- Device code auth: full 16-char code displayed, hub accepts 8-char prefix for backward compat
- Terminal escape injection in watch mode (sanitize all event fields)
- Path traversal in agent register (name sanitized to alphanumeric + dash + underscore)
- Case-insensitive script tag breakout in preview.html JSON escaping
- Raw mode guard ensures terminal restoration on all exit paths
- UTF-8 safe string truncation in TUI
- Hub: device_code redacted from access logs, format validated before DB lookup
- Hub: SQLite persistence reads DATABASE_PATH env var (Railway), consistent JSON error responses, session ID length cap, rate limiting

### Security
- 15+ findings from four rounds of Codex adversarial review, all addressed
- Atomic first-write ownership + write-once receipts on Hub
- 10 MB body-size limit on receipt upload
- Honest verification language ("Merkle structure verified", not "Verified")

## 0.7.2 (2026-04-15)

### Session Receipt: production-quality preview.html

- Self-contained verifier in preview.html: Merkle root recomputation, inclusion proof verification, and timeline ordering checks run client-side via Web Crypto API. Works air-gapped, zero network calls.
- Production design overhaul: three-panel narrative (planned/done/review), trust chain visual, agent cards with cost bars, command cards with retry detection, timeline grouped by agent, sidebar with IntersectionObserver, print stylesheet, copy buttons, mobile collapse.
- Honest empty states: grey "not captured" for unmeasured data, green confirmations only for things actually measured.
- Security hardening: XSS prevention via \u003c escaping, numeric coercion via num() helper, honest "Merkle structure verified" language (not "Verified").

### MCP bridge: session event wiring

- `treeship session event` CLI command: append structured events to the active session's event log. Used by MCP bridge, A2A bridge, and SDKs.
- `@treeship/mcp` now emits `agent.called_tool` session events after each tool call so MCP tool usage appears in the receipt timeline, agent graph, and side effects.
- Failed MCP tool calls are now audited (previously vanished from the audit trail).

### Agent instrumentation

- `TREESHIP_MODEL`, `TREESHIP_TOKENS_IN`, `TREESHIP_TOKENS_OUT`, `TREESHIP_COST_USD` environment variables: set these before `treeship wrap` to capture model, token counts, and cost in the receipt.
- `treeship declare` CLI command: create `.treeship/declaration.json` with `bounded_actions`, `forbidden`, `escalation_required`. Receipt compares declared vs actual tool usage and flags unauthorized calls.
- File operation type detection: wrap now distinguishes created, modified, and deleted files.
- ZK proof detection: `zk_proofs_present` is set automatically when proof files exist for the session.
- Approval gates shown in preview.html when approval artifacts are present.

### Hub hardening

- SQLite persistence: reads `DATABASE_PATH` env var (Railway), persistent default at `/var/lib/treeship/hub.db`.
- Consistent JSON error responses across all endpoints.
- Session ID length cap (128 chars).
- Rate limiting via chi Throttle middleware.
- Write-once receipts with RowsAffected check on conditional update.
- Crash-safe session close with `session.closing` recovery marker.
- Case-insensitive log redaction for session query parameters.

## 0.7.1 (2026-04-09)

### Security fixes (from Codex adversarial review)

- Store full 256-bit SHA-256 Merkle root in receipts instead of truncated 64-bit prefix. Prior receipts should be regenerated.
- Atomic first-write ownership on `PUT /v1/receipt/{session_id}`: dock_id is never overwritten on conflict, eliminating the race between two docks.
- Write-once receipt semantics: once a receipt is uploaded for a session_id, it cannot be replaced (byte-identical replays are accepted for retry safety). The `immutable` cache header is now honest.
- 10 MB body-size limit on receipt upload to prevent memory-DoS from authenticated docks.
- Daemon emits read events even when mtime also advances, preventing `touch` after a secret read from suppressing the `on: access` alert.
- Session close deletes `session.json` before composing the receipt to prevent late daemon events from landing in the log but not the receipt.
- `treeship session report` selects the most recently closed session by `session.ended_at` inside the receipt, not filesystem mtime.
- Log redaction matches the `session` query parameter case-insensitively.

## 0.7.0 (2026-04-09)

### Session Receipts

- New `treeship_core::session` module: event model, manifest, context propagation, agent graph, side effects, append-only event log, canonical receipt composer with Merkle root
- `.treeship` package format: deterministic `receipt.json` + `merkle.json` + `render.json` + per-artifact inclusion proofs + static `preview.html`
- `treeship session close` now composes a Session Receipt v1 and writes a `.treeship` package under `.treeship/sessions/`
- `treeship package inspect` and `treeship package verify` for offline inspection and local verification (no hub required)
- `treeship session report` uploads a closed session's receipt to the configured hub and prints the permanent public URL

### Hub: public receipt endpoints

- `PUT /v1/receipt/{session_id}` (DPoP-authenticated): idempotent upload, rejects cross-dock overwrites, refreshes per-ship agent registry from the receipt's agent graph
- `GET /v1/receipt/{session_id}` (public, no auth): returns 200 + raw receipt JSON, 403 "session still open" if the row exists without a receipt, 404 if not found. Permanent URL, immutable cache
- `GET /v1/ship/agents` and `GET /v1/ship/sessions`: per-ship registry endpoints for dashboards and A2A clients
- New `sessions` and `ship_agents` tables with composite keys scoped per dock

### Hub: workspace share tokens

- `POST /v1/session` (DPoP-authenticated): mints a short-lived opaque token bound to a dock_id at mint time
- New `auth.ResolveReader` helper: read endpoints accept either DPoP or `?session=TOKEN`, fails closed on expired tokens
- `treeship hub open` mints a share token and opens a browser URL that does not require a private key on the client
- Access logs now redact `session` query parameters to prevent tokens from landing in stdout

### Sensitive file read detection

- Daemon now tracks both mtime and atime per file; a `SnapshotDiff` separates writes from reads
- Sensitive-file pass walks dotfiles at the project root and one level into `.aws`, `.ssh`, `.gnupg`, `.docker`, `.kube`
- When a file matching an `on: access` rule has its atime advance, the daemon emits an `agent.read_file` event to the active session's event log with `capture_confidence: "inferred"` and writes an ALERT line if the rule has `alert: true`
- Closes the file-read capture gap that left `.env`, `*.pem`, and `.ssh/*` access invisible in prior releases

### A2A Integration

- New package: `@treeship/a2a`, framework-agnostic Treeship middleware for A2A (Agent2Agent) servers and clients
- `TreeshipA2AMiddleware` with `onTaskReceived` (awaited intent), `onTaskCompleted` (chained receipt), `onHandoff`, and `decorateArtifact`
- `buildAgentCard`, `hasTreeshipExtension`, `getTreeshipExtension`, `fetchAgentCard` for AgentCard discovery + extension publishing
- `verifyReceipt` and `verifyArtifact` for pre-delegation trust checks at line speed
- Canonical extension URI: `treeship.dev/extensions/attestation/v1`
- Zero runtime dependencies; never throws; CLI-missing path prints one actionable warning per process
- 15 vitest tests covering middleware, AgentCard helpers, CLI-missing handling, and `TREESHIP_DISABLE=1` short-circuit
- Docs: `docs/integrations/a2a.mdx` (Mintlify) and `treeship/docs/content/docs/integrations/a2a.mdx` (Fumadocs)
- Blog post: "A2A Makes Agents Interoperable. Treeship Makes That Interoperability Trustworthy."
- Release pipeline: `bridges/a2a` wired into `scripts/release.sh` and `.github/workflows/release.yml`

### Python SDK

- `Treeship.session_report(session_id=None)` returns a `SessionReportResult` with the permanent receipt URL, agent count, and event count
- Defaults to the most recently closed session when no `session_id` is given

## 0.5.0 (2026-04-04)

### Zero-Knowledge Proofs

- Circom Groth16 proofs: 3 circuits (policy-checker, input-output-binding, prompt-template)
- Trusted setup complete with Hermez powers-of-tau ceremony
- Real Groth16 WASM verification via ark-groth16 pairing math
- Verification keys embedded in WASM binary at compile time
- `treeship prove --circuit`, `treeship verify-proof`, `treeship zk-status` commands
- Auto-prove on declaration (when `bounded_actions` configured)
- Feature-flagged: `--features zk` (default build has zero ZK deps)

### RISC Zero Chain Proofs

- Guest program compiled for riscv32im target via rzup
- Real receipt-based proving and verification
- Background daemon proof queue with lock file safety
- Composite checkpoint: Merkle root + ChainProofSummary
- `treeship prove-chain` command
- Bonsai detection via `BONSAI_API_KEY` (local CPU default)

### Trust Model

- Documented Hermez ceremony trust assumption
- Bonsai marked as opt-in only (API key = consent)
- Offline verification documented for all proof types

### Release Pipeline

- npm: Pure OIDC via trusted publisher (no token)
- crates.io: ZK deps stripped for publish (full ZK via git install)
- All packages at 0.5.0 across npm, crates.io, PyPI

## 0.4.0

- Terminology: dock -> hub, login -> attach, logout -> detach, rm -> kill, workspace -> open
- Config: docks -> hub_connections, active_dock -> active_hub, dock_id -> hub_id
- New hub ID prefix: hub_ (backward compat with dck_)
- serde aliases for backward-compatible config deserialization
- All docs updated with new terminology
- New concept pages: ships, hub connections

## 0.3.1

- Fix: Remove print statement causing JSONDecodeError in synthetic_media_detector workflow
- Minor stability improvements

## 0.3.0

- Wrap command captures output digest, file changes, and git state
- Trust templates: 7 official templates (github-contributor, ci-cd, mcp-agent, claude-code, openclaw, hermes, research)
- Shell hooks for automatic attestation
- Background daemon for file watching
- Doctor diagnostic (9 checks)

## 0.2.1

- Hotfix for encrypted keystore path resolution on Linux
- Improved error messages for missing keys

## 0.1.0 (2026-03-31)

Initial release.

### Core
- DSSE envelope signing with Ed25519 (ed25519-dalek, NCC audited)
- 6 statement types: action, approval, handoff, endorsement, receipt, decision
- Encrypted keystore (AES-256-CTR + HMAC, machine-bound)
- Content-addressed artifact IDs from PAE bytes
- Rules engine with YAML config and command pattern matching
- Merkle tree with checkpoints, inclusion proofs, offline verification
- 120+ tests

### CLI
- 30+ commands: init, wrap, attest, verify, session, approve, hub, merkle, ui, otel
- Rich wrap receipts: output digest, file changes, git state, auto-chaining
- Shell hooks for automatic attestation
- Trust templates (7 official: github-contributor, ci-cd, mcp-agent, claude-code, openclaw, hermes, research)
- Interactive TUI dashboard (Ratatui)
- OpenTelemetry export (feature-flagged)
- Background daemon for file watching
- Doctor diagnostic (9 checks)

### Hub
- Go HTTP server with 12 API endpoints
- Device flow authentication with DPoP
- Artifact push/pull with Rekor anchoring
- Merkle checkpoint storage and proof serving
- CORS for treeship.dev

### SDKs
- @treeship/sdk (TypeScript, npm)
- @treeship/mcp (MCP bridge, npm)
- treeship-sdk (Python, PyPI)
- treeship-core, treeship-cli (Rust, crates.io)
- npm binary wrapper (treeship, platform packages)

### Website
- treeship.dev: landing page, /verify, /merkle, /connect, /hub/activate, /open
- docs.treeship.dev: 67 pages (Fumadocs), search, VS Code theme

### Security
- PID file locking, file permissions (0600/0700)
- Command sanitization (redact secrets)
- Untrusted config detection
- Shell hook absolute path (prevent PATH hijacking)
- DPoP (no stored session tokens)
