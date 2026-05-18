# Treeship — Claude Code instructions

This file is the entry point for Claude Code (and any other agent that consumes a top-of-repo `CLAUDE.md`) when working on the Treeship source repository.

## Code quality

You are expected to follow [the AI-assisted development policy](docs/quality/ai-assisted-development.md). It's not optional. It targets the failure modes that AI-generated code is specifically prone to in this codebase: silent `unwrap_or_default()` in signed-bytes paths, verifier loops that pass vacuously on empty input, wire-controllable dispatch fields not bound into the canonical, TOCTOU on permission-sensitive file reads, mixed RNG sources, fabricated test vectors, and scope drift in security-sensitive code.

The policy applies to: code you write, tests you add, docs you change, commits you make, PRs you open.

When in doubt, prefer the policy over speed.

## Read order

1. [`AGENTS.md`](AGENTS.md) — the design spec and cryptographic invariants. Read in full before changing any code under `packages/core`, `packages/cli`, or `packages/hub`.
2. [`ONBOARDING.md`](ONBOARDING.md) — repo map, CLI surface, dev setup.
3. [`CONTRIBUTING.md`](CONTRIBUTING.md) — test matrix, commit-message style, branch flow.
4. [`docs/quality/ai-assisted-development.md`](docs/quality/ai-assisted-development.md) — the code-quality policy referenced above.

## What this repo is

Treeship is a portable trust layer for AI agent workflows. Every action, approval, and handoff gets a cryptographically signed artifact that verifies offline, without trusting any infrastructure. The bar for changes to signing, verification, or canonical formats is higher than for normal software: a verifier that returns `Ok` for the wrong reason is worse than a verifier that crashes.
