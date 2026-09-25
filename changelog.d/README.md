# Changelog fragments

Don't edit the `## Unreleased` section of `CHANGELOG.md` in a PR. Add one file here instead.

- **Name:** the task id or a short topic, e.g. `W1-4-record-json-required.md`. Use letters, digits, `.`, `_` or `-`.
- **Content:** one or more `- ` bullets, written the way `CHANGELOG.md` entries are written: a bold lead line, then what changed and why. No headings.
- **One PR, one file.** Two PRs never touch the same file, so they never conflict.

At release, `scripts/release.sh prepare <version>` runs `python3 scripts/changelog.py assemble <version>`. That moves every fragment, plus anything still under `## Unreleased`, into a new `## <version> (<date>)` section, then deletes the fragments.

The docs changelog page shows pending fragments as its Unreleased section (`docs/scripts/sync-changelog.mjs`). CI (`docs-drift`) runs `scripts/changelog.py check`. The check validates fragments and fails a PR that adds bullets to `## Unreleased` directly.

## Release checklist addition: "next release" doc callouts

Docs sometimes carry a `**Next release.**` `Callout` or a `(next release)`
marker next to a flag that's implemented on `main` but not in the latest tag
(see `docs/content/docs/cli/judge.mdx`, added for `--contract` /
`--state-out` / `--resolve` et al. in the W3-6 audit fix). When cutting the
release that ships one of these flags, grep for `next release` under
`docs/content/` and remove the now-stale callout/marker in the same release
PR -- otherwise a shipped flag keeps reading as unreleased.
