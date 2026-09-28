# Releasing Treeship

The release is scripted in `scripts/release.sh` and finished by
`.github/workflows/release.yml`. This page is the order of operations and the
two decisions behind it that are not obvious from the scripts.

## Order of operations

1. **Prepare.** `scripts/release.sh prepare <version>` bumps every version site
   (`scripts/check-release-versions.py --consistency` lists them), assembles
   the changelog from `changelog.d/`, runs preflight and commits
   "Release v<version>". Open that commit as a PR and merge it.
2. **Tag.** With the prepare PR merged and explicit approval to release,
   `scripts/release.sh tag <version> --sha <merge sha>` creates the annotated
   tag; `git push origin v<version>` starts the release workflow.
3. **Publish.** The workflow builds the binaries, runs the smoke matrix, cuts
   the GitHub Release, publishes npm, crates.io and PyPI, and installs the
   published packages the way users do (`publish-smoke`).
4. **Lockfiles.** The workflow's `refresh-lockfiles` job runs
   `scripts/release.sh refresh-lockfiles` against the just-published versions
   and opens `release/lockfiles-v<version>` as a PR. Merge it. See below.
5. **Hub.** Deploy the hub with `scripts/hub-deploy.sh` so `/v1/version`
   reports the commit. See below.
6. **Site.** The site repo's version bump merges to its main, which deploys.

## Lockfiles

The npm packages in this repo depend on each other by version
(`@treeship/verify` on `@treeship/core-wasm`, the SDK and bridges on both).
`npm ci` requires each `package-lock.json` to carry the resolved tarball URL
and integrity hash of every dependency. At prepare time the new version has
no tarball, so there is nothing honest to hash: `prepare` writes the declared
range only (`scripts/lockfile-pin.py`), and the lockfiles are incomplete on
purpose until the packages are published.

The decision (0.31.11 re-test, N-3): **the release workflow refreshes the
lockfiles after publish and opens the PR.** Before 0.31.12 this was a manual
step (`scripts/release.sh refresh-lockfiles`, then a commit), and v0.31.10 and
v0.31.11 both left main unbuildable for JS for hours because nobody ran it in
time. The alternative, teaching the tag pipeline's own `npm ci` steps to fall
back to `npm install`, would have kept CI green without fixing what a person
checking out the tag sees.

Two consequences to know:

- **`npm ci` at a tag commit does not work for the in-repo JS packages.** It
  cannot: the tag predates the tarballs. Build from the lockfile PR's merge
  commit, or run `npm install` in the package directory. The lockfile gate
  (`scripts/check-lockfile-sync.py`) tolerates exactly this window: an entry
  that names the in-flight version is a warning while npm does not have it
  yet, and a failure once it does.
- **The lockfile PR needs a nudge.** GitHub does not start workflows on a PR
  opened with the workflow's own token. Push an empty commit to its branch or
  close and reopen it, and the checks run. A re-run of the release workflow
  while that PR is open updates its branch instead of failing.

## Hub version on Railway

`/v1/version` reports `version`, `commit` and `built_at`. The Dockerfile takes
them as build args (`HUB_VERSION`, `HUB_COMMIT`, `HUB_BUILT_AT`) and falls
back to `RAILWAY_GIT_COMMIT_SHA` for the commit, which Railway sets for
deploys from a connected repository. A `railway up` upload has no `.git`
directory and no `RAILWAY_GIT_COMMIT_SHA`, so those deploys reported `unknown`
(0.31.11 re-test, N-34). Railway passes service variables into the Docker
build as ARGs when the Dockerfile declares them, so the fix is to set them on
the service before each upload. `scripts/hub-deploy.sh` does both:

```sh
RAILWAY_SERVICE=<service id> RAILWAY_ENVIRONMENT=production scripts/hub-deploy.sh
```

It sets `HUB_COMMIT` to the current short SHA, `HUB_BUILT_AT` to now, and
`HUB_VERSION` to the `Release` constant in `packages/hub/internal/version`,
then runs `railway up` from the repository root. Run it from a clean checkout
of the commit you mean to deploy. The variables stay on the service, so the
script sets them fresh on every run; a deploy from the connected repository
ignores them and takes its commit from `RAILWAY_GIT_COMMIT_SHA`.
