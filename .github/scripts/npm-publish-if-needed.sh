#!/usr/bin/env bash
# Publish the npm package in the current directory at $VERSION, unless
# $PKG_NAME@$VERSION is already present on the npm registry. Idempotent
# across workflow re-runs and manual bootstraps of new scoped packages.
#
# Usage: npm-publish-if-needed.sh <pkg_name> <version>
#
# Why: a scope-new package must be bootstrapped once with
# `npm publish --access public --auth-type=web` before the OIDC trusted
# publisher in CI can take over. If the manual bootstrap lands at the same
# version the workflow is about to publish, the workflow's own `npm publish`
# would fail with "You cannot publish over the previously published
# versions" and unwind the release. This helper treats "exact version
# already live" as a pass.
#
# Note what that skip does NOT prove. Bootstrapping is two steps -- publish
# once by hand, THEN configure the trusted publisher on npmjs.com -- and this
# helper cannot tell them apart. If only the first was done, the package is
# live, this helper skips it, and the release goes green having never
# exercised CI's permission to write it.
#
# That is the v0.25.0/v0.25.1 sequence exactly. @treeship/cli-linux-arm64 was
# new in 0.25.0; attempt 1 of the release 404'd on it; it was bootstrapped by
# hand; attempt 2 reached this helper, saw it live, skipped, and went green.
# The trusted publisher was never configured, and nothing said so until
# v0.25.1 tried to publish a version that was not already there -- six
# packages into the job, leaving a partial release across three registries.
#
# The preflight in release.yml now checks provenance for exactly this reason:
# a green release that skipped a package is not evidence the package is
# publishable.

set -euo pipefail

PKG_NAME="${1:?usage: $0 <pkg_name> <version>}"
VERSION="${2:?usage: $0 <pkg_name> <version>}"

EXISTING="$(npm view "${PKG_NAME}@${VERSION}" version 2>/dev/null || true)"
if [ "$EXISTING" = "$VERSION" ]; then
  echo "  ✓ ${PKG_NAME}@${VERSION} already live on npm; skipping publish"
  exit 0
fi

echo "  → Publishing ${PKG_NAME}@${VERSION}..."
npm publish --access public
