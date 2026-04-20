#!/usr/bin/env bash
# Publish the npm package in the current directory at $VERSION, unless
# $PKG_NAME@$VERSION is already present on the npm registry. Idempotent
# across workflow re-runs and manual bootstraps of new scoped packages.
#
# Usage: npm-publish-if-needed.sh <pkg_name> <version>
#
# Why: a scope-new package (e.g. @treeship/core-wasm in the 0.9.x window)
# must be bootstrapped once with `npm publish --access public --auth-type=web`
# before the OIDC trusted publisher in CI can take over. If the manual
# bootstrap lands at the same version the workflow is about to publish,
# the workflow's own `npm publish` would fail with "You cannot publish
# over the previously published versions" and unwind the release. This
# helper treats "exact version already live" as a pass.

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
