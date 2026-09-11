#!/usr/bin/env bash
# Poll npm's registry for $PKG@$VERSION to exist, up to 15 minutes. Used
# after `npm publish` in the release workflow so a silent
# publish-but-not-propagated state is caught in CI instead of in user
# installs.
#
# Two things learned on v0.31.4 (2026-09-11), when this script split a
# release across npm by giving up on @treeship/sdk and then @treeship/mcp:
#
#   1. `npm view <pkg> version` reports the `latest` dist-tag, which npm's
#      CDN updates minutes after the version document itself. Asking for the
#      exact version (`npm view <pkg>@<version> version`) sees the publish
#      first, and is the question we actually want answered: is this
#      version installable.
#   2. Five minutes is not a wide window on a busy day. Fifteen is; a
#      publish that is still invisible after that is worth a human.
#
# Usage: wait-for-npm-version.sh <pkg> <version>

set -euo pipefail

PKG="${1:?usage: $0 <pkg> <version>}"
VERSION="${2:?usage: $0 <pkg> <version>}"

for i in $(seq 1 90); do
  EXACT="$(npm view "${PKG}@${VERSION}" version 2>/dev/null || true)"
  if [ "$EXACT" = "$VERSION" ]; then
    echo "  ✓ $PKG@$VERSION live on npm (attempt $i)"
    exit 0
  fi
  LATEST="$(npm view "$PKG" version 2>/dev/null || true)"
  echo "  ... $PKG@$VERSION not visible yet (latest tag: '${LATEST:-<none>}'), retrying in 10s (attempt $i/90)"
  sleep 10
done

echo "::error::$PKG@$VERSION did not become visible on npm after 900s (latest tag: ${LATEST:-<none>})"
exit 1
