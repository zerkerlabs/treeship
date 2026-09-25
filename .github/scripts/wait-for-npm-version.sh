#!/usr/bin/env bash
# Poll npm's registry for $PKG@$VERSION to be installable, up to 30 minutes. Used
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
# And on v0.31.7 and v0.31.9 (2026-09): the version document is not the
# tarball. `npm view` saw the version while the .tgz still 404ed for up to
# half an hour, so the check below also fetches the tarball.
#
# Usage: wait-for-npm-version.sh <pkg> <version>

set -euo pipefail

PKG="${1:?usage: $0 <pkg> <version>}"
VERSION="${2:?usage: $0 <pkg> <version>}"

# "Live" means installable, not merely listed. npm publishes the version
# metadata and the tarball through different paths, and the tarball has
# lagged the metadata by up to half an hour (0.31.7 and 0.31.9, 2026-09):
# the wrapper's version was visible, `npm install -g` got a 404 on the
# .tgz, and publish-smoke failed until a human reran it. So a package
# counts as landed only when its tarball URL answers 200.
CODE=""
for i in $(seq 1 120); do
  EXACT="$(npm view "${PKG}@${VERSION}" version 2>/dev/null || true)"
  if [ "$EXACT" = "$VERSION" ]; then
    TARBALL="$(npm view "${PKG}@${VERSION}" dist.tarball 2>/dev/null || true)"
    CODE="$(curl -sS -o /dev/null -w '%{http_code}' -m 30 -L "$TARBALL" 2>/dev/null || echo 000)"
    if [ "$CODE" = "200" ]; then
      echo "  ✓ $PKG@$VERSION live on npm, tarball served (attempt $i)"
      exit 0
    fi
    echo "  ... $PKG@$VERSION is listed but its tarball answers HTTP $CODE, retrying in 15s (attempt $i/120)"
    sleep 15
    continue
  fi
  LATEST="$(npm view "$PKG" version 2>/dev/null || true)"
  echo "  ... $PKG@$VERSION not visible yet (latest tag: '${LATEST:-<none>}'), retrying in 15s (attempt $i/120)"
  sleep 15
done

echo "::error::$PKG@$VERSION did not become installable on npm after 1800s (latest tag: ${LATEST:-<none>}, tarball HTTP ${CODE:-unknown})"
exit 1
