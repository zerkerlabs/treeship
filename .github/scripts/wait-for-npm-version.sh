#!/usr/bin/env bash
# Poll npm's registry for $PKG to report $VERSION, up to 30 times on
# 10-second intervals (5 minutes total). Used after `npm publish` in the
# release workflow so a silent publish-but-not-propagated state is caught
# in CI instead of in user installs. Wide window because npm's registry
# CDN can lag behind the origin by several minutes during busy periods.
#
# Usage: wait-for-npm-version.sh <pkg> <version>

set -euo pipefail

PKG="${1:?usage: $0 <pkg> <version>}"
VERSION="${2:?usage: $0 <pkg> <version>}"

for i in $(seq 1 30); do
  ACTUAL="$(npm view "$PKG" version 2>/dev/null || true)"
  if [ "$ACTUAL" = "$VERSION" ]; then
    echo "  ✓ $PKG@$VERSION live on npm (attempt $i)"
    exit 0
  fi
  echo "  ... $PKG reports '$ACTUAL' (want $VERSION), retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::$PKG did not reach $VERSION on npm after 300s (last seen: ${ACTUAL:-<none>})"
exit 1
