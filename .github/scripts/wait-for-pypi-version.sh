#!/usr/bin/env bash
# Poll PyPI for $PACKAGE to report $VERSION as the current info.version,
# up to 30 times on 10-second intervals (5 minutes total). Used after
# `twine upload` in the release workflow. PyPI's JSON API usually
# reflects a new version within seconds, but the CDN in front of it can
# lag; keep the window wide to match the npm and crates.io scripts.
#
# Usage: wait-for-pypi-version.sh <package> <version>

set -euo pipefail

PACKAGE="${1:?usage: $0 <package> <version>}"
VERSION="${2:?usage: $0 <package> <version>}"

for i in $(seq 1 30); do
  ACTUAL="$(curl -sSf "https://pypi.org/pypi/${PACKAGE}/json" 2>/dev/null \
    | jq -r '.info.version' 2>/dev/null || true)"
  if [ "$ACTUAL" = "$VERSION" ]; then
    echo "  ✓ ${PACKAGE} ${VERSION} live on PyPI (attempt $i)"
    exit 0
  fi
  echo "  ... ${PACKAGE} reports '${ACTUAL:-<none>}' (want ${VERSION}), retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::${PACKAGE} did not reach ${VERSION} on PyPI after 300s (last seen: ${ACTUAL:-<none>})"
exit 1
