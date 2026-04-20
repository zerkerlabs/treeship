#!/usr/bin/env bash
# Poll PyPI for $PACKAGE to report $VERSION as the current info.version,
# up to 10 times on 3-second intervals. Used after `twine upload` in the
# release workflow.
#
# Usage: wait-for-pypi-version.sh <package> <version>

set -euo pipefail

PACKAGE="${1:?usage: $0 <package> <version>}"
VERSION="${2:?usage: $0 <package> <version>}"

for i in $(seq 1 10); do
  ACTUAL="$(curl -sSf "https://pypi.org/pypi/${PACKAGE}/json" 2>/dev/null \
    | jq -r '.info.version' 2>/dev/null || true)"
  if [ "$ACTUAL" = "$VERSION" ]; then
    echo "  ✓ ${PACKAGE} ${VERSION} live on PyPI (attempt $i)"
    exit 0
  fi
  echo "  ... ${PACKAGE} reports '${ACTUAL:-<none>}' (want ${VERSION}), retrying in 3s (attempt $i/10)"
  sleep 3
done

echo "::error::${PACKAGE} did not reach ${VERSION} on PyPI after 30s (last seen: ${ACTUAL:-<none>})"
exit 1
