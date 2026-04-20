#!/usr/bin/env bash
# Poll the version-specific PyPI endpoint for $PACKAGE at $VERSION, up
# to 30 times on 10-second intervals (5 minutes total). Used after
# `twine upload` in the release workflow.
#
# We deliberately avoid the project-wide /pypi/<package>/json endpoint
# and its .info.version field, because it reflects the package's
# latest version on the CDN and can lag fresh releases. The
# version-specific /pypi/<package>/<version>/json endpoint returns
# 200 as soon as the release is actually live, or 404 if not.
#
# Usage: wait-for-pypi-version.sh <package> <version>

set -euo pipefail

PACKAGE="${1:?usage: $0 <package> <version>}"
VERSION="${2:?usage: $0 <package> <version>}"

for i in $(seq 1 30); do
  HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" \
    "https://pypi.org/pypi/${PACKAGE}/${VERSION}/json" || echo "000")"
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ ${PACKAGE} ${VERSION} live on PyPI (attempt $i)"
    exit 0
  fi
  echo "  ... ${PACKAGE}/${VERSION} returned HTTP ${HTTP_CODE}, retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::${PACKAGE}/${VERSION} did not return 200 from PyPI after 300s (last HTTP: ${HTTP_CODE})"
exit 1
