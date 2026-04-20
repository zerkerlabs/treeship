#!/usr/bin/env bash
# Poll the version-specific crates.io endpoint for $CRATE at $VERSION,
# up to 30 times on 10-second intervals (5 minutes total). Used after
# `cargo publish` in the release workflow.
#
# We deliberately avoid the crate-wide /api/v1/crates/<crate> endpoint
# and its .crate.max_version field, because that field lags fresh
# publishes by several minutes through the search index. The
# version-specific /api/v1/crates/<crate>/<version> endpoint returns
# 200 as soon as the version is actually available, or 404 if not.
#
# Usage: wait-for-crates-version.sh <crate> <version>

set -euo pipefail

CRATE="${1:?usage: $0 <crate> <version>}"
VERSION="${2:?usage: $0 <crate> <version>}"

for i in $(seq 1 30); do
  HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" \
    "https://crates.io/api/v1/crates/${CRATE}/${VERSION}" || echo "000")"
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ ${CRATE} ${VERSION} live on crates.io (attempt $i)"
    exit 0
  fi
  echo "  ... ${CRATE}/${VERSION} returned HTTP ${HTTP_CODE}, retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::${CRATE}/${VERSION} did not return 200 from crates.io after 300s (last HTTP: ${HTTP_CODE})"
exit 1
