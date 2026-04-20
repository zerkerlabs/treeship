#!/usr/bin/env bash
# Poll crates.io for $CRATE to report $VERSION as max_version, up to 30
# times on 10-second intervals (5 minutes total). Used after `cargo
# publish` in the release workflow. crates.io's search/max_version index
# typically lags origin by 2-5 minutes after a fresh publish, so we keep
# the window wide enough to ride that out without failing the workflow.
#
# Usage: wait-for-crates-version.sh <crate> <version>

set -euo pipefail

CRATE="${1:?usage: $0 <crate> <version>}"
VERSION="${2:?usage: $0 <crate> <version>}"

for i in $(seq 1 30); do
  ACTUAL="$(curl -sSf "https://crates.io/api/v1/crates/${CRATE}" 2>/dev/null \
    | jq -r '.crate.max_version' 2>/dev/null || true)"
  if [ "$ACTUAL" = "$VERSION" ]; then
    echo "  ✓ ${CRATE} ${VERSION} live on crates.io (attempt $i)"
    exit 0
  fi
  echo "  ... ${CRATE} reports '${ACTUAL:-<none>}' (want ${VERSION}), retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::${CRATE} did not reach ${VERSION} on crates.io after 300s (last seen: ${ACTUAL:-<none>})"
exit 1
