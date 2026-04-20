#!/usr/bin/env bash
# Poll crates.io for $CRATE to report $VERSION as max_version, up to 10
# times on 3-second intervals. Used after `cargo publish` in the release
# workflow.
#
# Usage: wait-for-crates-version.sh <crate> <version>

set -euo pipefail

CRATE="${1:?usage: $0 <crate> <version>}"
VERSION="${2:?usage: $0 <crate> <version>}"

for i in $(seq 1 10); do
  ACTUAL="$(curl -sSf "https://crates.io/api/v1/crates/${CRATE}" 2>/dev/null \
    | jq -r '.crate.max_version' 2>/dev/null || true)"
  if [ "$ACTUAL" = "$VERSION" ]; then
    echo "  ✓ ${CRATE} ${VERSION} live on crates.io (attempt $i)"
    exit 0
  fi
  echo "  ... ${CRATE} reports '${ACTUAL:-<none>}' (want ${VERSION}), retrying in 3s (attempt $i/10)"
  sleep 3
done

echo "::error::${CRATE} did not reach ${VERSION} on crates.io after 30s (last seen: ${ACTUAL:-<none>})"
exit 1
