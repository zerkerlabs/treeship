#!/usr/bin/env bash
# Poll for $CRATE at $VERSION on crates.io, up to 30 times on 10-second
# intervals (5 minutes total). Used after `cargo publish` in the release
# workflow.
#
# Strategy: query the sparse index FIRST (https://index.crates.io/...),
# fall back to /api/v1 only if the index doesn't show the version yet.
# Reasoning:
#
#   1. The sparse index is the canonical source of truth for cargo itself.
#      A version present there is, by definition, installable. The index
#      typically updates within seconds of publish.
#
#   2. The sparse index is served by different infrastructure than the
#      web API. The web API (/api/v1/crates/...) is fronted by anti-bot
#      filtering that blanket-403s GitHub Actions runner IPs and any
#      curl request without a meaningful User-Agent. We previously saw
#      300+ seconds of consecutive 403s on the api/v1 endpoint during
#      the v0.9.3 release while the version was already live.
#
#   3. We treat 403 as transient (not a hard verify-failure signal): a
#      403 means the registry is throttling US, not that the publish
#      failed. We keep retrying through 403s instead of treating the
#      first one as success or as failure.
#
# Per https://crates.io/policies#crawlers we set a User-Agent on every
# request to api/v1 -- identifies us, provides contact URL.
#
# Usage: wait-for-crates-version.sh <crate> <version>

set -euo pipefail

CRATE="${1:?usage: $0 <crate> <version>}"
VERSION="${2:?usage: $0 <crate> <version>}"

UA="treeship-release-workflow (+https://github.com/zerkerlabs/treeship)"

# Sparse-index URL pattern: https://index.crates.io/<a>/<b>/<crate>
# where <a><b> is the first 1-2 chars of the crate name (specifics
# documented at https://doc.rust-lang.org/cargo/reference/registry-index.html).
crate_to_index_path() {
  local name="$1"
  local len=${#name}
  case $len in
    1) echo "1/${name}" ;;
    2) echo "2/${name}" ;;
    3) echo "3/${name:0:1}/${name}" ;;
    *) echo "${name:0:2}/${name:2:2}/${name}" ;;
  esac
}

INDEX_PATH="$(crate_to_index_path "$CRATE")"
INDEX_URL="https://index.crates.io/${INDEX_PATH}"
API_URL="https://crates.io/api/v1/crates/${CRATE}/${VERSION}"

check_index() {
  # Returns 0 if VERSION is present in the index, 1 otherwise.
  # Each line of the index is a JSON record for one published version.
  #
  # Implementation note: we capture the body to a variable and use a
  # `case` glob match instead of `curl ... | grep -q`. The pipe form
  # under `set -o pipefail` produces false negatives when grep -q exits
  # early on first match: grep's exit closes the pipe, curl receives
  # SIGPIPE and exits 56, pipefail surfaces the 56 as the function's
  # return code -- so a successful match looks like a network failure.
  # Capturing first avoids the pipe entirely.
  local body
  body="$(curl -s -A "$UA" "$INDEX_URL" 2>/dev/null)" || return 1
  case "$body" in
    *"\"vers\":\"${VERSION}\""*) return 0 ;;
    *) return 1 ;;
  esac
}

check_api() {
  # Returns the HTTP code from the version-specific api/v1 endpoint.
  curl -s -A "$UA" -o /dev/null -w "%{http_code}" "$API_URL" || echo "000"
}

for i in $(seq 1 30); do
  if check_index; then
    echo "  ✓ ${CRATE} ${VERSION} present in sparse index (attempt $i)"
    exit 0
  fi

  HTTP_CODE="$(check_api)"
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ ${CRATE} ${VERSION} live via api/v1 (attempt $i)"
    exit 0
  fi

  # 403 = anti-bot throttle, not a real failure. 404 = not yet propagated.
  # Both are retryable; we just log and continue.
  echo "  ... ${CRATE}/${VERSION}: index miss, api/v1 HTTP ${HTTP_CODE}, retrying in 10s (attempt $i/30)"
  sleep 10
done

echo "::error::${CRATE}/${VERSION} did not return 200 from crates.io after 300s (last HTTP: ${HTTP_CODE})"
exit 1
