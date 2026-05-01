#!/usr/bin/env bash
#
# Treeship release platform smoke. Confirms `npm install -g treeship@<version>`
# works on every Linux distro the v0.10.1 hardening release claims to
# support, plus the macOS targets indirectly via the build matrix.
#
# What this verifies (per distro):
#   1. npm install -g treeship@<version> exits 0
#   2. treeship --version prints the expected version
#   3. treeship init succeeds in a tmpdir
#   4. treeship attest action succeeds (signs, returns artifact id)
#
# What this does NOT verify:
#   - Hub auth flows (would need a Hub endpoint configured)
#   - SDK paths (separate smoke matrix)
#   - Windows (not supported)
#
# Usage:
#   scripts/smoke-platform-release.sh <version>          # all distros
#   scripts/smoke-platform-release.sh <version> alpine   # one distro
#
# Requires: docker. Run BEFORE publishing a 0.10.1+ release. The musl
# static binary is the load-bearing change; pre-0.10.1 GNU builds will
# fail on Debian 12 / Ubuntu 22.04 / Alpine.

set -euo pipefail

VERSION="${1:-}"
ONLY="${2:-}"

if [ -z "$VERSION" ]; then
  cat >&2 <<EOF
usage: $0 <version> [distro]

Verifies npm install -g treeship@<version> on each supported Linux distro.

distros: debian12 ubuntu22 ubuntu24 alpine

example:
  $0 0.10.1            # smoke all
  $0 0.10.1 alpine     # smoke one
EOF
  exit 2
fi

# Image -> nickname mapping. Each image must ship Node 20+ via its
# default package manager, OR we install it inline.
declare -a SUITES=(
  "debian12 debian:12              apt"
  "ubuntu22 ubuntu:22.04           apt"
  "ubuntu24 ubuntu:24.04           apt"
  "alpine   alpine:3.20            apk"
)

# A tiny in-container test harness. We bake it into a heredoc so the
# script is self-contained — no second file to keep in sync.
make_apt_runner() {
  cat <<'SH'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -qq -y curl ca-certificates >/dev/null
# Install Node 20 via NodeSource so we get a current npm.
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
apt-get install -qq -y nodejs >/dev/null
node --version
npm --version
SH
}

make_apk_runner() {
  cat <<'SH'
set -e
apk add --no-cache nodejs npm curl ca-certificates >/dev/null
node --version
npm --version
SH
}

run_treeship_smoke() {
  local version="$1"
  cat <<SH
set -e
echo "  installing treeship@${version} ..."
npm install -g treeship@${version}

echo "  running treeship --version ..."
got=\$(treeship --version)
echo "    -> \$got"

if ! echo "\$got" | grep -q "${version}"; then
  echo "::error::version mismatch: expected ${version}, got \$got" >&2
  exit 1
fi

echo "  running treeship init in tmpdir ..."
TMPHOME=\$(mktemp -d)
treeship --config "\$TMPHOME/config.json" init >/dev/null
ls "\$TMPHOME/keys/" 2>&1

echo "  signing a test attestation ..."
treeship --config "\$TMPHOME/config.json" attest action \\
  --actor agent://smoke --action smoke.test --format json | head -c 200

echo
echo "  verifying the receipt envelope ..."
ID=\$(treeship --config "\$TMPHOME/config.json" attest action \\
  --actor agent://smoke --action smoke.verify --format json | \\
  node -e 'let d=""; process.stdin.on("data",c=>d+=c); process.stdin.on("end",()=>{const j=JSON.parse(d); process.stdout.write(j.id||j.artifact_id||"")})')
treeship --config "\$TMPHOME/config.json" verify "\$ID" >/dev/null
echo "  ✓ verify passed"

rm -rf "\$TMPHOME"
SH
}

run_one() {
  local nick="$1" image="$2" pm="$3"
  printf '\n=== %s (%s) ===\n' "$nick" "$image"

  local prep
  case "$pm" in
    apt) prep=$(make_apt_runner) ;;
    apk) prep=$(make_apk_runner) ;;
    *)   echo "::error::unknown package manager: $pm" >&2; return 1 ;;
  esac

  local smoke
  smoke=$(run_treeship_smoke "$VERSION")

  if docker run --rm "$image" sh -c "$prep
$smoke"; then
    printf '  ✓ %s OK\n' "$nick"
  else
    printf '  ✗ %s FAILED\n' "$nick"
    return 1
  fi
}

main() {
  local failures=0
  for entry in "${SUITES[@]}"; do
    # shellcheck disable=SC2086
    set -- $entry
    nick="$1" image="$2" pm="$3"
    if [ -n "$ONLY" ] && [ "$ONLY" != "$nick" ]; then continue; fi
    if ! run_one "$nick" "$image" "$pm"; then
      failures=$((failures + 1))
    fi
  done

  echo
  if [ "$failures" -gt 0 ]; then
    echo "::error::$failures distro(s) failed."
    exit 1
  fi
  echo "  All distros green for treeship@${VERSION}."
}

main
