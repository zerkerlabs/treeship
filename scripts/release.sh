#!/bin/bash
# Treeship release script — split into independent phases so accidental
# tagging is impossible.
#
#   scripts/release.sh prepare <version>
#       Bump every version site, run preflight, commit. Never tags. Safe to
#       run during a normal feature workflow.
#
#   scripts/release.sh tag <version> --sha <sha> [--yes]
#       Create the annotated tag. Requires an explicit subcommand, an
#       explicit target SHA (no implicit HEAD), a clean working tree, no
#       pre-existing local or remote tag, and either --yes or interactive
#       confirmation. Never pushes the tag automatically -- the user runs
#       `git push origin v<version>` after reviewing.
#
# Why split phases: v0.9.7's release-machinery PR caught a foot-gun where the
# unified script bumped+committed+tagged in one pass, producing a local tag
# even when the workflow only intended to land the bump as a PR. Tagging is
# the irreversible action that triggers the entire publish pipeline; it must
# require an explicit, audited gesture.

set -e

# ---------- prepare ---------------------------------------------------------

cmd_prepare() {
  local VERSION="$1"
  if [ -z "$VERSION" ]; then
    echo "usage: scripts/release.sh prepare <version>" >&2
    echo "example: scripts/release.sh prepare 0.9.7" >&2
    exit 2
  fi

  echo "Preparing v${VERSION} (bump + commit, no tag)"
  echo "================================"
  echo

  # Rust crates
  echo "Bumping Rust crates..."
  sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/core/Cargo.toml
  sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/cli/Cargo.toml
  sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/core-wasm/Cargo.toml
  sed -i '' "s/treeship-core = { version = \"[^\"]*\"/treeship-core = { version = \"${VERSION}\"/" packages/cli/Cargo.toml

  echo "Bumping @treeship/sdk..."
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix packages/sdk-ts

  echo "Bumping @treeship/mcp..."
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix bridges/mcp

  echo "Bumping @treeship/a2a..."
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix bridges/a2a

  if [ -f packages/verify-js/package.json ]; then
    echo "Bumping @treeship/verify..."
    npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix packages/verify-js
    node -e "
      const fs = require('fs');
      const p = JSON.parse(fs.readFileSync('packages/verify-js/package.json', 'utf8'));
      if (p.dependencies && p.dependencies['@treeship/core-wasm']) {
        p.dependencies['@treeship/core-wasm'] = '${VERSION}';
        fs.writeFileSync('packages/verify-js/package.json', JSON.stringify(p, null, 2) + '\n');
      }
    "
  fi

  for pkgjson in packages/sdk-ts/package.json bridges/a2a/package.json bridges/mcp/package.json; do
    if [ -f "$pkgjson" ]; then
      node -e "
        const fs = require('fs');
        const p = JSON.parse(fs.readFileSync('$pkgjson', 'utf8'));
        if (p.dependencies && p.dependencies['@treeship/core-wasm']) {
          p.dependencies['@treeship/core-wasm'] = '${VERSION}';
          fs.writeFileSync('$pkgjson', JSON.stringify(p, null, 2) + '\n');
        }
      "
    fi
  done

  echo "Bumping treeship-sdk (Python)..."
  sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/sdk-python/pyproject.toml
  sed -i '' "s/__version__ = \".*\"/__version__ = \"${VERSION}\"/" packages/sdk-python/treeship_sdk/__init__.py

  echo "Bumping npm wrapper..."
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix npm/treeship
  for pkg in cli-darwin-arm64 cli-darwin-x64 cli-linux-x64; do
    npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix "npm/@treeship/$pkg"
  done

  node -e "
    const fs = require('fs');
    const p = JSON.parse(fs.readFileSync('npm/treeship/package.json', 'utf8'));
    for (const dep of Object.keys(p.optionalDependencies || {})) {
      p.optionalDependencies[dep] = '${VERSION}';
    }
    fs.writeFileSync('npm/treeship/package.json', JSON.stringify(p, null, 2) + '\n');
  "

  echo "Updating Cargo.lock..."
  cargo check -p treeship-core 2>/dev/null || true

  echo
  echo "Running release version preflight..."
  if ! python3 "$(dirname "$0")/check-release-versions.py" "$VERSION"; then
    echo
    echo "Preflight failed. Fix the disagreeing sites above before committing." >&2
    exit 1
  fi

  echo
  echo "Committing..."
  git add -A
  git commit -m "Release v${VERSION}"

  echo
  echo "Prepare complete. Tag is intentionally NOT created."
  echo
  echo "Next steps:"
  echo "  1. Review the bump commit, optionally update CHANGELOG.md."
  echo "  2. Open a PR with this branch."
  echo "  3. After the PR merges and CI is green, ask for explicit tag approval."
  echo "  4. Tag with:"
  echo "       scripts/release.sh tag ${VERSION} --sha <merged-main-sha>"
}

# ---------- tag -------------------------------------------------------------

cmd_tag() {
  local VERSION=""
  local SHA=""
  local YES=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --sha) SHA="$2"; shift 2 ;;
      --yes) YES=1; shift ;;
      -*)    echo "tag: unknown flag $1" >&2; exit 2 ;;
      *)     if [ -z "$VERSION" ]; then VERSION="$1"; shift; else echo "tag: unexpected positional $1" >&2; exit 2; fi ;;
    esac
  done

  if [ -z "$VERSION" ] || [ -z "$SHA" ]; then
    cat >&2 <<EOF
usage: scripts/release.sh tag <version> --sha <sha> [--yes]
example: scripts/release.sh tag 0.9.7 --sha 76059e7 --yes

Why --sha is required: never tag implicit HEAD. The SHA you pass should
be the merge commit on origin/main for the release PR you intend to ship.
EOF
    exit 2
  fi

  # Guardrail: clean working tree. A tag on dirty state would not match what
  # CI checks out anyway, but we want loud failure rather than confusion.
  if [ -n "$(git status --porcelain)" ]; then
    echo "::error::working tree is dirty -- refusing to tag." >&2
    git status --short >&2
    exit 1
  fi

  # Guardrail: tag must not already exist locally.
  if git rev-parse --verify --quiet "v${VERSION}" >/dev/null; then
    echo "::error::local tag v${VERSION} already exists." >&2
    echo "         If this is a stale tag from a botched run, remove with: git tag -d v${VERSION}" >&2
    exit 1
  fi

  # Guardrail: tag must not exist on origin. Cheap protection against
  # accidentally retagging an already-published release.
  if git ls-remote --tags origin "v${VERSION}" 2>/dev/null | grep -Fq "refs/tags/v${VERSION}"; then
    echo "::error::remote tag v${VERSION} already exists on origin." >&2
    exit 1
  fi

  # Guardrail: target SHA must exist locally and be reachable.
  if ! git cat-file -e "${SHA}^{commit}" 2>/dev/null; then
    echo "::error::SHA ${SHA} not found locally. Did you forget to git fetch?" >&2
    exit 1
  fi

  local FULL_SHA TARGET_SUBJECT ORIGIN_MAIN
  FULL_SHA="$(git rev-parse "${SHA}")"
  TARGET_SUBJECT="$(git log -1 --format=%s "${FULL_SHA}")"
  ORIGIN_MAIN="$(git rev-parse origin/main 2>/dev/null || echo '<unknown>')"

  cat <<EOF

About to tag (annotated):
  tag name:        v${VERSION}
  target SHA:      ${FULL_SHA}
  target subject:  ${TARGET_SUBJECT}
  origin/main:     ${ORIGIN_MAIN}

This will:
  1. Create local annotated tag v${VERSION} pointing at ${FULL_SHA:0:12}.
  2. NOT push the tag. Push manually with:
       git push origin v${VERSION}
     The push triggers .github/workflows/release.yml which builds binaries
     and publishes to npm, crates.io, and PyPI.

EOF

  if [ "$YES" -ne 1 ]; then
    printf "Type 'tag %s' to confirm: " "${VERSION}"
    read -r CONFIRM
    if [ "${CONFIRM}" != "tag ${VERSION}" ]; then
      echo "Aborted." >&2
      exit 1
    fi
  fi

  git tag -a "v${VERSION}" "${FULL_SHA}" -m "Release v${VERSION}"
  echo
  echo "Tagged v${VERSION} -> ${FULL_SHA:0:12}."
  echo "Push when ready:"
  echo "  git push origin v${VERSION}"
}

# ---------- usage / dispatch -----------------------------------------------

usage() {
  cat <<EOF
Treeship release script.

  scripts/release.sh prepare <version>
      Bump every version site, run preflight, commit. Does not tag.

  scripts/release.sh tag <version> --sha <sha> [--yes]
      Create the annotated tag. Required after the prepare PR has merged
      and you have explicit approval to release.

The default invocation (no subcommand) intentionally errors out so a stray
\`scripts/release.sh 0.9.7\` cannot retain its old "do everything" semantics.

To inspect every version site without changing anything:
  python3 scripts/check-release-versions.py <version>
  python3 scripts/check-release-versions.py --consistency
EOF
}

case "${1:-}" in
  prepare) shift; cmd_prepare "$@" ;;
  tag)     shift; cmd_tag "$@" ;;
  ""|-h|--help|help) usage; exit 0 ;;
  *)
    cat >&2 <<EOF
::error::unknown subcommand: $1

The single-arg form 'scripts/release.sh <version>' was removed because
it tagged implicitly, which produced an accidental local tag during the
v0.9.7 cutover. Use 'prepare' for the bump and 'tag' for tagging.

EOF
    usage
    exit 2
    ;;
esac
