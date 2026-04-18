#!/bin/bash
# Treeship release script
# Usage: ./scripts/release.sh 0.1.1
#
# Bumps version across all packages, commits, tags, and pushes.
# The GitHub Actions release workflow handles the rest:
# - Builds binaries for all platforms
# - Creates GitHub Release
# - Publishes to npm (if NPM_TOKEN secret is set)
# - Publishes to crates.io (if CARGO_TOKEN secret is set)

set -e

VERSION="$1"

if [ -z "$VERSION" ]; then
  echo "Usage: ./scripts/release.sh <version>"
  echo "Example: ./scripts/release.sh 0.1.1"
  echo ""
  echo "Current versions:"
  echo "  core:        $(grep '^version' packages/core/Cargo.toml | head -1 | sed 's/.*= "//' | sed 's/"//')"
  echo "  cli:         $(grep '^version' packages/cli/Cargo.toml | head -1 | sed 's/.*= "//' | sed 's/"//')"
  echo "  sdk-ts:      $(node -p "require('./packages/sdk-ts/package.json').version")"
  echo "  mcp:         $(node -p "require('./bridges/mcp/package.json').version")"
  echo "  a2a:         $(node -p "require('./bridges/a2a/package.json').version")"
  echo "  verify:      $(node -p "require('./packages/verify-js/package.json').version" 2>/dev/null || echo 'not-built-yet')"
  echo "  core-wasm:   $(node -p "require('./packages/core-wasm/pkg/package.json').version" 2>/dev/null || echo 'not-built-yet')"
  echo "  sdk-python:  $(grep '^version' packages/sdk-python/pyproject.toml | head -1 | sed 's/.*= "//' | sed 's/"//')"
  echo "  npm wrapper: $(node -p "require('./npm/treeship/package.json').version")"
  exit 1
fi

echo "Releasing Treeship v${VERSION}"
echo "================================"
echo ""

# Rust crates
echo "Bumping Rust crates..."
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/core/Cargo.toml
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/cli/Cargo.toml
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/core-wasm/Cargo.toml
sed -i '' "s/treeship-core = { version = \"[^\"]*\"/treeship-core = { version = \"${VERSION}\"/" packages/cli/Cargo.toml

# TypeScript SDK
echo "Bumping @treeship/sdk..."
npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix packages/sdk-ts

# MCP bridge
echo "Bumping @treeship/mcp..."
npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix bridges/mcp

# A2A bridge
echo "Bumping @treeship/a2a..."
npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix bridges/a2a

# @treeship/verify standalone package (if it exists)
if [ -f packages/verify-js/package.json ]; then
  echo "Bumping @treeship/verify..."
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix packages/verify-js
  # Pin @treeship/core-wasm exact version in @treeship/verify
  node -e "
    const fs = require('fs');
    const p = JSON.parse(fs.readFileSync('packages/verify-js/package.json', 'utf8'));
    if (p.dependencies && p.dependencies['@treeship/core-wasm']) {
      p.dependencies['@treeship/core-wasm'] = '${VERSION}';
      fs.writeFileSync('packages/verify-js/package.json', JSON.stringify(p, null, 2) + '\n');
    }
  "
fi

# Pin @treeship/core-wasm exact version across any package that depends on it.
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

# Python SDK
echo "Bumping treeship-sdk (Python)..."
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" packages/sdk-python/pyproject.toml
sed -i '' "s/__version__ = \".*\"/__version__ = \"${VERSION}\"/" packages/sdk-python/treeship_sdk/__init__.py

# npm binary wrapper + platform packages
echo "Bumping npm wrapper..."
npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix npm/treeship
for pkg in cli-darwin-arm64 cli-darwin-x64 cli-linux-x64; do
  npm version "$VERSION" --no-git-tag-version --allow-same-version --prefix "npm/@treeship/$pkg"
done

# Update optionalDependencies in wrapper to match
node -e "
  const fs = require('fs');
  const p = JSON.parse(fs.readFileSync('npm/treeship/package.json', 'utf8'));
  for (const dep of Object.keys(p.optionalDependencies || {})) {
    p.optionalDependencies[dep] = '${VERSION}';
  }
  fs.writeFileSync('npm/treeship/package.json', JSON.stringify(p, null, 2) + '\n');
"

# Update Cargo.lock
echo "Updating Cargo.lock..."
cargo check -p treeship-core 2>/dev/null || true

echo ""
echo "Versions bumped to ${VERSION}:"
echo "  packages/core/Cargo.toml"
echo "  packages/cli/Cargo.toml"
echo "  packages/core-wasm/Cargo.toml"
echo "  packages/sdk-ts/package.json"
echo "  bridges/mcp/package.json"
echo "  bridges/a2a/package.json"
if [ -f packages/verify-js/package.json ]; then
  echo "  packages/verify-js/package.json"
fi
echo "  packages/sdk-python/pyproject.toml"
echo "  npm/treeship/package.json"
echo "  npm/@treeship/cli-*/package.json"
echo ""
echo "Note: @treeship/core-wasm is built and published by GitHub Actions"
echo "on tag push. The pkg/ directory is regenerated via"
echo "packages/core-wasm/build-npm.sh."
echo ""

# Commit and tag
echo "Committing..."
git add -A
git commit -m "Release v${VERSION}"

echo "Tagging v${VERSION}..."
git tag "v${VERSION}"

echo ""
echo "Ready to push. Run:"
echo ""
echo "  git push && git push --tags"
echo ""
echo "This will trigger GitHub Actions to:"
echo "  1. Build binaries (Linux, macOS arm64, macOS x64)"
echo "  2. Create GitHub Release with binaries"
echo "  3. Publish to npm (if NPM_TOKEN secret is set)"
echo "  4. Publish to crates.io (if CARGO_TOKEN secret is set)"
echo ""
echo "  5. Publish to PyPI (if PYPI_TOKEN secret is set)"
