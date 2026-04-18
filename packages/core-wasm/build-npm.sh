#!/usr/bin/env bash
# Build @treeship/core-wasm for npm publish.
#
# Usage:
#   packages/core-wasm/build-npm.sh <version>
#
# Runs `wasm-pack build --target bundler --out-dir pkg --release`, then
# rewrites pkg/package.json with the correct npm metadata (scoped name,
# license, repository, keywords, sideEffects). Keeps the wasm-pack output
# otherwise untouched.
#
# The `pkg/` directory is gitignored; it is regenerated on every release.

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CRATE_DIR"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not installed. Install with: cargo install wasm-pack" >&2
  exit 3
fi

echo "Building @treeship/core-wasm v${VERSION} with wasm-pack..."
wasm-pack build --target bundler --out-dir pkg --release

# Optional: shrink with wasm-opt if it's on PATH (not required; wasm-pack
# already produces a minimal binary under our workspace release profile).
if command -v wasm-opt >/dev/null 2>&1; then
  echo "Running wasm-opt -Oz..."
  for wasm in pkg/*.wasm; do
    wasm-opt -Oz -o "${wasm}.opt" "$wasm"
    mv "${wasm}.opt" "$wasm"
  done
else
  echo "wasm-opt not found; skipping (binary will still be small enough)."
fi

# Rewrite package.json with npm-ready metadata.
node - "$VERSION" <<'EOF'
const fs = require('fs');
const version = process.argv[2];
const path = 'pkg/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));

Object.assign(pkg, {
  name: '@treeship/core-wasm',
  version,
  description: 'WebAssembly bindings for Treeship cryptographic verification. Runs anywhere WASM runs: Node, browser, Vercel Edge, Cloudflare Workers, AWS Lambda.',
  license: 'Apache-2.0',
  homepage: 'https://treeship.dev',
  repository: {
    type: 'git',
    url: 'https://github.com/zerkerlabs/treeship',
    directory: 'packages/core-wasm',
  },
  keywords: [
    'treeship',
    'attestation',
    'verification',
    'wasm',
    'webassembly',
    'ed25519',
    'merkle',
    'receipts',
  ],
  sideEffects: false,
});

// Make sure the files array covers everything wasm-pack emits.
pkg.files = [
  '*.wasm',
  '*.js',
  '*.d.ts',
  'README.md',
  'LICENSE',
];

fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
console.log(`Wrote ${path}`);
EOF

# Pull in README + LICENSE so the npm tarball has them.
if [ -f "${CRATE_DIR}/README.md" ]; then
  cp "${CRATE_DIR}/README.md" pkg/README.md
fi
if [ -f "${CRATE_DIR}/../../LICENSE" ]; then
  cp "${CRATE_DIR}/../../LICENSE" pkg/LICENSE
fi

# Ensure `.gitignore` inside pkg doesn't get published (npm ignores it anyway,
# but be explicit).
rm -f pkg/.gitignore

echo "Done. Ready to publish:"
echo "  cd packages/core-wasm/pkg && npm publish --access public"
