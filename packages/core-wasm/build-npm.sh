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

# Two targets, not one.
#
# The bundler build emits `import * as wasm from "./..._bg.wasm"`, which needs
# a bundler to resolve. Published alone, it made `@treeship/core-wasm` fail to
# load in Node with
#
#     WebAssembly.Table.grow(): failed to grow table by 4
#
# at `__wbindgen_start()` -- reproduced on Node 22.20.0 and 22.23.1 from a
# clean install. That took down `@treeship/verify`, the "no CLI required"
# verifier, and every SDK method that calls it. The site was unaffected
# because it vendors the wasm and bundles it, which is exactly why this went
# unnoticed.
#
# The `exports` map below routes Node to the nodejs build and everything else
# to the bundler build, so both consumers get a package that works.
echo "Building @treeship/core-wasm v${VERSION} with wasm-pack (bundler + nodejs)..."
wasm-pack build --target bundler --out-dir pkg --release
wasm-pack build --target nodejs --out-dir pkg/node --release
# wasm-pack writes a full package.json into each out-dir; the nested one would
# shadow the real manifest. Replace it with a type marker rather than deleting
# it outright.
#
# The marker is load-bearing. The nodejs target emits CommonJS, the root
# manifest says "type": "module", and without this Node reads node/*.js as ESM
# and dies with `exports is not defined in ES module scope`. Deleting the
# nested manifest fixed the shadowing and introduced that, which the tarball
# test caught -- the exports map alone was not enough.
rm -f pkg/node/README.md pkg/node/.gitignore
printf '{\n  "type": "commonjs"\n}\n' > pkg/node/package.json

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

// Route Node to the nodejs build and everything else to the bundler build.
//
// `main` stays the bundler entry so older resolvers keep the behaviour they
// had; `exports.node` is what stops Node from loading a build that needs a
// bundler and failing at `WebAssembly.Table.grow()`.
//
// `import` and `require` are both mapped under node because the nodejs target
// emits CommonJS, and a bare `import` of this package in Node must not fall
// through to the bundler build.
pkg.exports = {
  '.': {
    node: {
      require: './node/treeship_core_wasm.js',
      import: './node/treeship_core_wasm.js',
      types: './node/treeship_core_wasm.d.ts',
    },
    default: {
      import: './treeship_core_wasm.js',
      types: './treeship_core_wasm.d.ts',
    },
  },
  './package.json': './package.json',
};

// Make sure the files array covers everything wasm-pack emits, including the
// nodejs build -- omitting `node/` would publish an exports map pointing at
// files that are not in the tarball, which fails at install rather than at
// import and is harder to diagnose.
pkg.files = [
  '*.wasm',
  '*.js',
  '*.d.ts',
  'node/',
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
