#!/usr/bin/env bash
# Fail when the published @treeship/core-wasm layout cannot be loaded by Node.
#
# v0.24.0 shipped only the wasm-pack `--target bundler` build. It emits
#   import * as wasm from "./treeship_core_wasm_bg.wasm";
# which needs a bundler to resolve, so importing the package in Node died with
#
#   WebAssembly.Table.grow(): failed to grow table by 4
#
# at __wbindgen_start(). That took down @treeship/verify -- the "no CLI
# required" verifier -- and every SDK method calling it.
#
# It went unnoticed because the only consumer anyone exercised was the website,
# which vendors the wasm and bundles it. Nothing ever installed the tarball and
# imported it the way a user does. This does exactly that.
set -euo pipefail

PKG_DIR="${1:-packages/core-wasm/pkg}"
[ -d "$PKG_DIR" ] || { echo "  err   $PKG_DIR not built; run build-npm.sh <version> first"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

TARBALL="$(cd "$PKG_DIR" && npm pack --silent | tail -1)"
cp "$PKG_DIR/$TARBALL" "$TMP/"
cd "$TMP"
npm init -y >/dev/null 2>&1
npm i "./$TARBALL" --silent >/dev/null 2>&1

cat > esm.mjs <<'EOF'
const m = await import('@treeship/core-wasm');
if (typeof m.verify_envelope !== 'function') { console.error('verify_envelope missing'); process.exit(1); }
// Loading is not enough: exercise it, or a stub would pass.
const bad = JSON.stringify({payload:"e30",payloadType:"application/vnd.treeship.action+json;v=2",signatures:[{sig:"AAAA",keyid:"k"}]});
const r = JSON.parse(m.verify_envelope(bad, "{}"));
if (r.valid !== false) { console.error('a tampered envelope verified; the module is not doing the work'); process.exit(1); }
console.log('    esm  ok — ' + m.version());
EOF

cat > cjs.cjs <<'EOF'
const m = require('@treeship/core-wasm');
if (typeof m.verify_envelope !== 'function') { console.error('verify_envelope missing'); process.exit(1); }
console.log('    cjs  ok — ' + m.version());
EOF

node esm.mjs
node cjs.cjs
echo "  ✓ @treeship/core-wasm installs and verifies under $(node --version)"
