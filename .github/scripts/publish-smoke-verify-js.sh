#!/usr/bin/env bash
# Fail when the PUBLISHED @treeship/verify cannot verify in Node.
#
# Every existing check tests a locally built artifact. scripts/
# check-verify-js-loads.sh runs build-npm.sh, `npm pack`s the result, and
# installs the tarball; publish-smoke.sh installs the published CLI, which is
# a Rust binary and cannot exercise the wasm at all. So nothing installs
# @treeship/verify from the registry and calls it.
#
# That gap is not theoretical. As of v0.25.1 the published core-wasm throws
#
#   RangeError: WebAssembly.Table.grow(): failed to grow table by 4
#
# on first use in Node, while a local build of the same commit loads and
# verifies fine. The JS loaders are byte-identical; only the .wasm differs.
# Every gate was green because every gate tested the binary that works.
#
# This is the third time the same shape has bitten: v0.24.0 shipped a
# bundler-only build because the only exercised consumer was the website;
# #320 fixed core-wasm and tested core-wasm rather than the package users
# install; and now the artifact under test is the one CI built rather than
# the one CI published. A check is only worth the distance between what it
# runs and what a user gets.
#
# Runs after publish, against the registry, on the same Node the smoke job
# uses. It calls a verify function, because the wasm loads lazily and an
# import proves nothing.
set -euo pipefail

VERSION="${1:?usage: publish-smoke-verify-js.sh <version>}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
npm init -y >/dev/null 2>&1

echo "--- npm install @treeship/verify@${VERSION} (from the registry)"
npm install "@treeship/verify@${VERSION}" --no-audit --no-fund >/dev/null

cat > t.mjs <<'JS'
const m = await import('@treeship/verify');
const fn = m.verifyReceipt ?? m.verify_receipt;
if (typeof fn !== 'function') {
  console.error('  err   published @treeship/verify exposes no verifyReceipt; exports:',
    Object.keys(m).join(', '));
  process.exit(1);
}
// The wasm loads lazily. Importing proves nothing -- call it.
let out;
try {
  out = await fn(JSON.stringify({
    payload: 'e30',
    payloadType: 'application/vnd.treeship.receipt+json;v=1',
    signatures: [{ sig: 'AAAA', keyid: 'k' }],
  }));
} catch (e) {
  console.error('  err   published @treeship/verify threw before producing a verdict:');
  console.error('        ' + String(e).slice(0, 200));
  console.error('        A local build of the same commit may work; this tests what users install.');
  process.exit(1);
}
const verdict = typeof out === 'string' ? JSON.parse(out) : out;
if (verdict && verdict.valid === true) {
  console.error('  err   a tampered receipt verified; the published module is not doing the work');
  process.exit(1);
}
console.log('    published @treeship/verify rejected a tampered receipt');
JS

node t.mjs
echo "  ✓ @treeship/verify@${VERSION} verifies from the registry under $(node --version)"
