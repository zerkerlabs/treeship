#!/usr/bin/env bash
# Fail when @treeship/verify cannot verify a receipt in Node.
#
# This exists because check-wasm-loads.sh was not enough, and the way it was
# not enough is the same mistake the original bug was made of.
#
# v0.24.0 shipped a bundler-only core-wasm that threw
# `WebAssembly.Table.grow()` on import in Node. That went unnoticed because
# the only consumer anyone exercised was the website, which vendors and
# bundles the wasm. The fix added a tarball test -- against
# `packages/core-wasm/pkg`. The package users actually install is
# `@treeship/verify`, and it was still untested.
#
# It gets worse with the pin. @treeship/verify, @treeship/sdk, @treeship/mcp
# and @treeship/a2a all depend on `@treeship/core-wasm` at EXACTLY 0.24.0 --
# no caret, deliberately, to stop silent drift. That same pin stops the fix
# from propagating: publishing a repaired core-wasm as 0.24.1 does not reach
# them, and `npm i @treeship/verify` keeps resolving the broken build. So a
# green core-wasm gate can sit next to a broken user install indefinitely.
#
# The load is also lazy -- `verify-js` imports the wasm on first call, not at
# module load -- so importing the package is not proof of anything. This
# calls a verify function and requires a real verdict.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "  building core-wasm and verify-js..."
CORE="$ROOT/packages/core-wasm/pkg"
[ -d "$CORE" ] || { echo "  err   $CORE not built; run packages/core-wasm/build-npm.sh <version>"; exit 1; }

# Deps first: a missing node_modules made this report "build failed" when the
# build was fine, which is exactly the misattribution this file complains
# about. Show the real output on failure instead of swallowing it.
( cd "$ROOT/packages/verify-js" && npm install --silent >/dev/null 2>&1 ) || true
if ! ( cd "$ROOT/packages/verify-js" && npm run build 2>&1 | tail -20 ); then
  echo "  err   verify-js build failed (output above)"
  exit 1
fi

CORE_TGZ="$(cd "$CORE" && npm pack --silent | tail -1)"
VFY_TGZ="$(cd "$ROOT/packages/verify-js" && npm pack --silent | tail -1)"

cd "$TMP"
npm init -y >/dev/null 2>&1
# Install the LOCAL core-wasm first so the pin resolves to the fixed build
# rather than whatever the registry still has at 0.24.0.
npm i "$CORE/$CORE_TGZ" "$ROOT/packages/verify-js/$VFY_TGZ" --silent >/dev/null 2>&1

# The pin must resolve to the local build, not the registry.
#
# This works without touching the pin because the CI step builds core-wasm at
# whatever version the pin already names -- so the LOCAL, fixed build is
# installed under the pinned version and npm dedupes. The gate therefore tests
# the repaired build under today's pin, with nothing unpublished involved.
#
# Bumping the four pins by hand was the wrong instinct and CI said so: it
# pointed them at 0.24.1, which does not exist on npm, and six jobs failed with
# ETARGET. `check-release-versions.py` already enforces that all four pins move
# in lockstep with core-wasm -- it was added because exactly this shipped broken
# at 0.9.6 -- so the bump belongs to the release, not to a fix PR.
#
# This is the check that catches the propagation bug. verify-js pins
# core-wasm EXACTLY, so if the pin still names a published-broken version,
# npm installs the local fixed copy at top level AND the broken one nested
# under verify-js -- and the nested one wins. Verified live: top level 0.24.1,
# nested 0.24.0, user gets 0.24.0.
NESTED="node_modules/@treeship/verify/node_modules/@treeship/core-wasm/package.json"
if [ -f "$NESTED" ]; then
  NESTED_VER="$(node -p "require('./$NESTED').version")"
  echo "  err   @treeship/verify resolved its own nested core-wasm ($NESTED_VER)."
  echo "        Its pin does not match the build under test, so the fix does not"
  echo "        reach users no matter how green the core-wasm gate is."
  exit 1
fi

cat > t.mjs <<'EOF'
const m = await import('@treeship/verify');
const fn = m.verifyReceipt ?? m.verify_receipt ?? m.default?.verifyReceipt;
if (typeof fn !== 'function') {
  console.error('  err   @treeship/verify exposes no verifyReceipt; exports:',
    Object.keys(m).join(', '));
  process.exit(1);
}
// The wasm loads lazily, so importing proves nothing. Call it.
let out;
try {
  out = await fn(JSON.stringify({
    payload: 'e30',
    payloadType: 'application/vnd.treeship.receipt+json;v=1',
    signatures: [{ sig: 'AAAA', keyid: 'k' }],
  }));
} catch (e) {
  console.error('  err   verify threw before producing a verdict:', String(e).slice(0, 160));
  process.exit(1);
}
const verdict = typeof out === 'string' ? JSON.parse(out) : out;
if (verdict && verdict.valid === true) {
  console.error('  err   a tampered receipt verified; the module is not doing the work');
  process.exit(1);
}
console.log('    @treeship/verify rejected a tampered receipt — wasm loaded and ran');
EOF

node t.mjs
echo "  ✓ @treeship/verify installs and verifies under $(node --version)"
