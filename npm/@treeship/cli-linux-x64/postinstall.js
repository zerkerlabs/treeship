// @treeship/cli-darwin-arm64 -- platform binary postinstall.
//
// Downloads the Treeship CLI binary from the matching GitHub Release
// and verifies its SHA-256 against the expected hash that ships
// inside this npm package. Both halves of the trust path matter:
//
//   1. The expected hash arrives via npm (signed by npm's package
//      integrity, separate trust root from GitHub).
//   2. The binary arrives via GitHub Releases.
//   3. If either is tampered, the hashes don't match and we abort.
//
// Earlier versions (<= 0.10.0) downloaded the binary, chmod +x'd it,
// and exited 0 -- no integrity check, and an install failure also
// exited 0 (claiming success). This file is the v0.10.1 hardening.

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const VERSION = require('./package.json').version;
const BINARY_NAME = 'treeship-linux-x86_64';
const URL = 'https://github.com/zerkerlabs/treeship/releases/download/v' + VERSION + '/' + BINARY_NAME;
const BIN_DIR = path.join(__dirname, 'bin');
const DEST = path.join(BIN_DIR, 'treeship');
const PARTIAL = DEST + '.partial';
const CHECKSUM_FILE = path.join(__dirname, 'expected-checksum.txt');

// Read the expected SHA-256 that the release pipeline embedded in this
// package. Format: a single line, lowercase hex, 64 chars. If absent
// or malformed, refuse to install -- a binary without a published
// checksum is an unverifiable binary.
function readExpectedChecksum() {
  let raw;
  try {
    raw = fs.readFileSync(CHECKSUM_FILE, 'utf8');
  } catch (e) {
    return null;
  }
  const hex = raw.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  return hex;
}

function abort(reason, code) {
  // Always delete the partial download so a retry doesn't think it
  // already has the binary.
  try { if (fs.existsSync(PARTIAL)) fs.unlinkSync(PARTIAL); } catch {}
  console.error('treeship: install failed -- ' + reason);
  console.error('  Recover:');
  console.error('    1. Re-run the install (transient network/CDN issues clear up):');
  console.error('       npm install -g treeship');
  console.error('    2. Or download the binary directly and place it on PATH:');
  console.error('       https://github.com/zerkerlabs/treeship/releases/tag/v' + VERSION);
  console.error('    3. Or build from source:');
  console.error('       git clone https://github.com/zerkerlabs/treeship');
  console.error('       cd treeship && cargo build --release -p treeship-cli');
  process.exit(code || 1);
}

const expected = readExpectedChecksum();
if (!expected) {
  abort(
    'expected-checksum.txt missing or malformed in ' + path.basename(__dirname) +
    '. This npm package was published without a binary integrity hash and ' +
    'cannot be installed safely. File an issue at ' +
    'https://github.com/zerkerlabs/treeship/issues so we can re-publish it.',
    1,
  );
}

if (fs.existsSync(DEST)) {
  // Already installed and verified previously -- nothing to do.
  process.exit(0);
}

fs.mkdirSync(BIN_DIR, { recursive: true });
console.log('treeship: downloading ' + BINARY_NAME + ' v' + VERSION + ' ...');

function download(url, redirects) {
  if (redirects > 5) return abort('too many redirects', 1);

  const req = https.get(url, (res) => {
    if (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) {
      res.resume();
      return download(res.headers.location, redirects + 1);
    }
    if (res.statusCode !== 200) {
      res.resume();
      return abort('download HTTP ' + res.statusCode + ' from ' + url, 1);
    }

    const hash = crypto.createHash('sha256');
    const file = fs.createWriteStream(PARTIAL);

    res.on('data', (chunk) => {
      hash.update(chunk);
      file.write(chunk);
    });
    res.on('end', () => {
      file.end(() => {
        const got = hash.digest('hex');
        if (got !== expected) {
          // Delete the partial file before aborting so a retry can't
          // pick up the bad bytes.
          try { fs.unlinkSync(PARTIAL); } catch {}
          return abort(
            'SHA-256 mismatch.\n' +
            '       expected: ' + expected + '\n' +
            '       got:      ' + got + '\n' +
            '       This means either the GitHub Release was tampered with, ' +
            'a CDN cached a stale or malicious binary, or the npm package ' +
            'and the release are out of sync. Do not run the binary.',
            1,
          );
        }
        try {
          fs.renameSync(PARTIAL, DEST);
          fs.chmodSync(DEST, 0o755);
        } catch (e) {
          return abort('could not finalize binary: ' + e.message, 1);
        }
        console.log('treeship: installed (sha256 verified)');
      });
    });
    res.on('error', (e) => abort('stream error: ' + e.message, 1));
    file.on('error', (e) => abort('write error: ' + e.message, 1));
  });
  req.on('error', (e) => abort('connection error: ' + e.message, 1));
  req.setTimeout(60_000, () => {
    req.destroy();
    abort('download timed out after 60s', 1);
  });
}

download(URL, 0);
