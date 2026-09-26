// T2 package vectors through @treeship/verify's verifyPackage (W2-6). The
// verify_js column is a read with no pinned keys; verify_js_pinned pins the
// key(s) the package names, the way the CLI's cli_strict column does.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { verifyPackage, type PackageFiles } from '../src/index.js';

const ROOT = join(__dirname, '../../../tests/vectors/packages');
const expected = JSON.parse(readFileSync(join(ROOT, 'expected.json'), 'utf8')).vectors as Record<
  string,
  Record<string, unknown>
>;

function readPackage(dir: string): PackageFiles {
  const files: PackageFiles = {};
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else files[relative(dir, p).split('\\\\').join('/')] = new Uint8Array(readFileSync(p));
    }
  };
  walk(dir);
  return files;
}

function packageKeys(files: PackageFiles): Record<string, string> {
  const raw = files['keys.json'];
  if (!raw) return {};
  return JSON.parse(new TextDecoder().decode(raw as Uint8Array)).keys ?? {};
}

describe('T2 package vectors: verifyPackage', () => {
  for (const [name, want] of Object.entries(expected)) {
    it(`${name}: no pinned keys → ${want.verify_js}`, async () => {
      const r = await verifyPackage(readPackage(join(ROOT, name)));
      expect(r.verdict, JSON.stringify(r.checks, null, 1)).toBe(want.verify_js);
      if (name.startsWith('tampered/') && !want.verify_js_known_gap) expect(['verified', 'signatures-pass']).not.toContain(r.verdict);
    });
    it(`${name}: package keys pinned → ${want.verify_js_pinned}`, async () => {
      const files = readPackage(join(ROOT, name));
      const r = await verifyPackage(files, { pinnedKeys: packageKeys(files) });
      expect(r.verdict, JSON.stringify(r.checks, null, 1)).toBe(want.verify_js_pinned);
      // A vector may name a documented gap (`verify_js_known_gap`) that only a
      // verifier holding its own trust store can close; the verdict is still
      // pinned to what the library gives so a change is noticed.
      if (name.startsWith('tampered/') && !want.verify_js_known_gap) expect(['verified', 'signatures-pass']).not.toContain(r.verdict);
    });
  }
});

describe('verifyPackage', () => {
  it('receipt.json alone is receipt-only', async () => {
    const files = readPackage(join(ROOT, 'honest/basic'));
    const r = await verifyPackage({ 'receipt.json': files['receipt.json'] });
    expect(r.verdict).toBe('structural-pass');
    expect(r.scope).toBe('receipt-only');
  });

  it('a pinned key that keys.json contradicts fails', async () => {
    const honest = packageKeys(readPackage(join(ROOT, 'honest/basic')));
    const r = await verifyPackage(readPackage(join(ROOT, 'tampered/swap-package-key')), { pinnedKeys: honest });
    expect(r.verdict).toBe('failed');
    expect(r.checks.some((c) => c.detail.includes('different key'))).toBe(true);
  });

  it('a key pinned for a different signer does not make the package verified', async () => {
    const files = readPackage(join(ROOT, 'honest/basic'));
    const r = await verifyPackage(files, { pinnedKeys: { key_0000000000000000: 'ed25519:' + 'A'.repeat(43) } });
    expect(r.verdict).toBe('signatures-pass');
  });

  it('an artifact digest must match in full', async () => {
    const files = readPackage(join(ROOT, 'honest/basic'));
    const receipt = JSON.parse(new TextDecoder().decode(files['receipt.json'] as Uint8Array));
    const d: string = receipt.artifacts[0].digest;
    receipt.artifacts[0].digest = d.slice(0, -1) + (d.endsWith('0') ? '1' : '0');
    const r = await verifyPackage({ ...files, 'receipt.json': JSON.stringify(receipt, null, 2) }, {
      pinnedKeys: packageKeys(files),
    });
    expect(r.verdict).toBe('failed');
    expect(r.artifacts[0].detail).toMatch(/digest/);
  });
});
