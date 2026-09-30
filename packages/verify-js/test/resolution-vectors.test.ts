// Cross-SDK vectors for the resolution and presentation verifiers. The same
// file drives packages/core/tests/resolution_vectors.rs, so Rust and JS
// verdicts cannot drift. In CI the locally built @treeship/core-wasm is
// installed before this runs.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyResolution, verifyPresentation } from '../src/index.js';

const FILE = join(__dirname, '../../../tests/vectors/resolution/vectors.json');

interface Case {
  name: string;
  why: string;
  now: string;
  trust_roots: { version: number; roots: unknown[] };
  bundle: Record<string, unknown>;
  presentation: Record<string, unknown>;
  expected: { sig_ok: boolean; key_bound: boolean; revoked: boolean; key_bound_reason?: string | null };
}

const doc = JSON.parse(readFileSync(FILE, 'utf8')) as { cases: Case[] };

describe('resolution vectors', () => {
  for (const c of doc.cases) {
    it(`resolution: ${c.name}`, async () => {
      const v = (await verifyResolution(
        c.bundle as never,
        c.trust_roots as never,
        c.now,
      )) as unknown as Record<string, unknown>;
      expect(v.sig_ok, `${c.why}: sig_ok`).toBe(c.expected.sig_ok);
      expect(v.key_bound, `${c.why}: key_bound`).toBe(c.expected.key_bound);
      expect(Boolean(v.revoked), `${c.why}: revoked`).toBe(c.expected.revoked);
      if (c.expected.key_bound_reason) {
        expect(v.key_bound_reason, `${c.why}: key_bound_reason`).toBe(c.expected.key_bound_reason);
      }
    });
    it(`presentation: ${c.name}`, async () => {
      const p = (await verifyPresentation(c.presentation, c.trust_roots as never, {
        now: c.now,
      })) as unknown as Record<string, unknown>;
      expect(p.sig_ok, `${c.why}: sig_ok`).toBe(c.expected.sig_ok);
      expect(p.key_bound, `${c.why}: key_bound`).toBe(c.expected.key_bound);
      expect(p.revoked !== null && p.revoked !== undefined, `${c.why}: revoked`).toBe(
        c.expected.revoked,
      );
      if (c.expected.key_bound_reason) {
        expect(p.key_bound_reason, `${c.why}: key_bound_reason`).toBe(c.expected.key_bound_reason);
      }
    });
  }
});
