// Cross-SDK vectors shared with packages/core/tests/resolution_vectors.rs and
// packages/verify-js/test/resolution-vectors.test.ts.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ship } from "../src/index.js";

const FILE = join(__dirname, "../../../tests/vectors/resolution/vectors.json");

interface Case {
  name: string;
  why: string;
  now: string;
  trust_roots: { version: number; roots: unknown[] };
  bundle: Record<string, unknown>;
  presentation: Record<string, unknown>;
  expected: { sig_ok: boolean; key_bound: boolean; revoked: boolean; key_bound_reason?: string | null };
}

const doc = JSON.parse(readFileSync(FILE, "utf8")) as { cases: Case[] };

describe("resolution vectors via the SDK", () => {
  for (const c of doc.cases) {
    it(c.name, async () => {
      // The SDK takes camelCase trust roots and serializes them for the wasm.
      const roots = (c.trust_roots.roots as Array<Record<string, string>>).map((r) => ({
        keyId: r.key_id,
        publicKey: r.public_key,
        kind: r.kind,
        agent: r.agent,
        label: r.label,
      })) as never;
      const v = (await ship().verify.verifyResolution(c.bundle as never, roots, c.now)) as unknown as Record<string, unknown>;
      expect(v.key_bound, `${c.why}: resolution key_bound`).toBe(c.expected.key_bound);
      expect(Boolean(v.revoked), `${c.why}: resolution revoked`).toBe(c.expected.revoked);
      const p = (await ship().verify.verifyPresentation(c.presentation as never, roots, { now: c.now })) as unknown as Record<string, unknown>;
      expect(p.key_bound, `${c.why}: presentation key_bound`).toBe(c.expected.key_bound);
      expect(p.revoked !== null && p.revoked !== undefined, `${c.why}: presentation revoked`).toBe(c.expected.revoked);
      if (c.expected.key_bound_reason) {
        expect(v.key_bound_reason, `${c.why}: reason`).toBe(c.expected.key_bound_reason);
        expect(p.key_bound_reason, `${c.why}: reason`).toBe(c.expected.key_bound_reason);
      }
    });
  }
});
