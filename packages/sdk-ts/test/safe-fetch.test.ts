/**
 * Shared SSRF vectors against this package's guard. The MCP bridge runs the
 * same file; two copies of a security control drift, and drift here is
 * silent — the bridge keeps verifying receipts, it just stops refusing the
 * bad ones.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { assertFetchableUrl, isPrivateAddress, UnsafeUrlError } from "../src/safe-fetch.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, "..", "..", "..", "tests", "vectors", "ssrf-urls.json"), "utf8"),
) as {
  blocked: Array<{ url: string; why: string }>;
  allowed: Array<{ url: string; why: string }>;
};

describe("SSRF guard", () => {
  it("has vectors to run", () => {
    // A vector file that failed to load would make every case below vacuous.
    expect(vectors.blocked.length).toBeGreaterThan(10);
    expect(vectors.allowed.length).toBeGreaterThan(0);
  });

  for (const { url, why } of vectors.blocked) {
    it(`blocks ${url} — ${why}`, () => {
      expect(() => assertFetchableUrl(url)).toThrow(UnsafeUrlError);
    });
  }

  // The other failure: a guard that rejects real Hub URLs closes the hole and
  // the feature together, which is how a check gets reverted rather than fixed.
  for (const { url, why } of vectors.allowed) {
    it(`allows ${url} — ${why}`, () => {
      expect(() => assertFetchableUrl(url)).not.toThrow();
    });
  }
});

describe("isPrivateAddress", () => {
  it("treats a non-IP hostname as unknown, not public", () => {
    // Callers must not read `false` as "safe" for a name — that is what the
    // DNS resolution step is for.
    expect(isPrivateAddress("hub.example.com")).toBe(false);
  });

  it("covers the RFC 1918 boundaries, not just the middle", () => {
    expect(isPrivateAddress("172.15.0.1")).toBe(false); // just below the range
    expect(isPrivateAddress("172.16.0.1")).toBe(true);
    expect(isPrivateAddress("172.31.255.255")).toBe(true);
    expect(isPrivateAddress("172.32.0.1")).toBe(false); // just above
  });

  it("refuses malformed dotted quads rather than passing them through", () => {
    // 999.1.1.1 is not a public address; it is not an address. Anything a
    // resolver might interpret creatively should not be treated as safe.
    expect(isPrivateAddress("999.1.1.1")).toBe(true);
  });

  it("sees through IPv6 zone ids and brackets", () => {
    expect(isPrivateAddress("[::1]")).toBe(true);
    expect(isPrivateAddress("fe80::1%eth0")).toBe(true);
  });

  it("allows genuine public addresses", () => {
    expect(isPrivateAddress("93.184.216.34")).toBe(false);
    expect(isPrivateAddress("2606:2800:220:1:248:1893:25c8:1946")).toBe(false);
  });
});
