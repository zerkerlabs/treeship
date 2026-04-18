import { describe, it, expect } from 'vitest';
import {
  verifyReceipt,
  verifyCertificate,
  crossVerify,
} from '../src/index.js';

describe('@treeship/verify', () => {
  it('exports verifyReceipt, verifyCertificate, crossVerify', () => {
    expect(typeof verifyReceipt).toBe('function');
    expect(typeof verifyCertificate).toBe('function');
    expect(typeof crossVerify).toBe('function');
  });

  // Live runtime tests (real WASM loads with a real receipt fixture) run
  // in the edge-runtime acceptance harness at tests/runtime-acceptance/,
  // not here -- those need vite-plugin-wasm configured per target and a
  // real core-wasm published to the registry. Vitest's default Node
  // loader does not resolve bundler-target WASM without the plugin, so
  // we keep this suite existence-only.
});
