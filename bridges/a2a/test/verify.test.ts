import { describe, it, expect } from 'vitest';
import { summarizeVerifiedReceipt } from '../src/verify.js';

describe('@treeship/a2a verifyReceipt trust gating (AUD-27)', () => {
  // A hostile receipt: claims a ship, no declaration, zero violations.
  const hostile = {
    session_id: 'ssn_attacker',
    ship_id: 'ship_VICTIM',
    events: [1, 2],
    artifacts: [1],
    // no `declaration`, no `violations`
  };

  it('does NOT leak shipId / withinDeclaredBounds when unverified', () => {
    const out = summarizeVerifiedReceipt(hostile, {
      structurallyConsistent: false,
      cryptographicallyVerified: false,
    });
    // The trust-bearing fields must not come from the raw JSON.
    expect(out.shipId).toBeUndefined();
    expect(out.withinDeclaredBounds).toBeUndefined();
    expect(out.structurallyConsistent).toBe(false);
    expect(out.cryptographicallyVerified).toBe(false);
    // Informational summary is still available.
    expect(out.sessionId).toBe('ssn_attacker');
    expect(out.events).toBe(2);
  });

  it('does NOT default withinDeclaredBounds to true when there is no declaration', () => {
    // Even when structurally consistent, no declaration means UNKNOWN, not "in bounds".
    const out = summarizeVerifiedReceipt(hostile, {
      structurallyConsistent: true,
      cryptographicallyVerified: false,
    });
    expect(out.withinDeclaredBounds).toBeUndefined();
    expect(out.shipId).toBe('ship_VICTIM'); // shipId is fine once structurally consistent
  });

  it('reports withinDeclaredBounds only with a declaration AND structural consistency', () => {
    const declared = { ...hostile, declaration: { tools: ['x'] }, violations: [] };
    const ok = summarizeVerifiedReceipt(declared, {
      structurallyConsistent: true,
      cryptographicallyVerified: false,
    });
    expect(ok.withinDeclaredBounds).toBe(true);

    const withViolations = { ...declared, violations: ['tool.escape'] };
    const bad = summarizeVerifiedReceipt(withViolations, {
      structurallyConsistent: true,
      cryptographicallyVerified: false,
    });
    expect(bad.withinDeclaredBounds).toBe(false);

    // But if it did not structurally verify, still undefined regardless.
    const unver = summarizeVerifiedReceipt(declared, {
      structurallyConsistent: false,
      cryptographicallyVerified: false,
    });
    expect(unver.withinDeclaredBounds).toBeUndefined();
  });
});
