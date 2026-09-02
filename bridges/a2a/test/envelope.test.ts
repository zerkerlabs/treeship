import { describe, expect, it } from 'vitest';
import { A2A_SPEC, parseEnvelope, resolveSenderPath } from '../src/envelope.js';

function envelope(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    spec: A2A_SPEC,
    kind: 'offer',
    id: 'a2a_01HZX',
    from: 'agent://grok',
    to: 'agent://claude',
    created_at: '2026-09-01T15:04:05Z',
    reply_to: null,
    body: {},
    ...over,
  });
}

describe('parseEnvelope refuses what it does not understand', () => {
  it('accepts a well-formed offer', () => {
    const r = parseEnvelope(envelope());
    expect(r.ok).toBe(true);
  });

  it('refuses an unknown spec instead of assuming v1', () => {
    // Assuming v1 is how a future field with security meaning gets ignored.
    const r = parseEnvelope(envelope({ spec: 'treeship.a2a/v2' }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/unknown spec/);
  });

  it('refuses a missing spec', () => {
    const r = parseEnvelope(JSON.stringify({ kind: 'offer', id: 'x' }));
    expect(r.ok).toBe(false);
  });

  it('refuses an unknown kind', () => {
    expect(parseEnvelope(envelope({ kind: 'execute' })).ok).toBe(false);
  });

  it.each(['id', 'from', 'to', 'created_at'])('refuses a blank %s', (field) => {
    expect(parseEnvelope(envelope({ [field]: '  ' })).ok).toBe(false);
  });

  it('refuses a non-object body', () => {
    expect(parseEnvelope(envelope({ body: 'nope' })).ok).toBe(false);
  });

  it('refuses a refusal reason no host handles', () => {
    // A `refuse` carrying an unknown reason is a silent dead end for the sender.
    const r = parseEnvelope(envelope({ kind: 'refuse', body: { refusal: 'vibes' } }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not a known refusal/);
  });

  it('accepts every refusal the gate can produce', () => {
    for (const refusal of [
      'no_presentation',
      'no_challenge',
      'challenge_failed',
      'untrusted_issuer',
      'revoked',
      'stale',
      'verification_failed',
      'gate_unavailable',
    ]) {
      expect(parseEnvelope(envelope({ kind: 'refuse', body: { refusal } })).ok).toBe(true);
    }
  });

  it('refuses a short challenge nonce', () => {
    expect(parseEnvelope(envelope({ kind: 'challenge', body: { nonce: 'short' } })).ok).toBe(false);
    expect(parseEnvelope(envelope({ kind: 'challenge', body: { nonce: 'n'.repeat(32) } })).ok).toBe(true);
  });

  it('refuses an envelope carrying a private key', () => {
    const r = parseEnvelope(
      envelope({ body: { note: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----' } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/no secrets/);
  });

  it('refuses non-JSON without throwing', () => {
    expect(parseEnvelope('<html>').ok).toBe(false);
  });
});

describe('resolveSenderPath confines a path the other agent chose', () => {
  const base = '/workspace/treeship/inbox';

  it('resolves a plain relative path inside the base', () => {
    expect(resolveSenderPath(base, 'peer.presentation.json')).toBe(
      '/workspace/treeship/inbox/peer.presentation.json',
    );
  });

  it('refuses traversal out of the base', () => {
    // The sender names this path and we hand it to verify-presentation, so an
    // unconfined value is an arbitrary read driven by an unproven party.
    expect(resolveSenderPath(base, '../../../etc/passwd')).toBeNull();
    expect(resolveSenderPath(base, 'a/../../../../etc/passwd')).toBeNull();
  });

  it('refuses an absolute path', () => {
    expect(resolveSenderPath(base, '/etc/passwd')).toBeNull();
    // Including one pointing at a presentation we minted ourselves.
    expect(resolveSenderPath(base, '/workspace/treeship/presentations/ours.json')).toBeNull();
  });

  it('refuses the base itself and empty input', () => {
    expect(resolveSenderPath(base, '.')).toBeNull();
    expect(resolveSenderPath(base, '')).toBeNull();
    expect(resolveSenderPath(base, '   ')).toBeNull();
  });

  it('refuses a NUL byte', () => {
    expect(resolveSenderPath(base, 'ok.json\0.png')).toBeNull();
  });

  it('allows a nested path that stays inside', () => {
    expect(resolveSenderPath(base, 'sub/peer.json')).toBe('/workspace/treeship/inbox/sub/peer.json');
  });
});

describe('handoff envelopes carry a readable custody record', () => {
  const handoff = (body: Record<string, unknown>) =>
    JSON.stringify({
      spec: A2A_SPEC,
      kind: 'handoff',
      id: 'a2a_01',
      from: 'agent://grok',
      to: 'agent://claude',
      created_at: '2026-09-02T00:00:00Z',
      reply_to: 'a2a_00',
      body,
    });

  it('accepts the shape the spec documents', () => {
    const r = parseEnvelope(
      handoff({
        from: 'agent://grok',
        to: 'agent://claude',
        artifacts: ['art_1'],
        verify_artifact: 'art_handoff',
        close_loop: { kind: 'wrap', session_id: 'ssn_1', command: 'npm test' },
      }),
    );
    expect(r.ok).toBe(true);
  });

  it('accepts null verify_artifact and null close_loop (asserted custody, no evidence)', () => {
    const r = parseEnvelope(
      handoff({ from: 'agent://a', to: 'agent://b', artifacts: [], verify_artifact: null, close_loop: null }),
    );
    expect(r.ok).toBe(true);
  });

  it('refuses a handoff that names no parties', () => {
    const r = parseEnvelope(handoff({ to: 'agent://b', artifacts: ['art_1'] }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/handoff\.body\.from/);
  });

  it('refuses artifacts that are not a list of ids', () => {
    const r = parseEnvelope(handoff({ from: 'agent://a', to: 'agent://b', artifacts: 'art_1' }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/artifacts/);
  });

  it('refuses close-loop evidence that cannot be located', () => {
    // Evidence without a session id is a note, not evidence.
    const r = parseEnvelope(
      handoff({ from: 'agent://a', to: 'agent://b', artifacts: ['art_1'], close_loop: { kind: 'wrap' } }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/close_loop/);
  });
});
