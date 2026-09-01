import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// The gate shells out to the CLI. Every test drives the CLI's behaviour
// through this mock, because what we are asserting is the gate's DECISION,
// not the verifier's cryptography (which has its own tests in core).
const execFileMock = vi.hoisted(() => {
  const fn = vi.fn() as unknown as {
    (...args: unknown[]): unknown;
    impl: (...args: unknown[]) => Promise<{ stdout: string; stderr: string }>;
    [key: symbol]: unknown;
  };
  fn.impl = async () => ({ stdout: '', stderr: '' });
  // `promisify(execFile)` runs at module-load time inside gate.ts, and ES
  // imports hoist above top-level statements -- so this symbol has to exist
  // before the import, not after it.
  fn[Symbol.for('nodejs.util.promisify.custom')] = (...args: unknown[]) => fn.impl(...args);
  return fn;
});
vi.mock('node:child_process', () => ({ execFile: execFileMock }));

import { classifyRefusal, gateInbound, mintChallenge } from '../src/gate.js';

function cliSucceeds(stdout = '{"status":"verified"}') {
  execFileMock.impl = async () => ({ stdout, stderr: '' });
}
function cliFails(stderr: string, code = 1) {
  execFileMock.impl = async () => {
    const e = Object.assign(new Error('cli failed'), { code, stderr, stdout: '' });
    throw e;
  };
}
function cliMissing() {
  execFileMock.impl = async () => {
    throw Object.assign(new Error('spawn treeship ENOENT'), { code: 'ENOENT', path: 'treeship' });
  };
}

beforeEach(() => {
  delete process.env.TREESHIP_A2A_UNVERIFIED;
  execFileMock.impl = async () => ({ stdout: '', stderr: '' });
});
afterEach(() => vi.clearAllMocks());

describe('the gate refuses before it runs the work', () => {
  it('refuses when no presentation was supplied', async () => {
    // The whole point of fail-closed: absent evidence is refusal, not a pass.
    cliSucceeds();
    const result = await gateInbound({ presentationPath: undefined, challenge: 'n'.repeat(32) });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.refusal).toBe('no_presentation');
  });

  it('refuses when no challenge was minted', async () => {
    // A presentation without a live challenge proves a document exists,
    // not that the counterparty controls the key.
    cliSucceeds();
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: undefined });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.refusal).toBe('no_challenge');
  });

  it('refuses when the CLI is missing instead of allowing the work', async () => {
    // This is the inversion that matters. Attestation swallows a missing CLI
    // because failing to RECORD work is no reason to refuse work. The gate
    // does the opposite: a gate that cannot run must not look like a gate
    // that passed.
    cliMissing();
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: 'n'.repeat(32) });
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.refusal).toBe('gate_unavailable');
  });

  it('passes the minted challenge to the verifier, never a caller-supplied one', async () => {
    let seenArgs: string[] = [];
    execFileMock.impl = async (_bin: string, args: string[]) => {
      seenArgs = args;
      return { stdout: '{"status":"verified"}', stderr: '' };
    };
    const nonce = 'a'.repeat(32);
    await gateInbound({ presentationPath: '/tmp/peer.json', challenge: nonce });
    expect(seenArgs).toContain('--challenge');
    expect(seenArgs[seenArgs.indexOf('--challenge') + 1]).toBe(nonce);
  });

  it('allows the work when the presentation verifies against the challenge', async () => {
    cliSucceeds();
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: 'a'.repeat(32) });
    expect(result.allowed).toBe(true);
  });
});

describe('refusal reasons are legible to the calling agent', () => {
  it.each([
    ['CHALLENGE FAILED: nonce did not match', 'challenge_failed'],
    ['presentation is STALE: staple is 4h old', 'stale'],
    ['untrusted issuer: no pinned cert_issuer for ship_abc', 'untrusted_issuer'],
    ['card was revoked at 2026-01-01', 'revoked'],
    ['some unmapped verifier complaint', 'verification_failed'],
  ])('maps %j to %s', async (stderr, expected) => {
    cliFails(stderr);
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: 'a'.repeat(32) });
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.refusal).toBe(expected);
      // The other agent has to be able to act on this, so the verifier's own
      // words survive rather than being replaced by our label.
      expect(result.message).toContain(stderr.slice(0, 12));
    }
  });

  it('classifies case-insensitively', () => {
    expect(classifyRefusal('challenge failed')).toBe('challenge_failed');
    expect(classifyRefusal('STALE')).toBe('stale');
  });
});

describe('the opt-out is explicit and never silent', () => {
  it('allows unverified work only with the env opt-out, and marks it', async () => {
    process.env.TREESHIP_A2A_UNVERIFIED = '1';
    cliFails('CHALLENGE FAILED');
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: 'a'.repeat(32) });
    expect(result.allowed).toBe(true);
    // A skipped gate that records nothing is indistinguishable from a gate
    // that passed. The flag exists so the receipt can say so.
    if (result.allowed) {
      expect(result.unverified).toBe(true);
      expect(result.reason).toContain('challenge_failed');
    }
  });

  it('does not treat an arbitrary env value as opt-in', async () => {
    process.env.TREESHIP_A2A_UNVERIFIED = '0';
    cliFails('CHALLENGE FAILED');
    const result = await gateInbound({ presentationPath: '/tmp/peer.json', challenge: 'a'.repeat(32) });
    expect(result.allowed).toBe(false);
  });
});

describe('mintChallenge', () => {
  it('refuses a nonce the CLI could not mint rather than inventing one', async () => {
    cliMissing();
    expect(await mintChallenge()).toBeNull();
  });

  it('rejects a short nonce even if the CLI returned one', async () => {
    // Matches the CLI's own rule: a guessable nonce can be pre-signed, which
    // makes the liveness proof prove only that a document exists.
    execFileMock.impl = async () => ({ stdout: '{"challenge":"tooshort"}', stderr: '' });
    expect(await mintChallenge()).toBeNull();
  });

  it('returns the minted nonce', async () => {
    const nonce = 'b'.repeat(32);
    execFileMock.impl = async () => ({ stdout: JSON.stringify({ challenge: nonce }), stderr: '' });
    expect(await mintChallenge()).toBe(nonce);
  });
});

describe('admitTask leaves evidence for every outcome', () => {
  // The middleware's other paths swallow a missing CLI. The gate must not, and
  // a skip or refusal must produce an artifact -- otherwise "refused the work"
  // and "never saw the work" are the same silence in the log.
  const attestMock = vi.hoisted(() => vi.fn(async () => 'art_stub'));
  vi.mock('../src/attest.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../src/attest.js')>();
    return { ...actual, attestAction: attestMock, provisionAgentKey: vi.fn(async () => undefined) };
  });

  async function middleware() {
    const { TreeshipA2AMiddleware } = await import('../src/middleware.js');
    return new TreeshipA2AMiddleware({ shipId: 'shp_test' });
  }

  beforeEach(() => {
    attestMock.mockClear();
    delete process.env.TREESHIP_A2A_UNVERIFIED;
  });

  it('refuses when no challenge was minted for this task', async () => {
    cliSucceeds();
    const mw = await middleware();
    // admitTask without a prior mintTaskChallenge: there is no nonce, so the
    // presentation cannot be answering one.
    const result = await mw.admitTask({ taskId: 't1', presentationPath: '/tmp/peer.json' });
    expect(result.allowed).toBe(false);
  });

  it('attests a refusal', async () => {
    execFileMock.impl = async (_bin: string, args: string[]) => {
      if (args.includes('mint-challenge')) return { stdout: `{"challenge":"${'c'.repeat(32)}"}`, stderr: '' };
      throw Object.assign(new Error('x'), { stderr: 'CHALLENGE FAILED', code: 1 });
    };
    const mw = await middleware();
    await mw.mintTaskChallenge('t2');
    const result = await mw.admitTask({ taskId: 't2', presentationPath: '/tmp/peer.json' });

    expect(result.allowed).toBe(false);
    const actions = attestMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain('a2a.gate.refused');
  });

  it('attests the skip when the opt-out is used', async () => {
    process.env.TREESHIP_A2A_UNVERIFIED = '1';
    execFileMock.impl = async (_bin: string, args: string[]) => {
      if (args.includes('mint-challenge')) return { stdout: `{"challenge":"${'c'.repeat(32)}"}`, stderr: '' };
      throw Object.assign(new Error('x'), { stderr: 'CHALLENGE FAILED', code: 1 });
    };
    const mw = await middleware();
    await mw.mintTaskChallenge('t3');
    const result = await mw.admitTask({ taskId: 't3', presentationPath: '/tmp/peer.json' });

    expect(result.allowed).toBe(true);
    const actions = attestMock.mock.calls.map((c) => (c[0] as { action: string }).action);
    expect(actions).toContain('a2a.gate.skipped');
  });

  it('stamps the gate outcome onto the intent artifact', async () => {
    execFileMock.impl = async (_bin: string, args: string[]) => {
      if (args.includes('mint-challenge')) return { stdout: `{"challenge":"${'c'.repeat(32)}"}`, stderr: '' };
      return { stdout: '{"status":"verified"}', stderr: '' };
    };
    const mw = await middleware();
    await mw.mintTaskChallenge('t4');
    await mw.admitTask({ taskId: 't4', presentationPath: '/tmp/peer.json' });
    attestMock.mockClear();
    await mw.onTaskReceived({ taskId: 't4', skill: 'research' });

    const meta = (attestMock.mock.calls[0]?.[0] as { meta: Record<string, unknown> }).meta;
    expect(meta.gate_status).toBe('verified');
  });

  it('records an ungated task as not_gated rather than implying it passed', async () => {
    cliSucceeds();
    const mw = await middleware();
    await mw.onTaskReceived({ taskId: 't5', skill: 'research' });
    const meta = (attestMock.mock.calls[0]?.[0] as { meta: Record<string, unknown> }).meta;
    expect(meta.gate_status).toBe('not_gated');
  });
});
