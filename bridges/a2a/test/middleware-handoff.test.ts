import { readFileSync } from 'node:fs';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// Same scaffold as gate.test.ts: every CLI call goes through this mock, and
// what is asserted here is WHICH commands the middleware issues and with what
// arguments -- the CLI's own refusals are covered by tests/a2a/ on real ships.
const execFileMock = vi.hoisted(() => {
  const fn = vi.fn() as unknown as {
    (...args: unknown[]): unknown;
    impl: (...args: unknown[]) => Promise<{ stdout: string; stderr: string }>;
    [key: symbol]: unknown;
  };
  fn.impl = async () => ({ stdout: '', stderr: '' });
  fn[Symbol.for('nodejs.util.promisify.custom')] = (...args: unknown[]) => fn.impl(...args);
  return fn;
});
vi.mock('node:child_process', () => ({ execFile: execFileMock }));

import { TreeshipA2AMiddleware } from '../src/middleware.js';

const MINT = readFileSync(new URL('./fixtures/mint-challenge.json', import.meta.url), 'utf8');
const ACCEPTED = readFileSync(new URL('./fixtures/verify-accepted.json', import.meta.url), 'utf8');
const REPLAYED = readFileSync(new URL('./fixtures/verify-replayed-nonce.json', import.meta.url), 'utf8');
const NONCE = (JSON.parse(MINT) as { nonce: string }).nonce;

type Call = string[];
let calls: Call[];

/** Script the CLI: mint succeeds, verify answers as configured, attests return ids. */
function scriptCli(verify: { stdout?: string; fail?: string }) {
  calls = [];
  execFileMock.impl = async (_cmd: unknown, argv: unknown) => {
    const a = argv as string[];
    calls.push(a);
    if (a[0] === 'session' && a[1] === 'mint-challenge') return { stdout: MINT, stderr: '' };
    if (a[0] === 'verify-presentation') {
      if (verify.fail !== undefined) {
        throw Object.assign(new Error('cli failed'), { code: 1, stderr: '', stdout: verify.fail });
      }
      return { stdout: verify.stdout ?? ACCEPTED, stderr: '' };
    }
    if (a[0] === 'attest' && a[1] === 'action') return { stdout: JSON.stringify({ id: 'art_intent' }), stderr: '' };
    if (a[0] === 'attest' && a[1] === 'handoff') return { stdout: JSON.stringify({ id: 'art_handoff' }), stderr: '' };
    return { stdout: '', stderr: '' };
  };
}

const handoffCalls = () => calls.filter((a) => a[0] === 'attest' && a[1] === 'handoff');

beforeEach(() => {
  delete process.env.TREESHIP_A2A_UNVERIFIED;
});
afterEach(() => vi.clearAllMocks());

describe('the receiver records the verify it performed as a live handoff', () => {
  it('mints `attest handoff --verified --challenge` after a verified admit, naming the presenter', async () => {
    scriptCli({});
    const mw = new TreeshipA2AMiddleware({ shipId: 'shp_c', receiptBaseUrl: 'https://treeship.dev/receipt' });
    const nonce = await mw.mintTaskChallenge('t1');
    expect(nonce).toBe(NONCE);

    const admitted = await mw.admitTask({ taskId: 't1', presentationPath: 'inbox/grok.presentation.json', maxStapleAge: '1h' });
    expect(admitted.allowed).toBe(true);

    await mw.onTaskReceived({ taskId: 't1', fromAgent: 'agent://grok', skill: 'review' });

    const [call, ...rest] = handoffCalls();
    expect(rest).toHaveLength(0);
    expect(call).toBeDefined();
    const arg = (flag: string) => call[call.indexOf(flag) + 1];
    expect(arg('--from')).toBe('agent://grok');
    expect(arg('--to')).toBe(mw.actor);
    expect(arg('--artifacts')).toBe('art_intent');
    expect(arg('--verified')).toBe('inbox/grok.presentation.json');
    expect(arg('--challenge')).toBe(NONCE);
    expect(arg('--max-staple-age')).toBe('1h');

    const result = await mw.onTaskCompleted({ taskId: 't1', elapsedMs: 1, status: 'completed' });
    expect(result.handoffId).toBe('art_handoff');
    const decorated = mw.decorateArtifact({ metadata: {} } as { metadata?: Record<string, unknown> }, result);
    expect(decorated?.metadata?.treeship_handoff_id).toBe('art_handoff');
  });

  it('never mints a live handoff for an unverified opt-out', async () => {
    // The opt-out already leaves `a2a.gate.skipped`. A handoff claiming live
    // custody on top of it would launder the skip into a verify.
    process.env.TREESHIP_A2A_UNVERIFIED = '1';
    scriptCli({ fail: REPLAYED });
    const mw = new TreeshipA2AMiddleware({ shipId: 'shp_c', receiptBaseUrl: 'https://treeship.dev/receipt' });
    await mw.mintTaskChallenge('t2');
    const admitted = await mw.admitTask({ taskId: 't2', presentationPath: 'inbox/old.presentation.json' });
    expect(admitted.allowed).toBe(true);
    expect('unverified' in admitted && admitted.unverified).toBe(true);

    await mw.onTaskReceived({ taskId: 't2', fromAgent: 'agent://grok' });
    expect(handoffCalls()).toHaveLength(0);
    const result = await mw.onTaskCompleted({ taskId: 't2', elapsedMs: 1, status: 'completed' });
    expect(result.handoffId).toBeUndefined();
  });

  it('spends the nonce on one task: a second receipt of the same task records no second handoff', async () => {
    scriptCli({});
    const mw = new TreeshipA2AMiddleware({ shipId: 'shp_c', receiptBaseUrl: 'https://treeship.dev/receipt' });
    await mw.mintTaskChallenge('t3');
    await mw.admitTask({ taskId: 't3', presentationPath: 'inbox/p.json' });
    await mw.onTaskReceived({ taskId: 't3', fromAgent: 'agent://grok' });
    await mw.onTaskReceived({ taskId: 't3', fromAgent: 'agent://grok' });
    expect(handoffCalls()).toHaveLength(1);
  });

  it('records nothing when the gate refused', async () => {
    scriptCli({ fail: REPLAYED });
    const mw = new TreeshipA2AMiddleware({ shipId: 'shp_c', receiptBaseUrl: 'https://treeship.dev/receipt' });
    await mw.mintTaskChallenge('t4');
    const admitted = await mw.admitTask({ taskId: 't4', presentationPath: 'inbox/old.json' });
    expect(admitted.allowed).toBe(false);
    expect(handoffCalls()).toHaveLength(0);
  });
});
