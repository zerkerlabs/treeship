import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The kill switch reaches the A2A middleware: while `treeship halt <actor>`
// stands, `admitTask` refuses with `halted` and `onTaskReceived` throws,
// and each refusal is signed as `blocked.v1` chained onto the session.

const execFileMock = vi.hoisted(() => {
  const fn = vi.fn() as unknown as {
    (...args: unknown[]): unknown;
    impl: (args: string[]) => Promise<{ stdout: string; stderr: string }>;
    calls_: string[][];
    [key: symbol]: unknown;
  };
  fn.calls_ = [];
  fn.impl = async () => ({ stdout: '', stderr: '' });
  fn[Symbol.for('nodejs.util.promisify.custom')] = (_cmd: string, args: string[]) => {
    fn.calls_.push(args);
    return fn.impl(args);
  };
  return fn;
});
vi.mock('node:child_process', () => ({ execFile: execFileMock }));

import { TreeshipA2AMiddleware, TreeshipHaltedError } from '../src/index.js';

function cli(listing: string | Error) {
  execFileMock.impl = async (args: string[]) => {
    if (args[0] === 'halt' && args[1] === 'list') {
      if (listing instanceof Error) throw listing;
      return { stdout: listing, stderr: '' };
    }
    if (args[0] === 'attest' && args[1] === 'receipt') {
      return { stdout: '{"id":"art_blocked1","status":"ok"}', stderr: '' };
    }
    return { stdout: '{"id":"art_other","status":"ok"}', stderr: '' };
  };
}
const halts = (rows: unknown[]) => JSON.stringify({ halts: rows });

let mw: TreeshipA2AMiddleware;
beforeEach(() => {
  execFileMock.calls_.length = 0;
  mw = new TreeshipA2AMiddleware({ shipId: 'shp_test', actor: 'agent://a2a-test' });
});
afterEach(() => {
  delete process.env.TREESHIP_STRICT;
  TreeshipA2AMiddleware.__resetHaltWarning();
  vi.clearAllMocks();
});

describe('the kill switch reaches the A2A middleware', () => {
  it('admitTask refuses with `halted` and signs blocked.v1', async () => {
    cli(halts([{ actor: 'agent://a2a-test', halt: 'art_halt1', honoured: true, reason: 'incident' }]));
    const r = await mw.admitTask({ taskId: 't1', presentationPath: '/p.json' });
    expect(r.allowed).toBe(false);
    if (r.allowed) return;
    expect(r.refusal).toBe('halted');
    expect(r.message).toContain('art_halt1');
    const receipt = execFileMock.calls_.find((a) => a[0] === 'attest' && a[1] === 'receipt');
    expect(receipt).toBeDefined();
    expect(receipt).toContain('blocked.v1');
    expect(receipt).toContain('--chain');
    const payload = JSON.parse(receipt![receipt!.indexOf('--payload') + 1]);
    expect(payload).toMatchObject({
      reason_class: 'operator_revocation',
      actor: 'agent://a2a-test',
      evidence_digest: 'art_halt1',
    });
    // The presentation was never verified: the halt came first.
    expect(execFileMock.calls_.some((a) => a[0] === 'verify-presentation')).toBe(false);
  });

  it('onTaskReceived throws for a local task under a halt on every actor', async () => {
    cli(halts([{ actor: '*', halt: 'art_haltall', honoured: true }]));
    const err = await mw.onTaskReceived({ taskId: 't2', skill: 'summarise' }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(TreeshipHaltedError);
    expect((err as TreeshipHaltedError).halt).toBe('art_haltall');
    expect((err as TreeshipHaltedError).blocked).toBe('art_blocked1');
    // No intent for work that never ran.
    expect(execFileMock.calls_.some((a) => a[0] === 'attest' && a[1] === 'action')).toBe(false);
  });

  it('ignores a halt this ship did not sign', async () => {
    cli(halts([{ actor: '*', halt: 'art_forged', honoured: false }]));
    const id = await mw.onTaskReceived({ taskId: 't3', skill: 'summarise' });
    expect(id).toBe('art_other');
  });

  it('fails open when the check cannot run, and says so once', async () => {
    cli(Object.assign(new Error('spawn treeship ENOENT'), { code: 'ENOENT', path: 'treeship' }));
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await mw.onTaskReceived({ taskId: 't4', skill: 's' });
    await mw.onTaskReceived({ taskId: 't5', skill: 's' });
    const warnings = write.mock.calls.map((a) => String(a[0])).filter((l) => l.includes('halt check could not run'));
    expect(warnings).toHaveLength(1);
    write.mockRestore();
  });

  it('refuses when the check cannot run under TREESHIP_STRICT=1', async () => {
    process.env.TREESHIP_STRICT = '1';
    cli(Object.assign(new Error('spawn treeship ENOENT'), { code: 'ENOENT', path: 'treeship' }));
    await expect(mw.onTaskReceived({ taskId: 't6', skill: 's' })).rejects.toThrow(/halt check could not run/);
    const r = await mw.admitTask({ taskId: 't7', presentationPath: '/p.json' });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.refusal).toBe('halted');
  });
});
