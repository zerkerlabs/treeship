import { describe, it, expect, vi, afterEach } from 'vitest';

// A signing failure must never be silent (audit 2026-09, AUD-33): the CLI's
// stderr reaches the operator, and TREESHIP_STRICT=1 turns it into a throw.
describe('attest failure reporting', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.TREESHIP_STRICT;
    vi.doUnmock('node:child_process');
  });

  async function loadWithFailingCli() {
    vi.doMock('node:child_process', () => ({
      execFile: (_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null, out?: unknown) => void) => {
        const err = Object.assign(new Error('Command failed'), {
          stderr: '{"error":"no active session; run: treeship session start","status":"error"}\n',
        });
        cb(err);
      },
    }));
    vi.resetModules();
    return import('../src/attest.js');
  }

  it('prints the CLI error to stderr and returns undefined by default', async () => {
    const { attestAction } = await loadWithFailingCli();
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const id = await attestAction({ actor: 'agent://t', action: 'mcp.tool.x.intent' });
    expect(id).toBeUndefined();
    const lines = write.mock.calls.map((c) => String(c[0]));
    expect(lines.some((l) => l.includes('attestAction mcp.tool.x.intent failed') && l.includes('no active session'))).toBe(true);
  });

  it('throws under TREESHIP_STRICT=1', async () => {
    process.env.TREESHIP_STRICT = '1';
    const { attestAction } = await loadWithFailingCli();
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(attestAction({ actor: 'agent://t', action: 'mcp.tool.x.intent' })).rejects.toThrow();
  });
});
