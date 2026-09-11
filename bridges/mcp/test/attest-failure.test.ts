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

// The strict half has to hold on the path that runs: through
// TreeshipMCPClient.callTool, where every catch used to swallow the throw
// (audit follow-up, AUD-33 residual).
describe('TREESHIP_STRICT through the client', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.TREESHIP_STRICT;
    vi.doUnmock('../src/attest.js');
  });

  async function clientWithFailingIntent() {
    vi.doMock('../src/attest.js', () => ({
      attestAction: async () => {
        throw new Error('STRICT_BOOM_INTENT');
      },
      attestReceipt: async () => undefined,
      emitSessionEvent: async () => undefined,
    }));
    vi.resetModules();
    const { TreeshipMCPClient } = await import('../src/client.js');
    return new TreeshipMCPClient({ name: 't', version: '0' });
  }

  it('fails the tool call when the intent cannot be signed', async () => {
    process.env.TREESHIP_STRICT = '1';
    const client = await clientWithFailingIntent();
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await expect(client.callTool({ name: 'x', arguments: {} })).rejects.toThrow('STRICT_BOOM_INTENT');
  });

  it('proceeds without a receipt when not strict', async () => {
    const client = await clientWithFailingIntent();
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    // Not connected: the SDK client throws its own error, which is the
    // proof the intent failure did not stop the call from being attempted.
    await expect(client.callTool({ name: 'x', arguments: {} })).rejects.toThrow('Not connected');
  });
});
