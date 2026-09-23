import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';

// The kill switch reaches the bridge: while `treeship halt <actor>` stands,
// `callTool` refuses before the server sees the call, and signs the refusal
// as the same `blocked.v1` the Claude Code gate mints.

type Call = { args: string[] };
const calls: Call[] = [];

function halts(rows: unknown[]) {
  return JSON.stringify({ halts: rows });
}

/** A fake CLI: `halt list` answers with `listing`; `attest receipt` mints. */
function cliWith(listing: string | Error) {
  vi.doMock('node:child_process', () => ({
    execFile: (
      _cmd: string,
      args: string[],
      _opts: unknown,
      cb: (err: Error | null, out?: { stdout: string; stderr: string }) => void,
    ) => {
      calls.push({ args });
      if (args[0] === 'halt' && args[1] === 'list') {
        if (listing instanceof Error) return cb(listing);
        return cb(null, { stdout: listing, stderr: '' });
      }
      if (args[0] === 'attest' && args[1] === 'receipt') {
        return cb(null, { stdout: '{"id":"art_blocked1","status":"ok"}', stderr: '' });
      }
      cb(null, { stdout: '{"id":"art_other","status":"ok"}', stderr: '' });
    },
  }));
  vi.resetModules();
}

async function client(name = 'my-agent') {
  const { Client } = await import('../src/index.js');
  return new Client({ name, version: '1.0' }, { capabilities: {} });
}

beforeEach(() => {
  calls.length = 0;
  process.env.TREESHIP_ACTOR = 'agent://mcp-test';
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.doUnmock('node:child_process');
  delete process.env.TREESHIP_STRICT;
  delete process.env.TREESHIP_ACTOR;
  const { Client } = await import('../src/index.js');
  (Client as unknown as { __resetHaltWarning(): void }).__resetHaltWarning();
});

describe('the kill switch reaches the MCP bridge', () => {
  it('refuses the call under a halt on this actor and signs blocked.v1', async () => {
    cliWith(halts([{ actor: 'agent://mcp-test', halt: 'art_halt1', honoured: true, reason: 'incident' }]));
    const c = await client();
    const err = await c.callTool({ name: 'search', arguments: {} }).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).name).toBe('TreeshipHaltedError');
    expect((err as Error).message).toContain('art_halt1');
    expect((err as Error).message).toContain('treeship halt --lift agent://mcp-test');
    expect((err as { blocked?: string }).blocked).toBe('art_blocked1');
    // The refusal is signed the way the plugin signs it, chained onto the session.
    const receipt = calls.find((c) => c.args[0] === 'attest' && c.args[1] === 'receipt');
    expect(receipt).toBeDefined();
    expect(receipt!.args).toContain('--chain');
    expect(receipt!.args).toContain('blocked.v1');
    const payload = JSON.parse(receipt!.args[receipt!.args.indexOf('--payload') + 1]);
    expect(payload).toMatchObject({
      reason_class: 'operator_revocation',
      refused_kind: 'action',
      actor: 'agent://mcp-test',
      evidence_digest: 'art_halt1',
    });
    // No intent was attested: the call never got that far.
    expect(calls.some((c) => c.args[0] === 'attest' && c.args[1] === 'action')).toBe(false);
  });

  it('refuses under a halt on every actor (*)', async () => {
    cliWith(halts([{ actor: '*', halt: 'art_haltall', honoured: true }]));
    const c = await client();
    await expect(c.callTool({ name: 'x', arguments: {} })).rejects.toThrow(/art_haltall/);
  });

  it('ignores a halt this ship did not sign, and one on another actor', async () => {
    cliWith(halts([
      { actor: 'agent://mcp-test', halt: 'art_forged', honoured: false },
      { actor: 'agent://someone-else', halt: 'art_theirs', honoured: true },
    ]));
    const c = await client();
    // Not halted: the call proceeds to the (unconnected) SDK client.
    await expect(c.callTool({ name: 'x', arguments: {} })).rejects.toThrow('Not connected');
  });

  it('fails open when the check cannot run, and says so once', async () => {
    cliWith(Object.assign(new Error('spawn treeship ENOENT'), { code: 'ENOENT' }));
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const c = await client();
    await expect(c.callTool({ name: 'x', arguments: {} })).rejects.toThrow('Not connected');
    await expect(c.callTool({ name: 'y', arguments: {} })).rejects.toThrow('Not connected');
    const warnings = write.mock.calls.map((a) => String(a[0])).filter((l) => l.includes('halt check could not run'));
    expect(warnings).toHaveLength(1);
  });

  it('refuses when the check cannot run under TREESHIP_STRICT=1', async () => {
    process.env.TREESHIP_STRICT = '1';
    cliWith(Object.assign(new Error('spawn treeship ENOENT'), { code: 'ENOENT' }));
    const c = await client();
    await expect(c.callTool({ name: 'x', arguments: {} })).rejects.toThrow(/halt check could not run/);
  });

  it('does nothing under TREESHIP_DISABLE=1', async () => {
    process.env.TREESHIP_DISABLE = '1';
    try {
      cliWith(halts([{ actor: '*', halt: 'art_haltall', honoured: true }]));
      const c = await client();
      await expect(c.callTool({ name: 'x', arguments: {} })).rejects.toThrow('Not connected');
      expect(calls).toHaveLength(0);
    } finally {
      delete process.env.TREESHIP_DISABLE;
    }
  });
});
