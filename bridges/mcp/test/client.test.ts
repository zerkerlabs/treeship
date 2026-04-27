import { describe, it, expect } from 'vitest';

describe('@treeship/mcp', () => {
  it('exports Client', async () => {
    const mod = await import('../src/index.js');
    expect(mod.Client).toBeDefined();
  });

  it('exports TreeshipMCPClient as Client', async () => {
    const { Client } = await import('../src/index.js');
    expect(Client.name).toBe('TreeshipMCPClient');
  });

  it('Client is a subclass of the MCP SDK Client', async () => {
    const { Client: OriginalClient } = await import(
      '@modelcontextprotocol/sdk/client/index.js'
    );
    const { Client } = await import('../src/index.js');
    expect(Client.prototype).toBeInstanceOf(OriginalClient);
  });
});

// ---------------------------------------------------------------------------
// Regression tests for the meta.tool_input sanitizer (Codex blocker #3).
//
// The whole point of the sanitizer is that it lets the receipt's MCP
// promotion logic see file paths and commands so files_written / processes
// populate, while NEVER leaking content / text / body / password / token /
// secret / api_key into the (signed, eventually shareable) session log.
//
// These tests pin both halves: the right keys come through, the wrong
// keys do not.
// ---------------------------------------------------------------------------
describe('sanitizeToolInput', () => {
  it('extracts file_path for a write_file-style call', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    const out = __sanitizeToolInput({
      file_path: 'src/secret.rs',
      content: 'super secret content here',
    });
    expect(out).toEqual({ file_path: 'src/secret.rs' });
    expect(out).not.toHaveProperty('content');
  });

  it('drops command and cmd entirely (raw command lines leak secrets)', async () => {
    // Codex round-2: shell-style MCP tools commonly carry secrets in
    // command args (curl -H 'Authorization: Bearer sk-live-...').
    // The bridge MUST NOT publish those raw strings into the session log.
    // Result: shell tools still get an agent.called_tool record from the
    // bridge (with the tool name and result digest), but no
    // meta.tool_input.command gets emitted -- so the bearer token never
    // reaches a sealed receipt.
    const { __sanitizeToolInput } = await import('../src/client.js');
    expect(
      __sanitizeToolInput({
        command: "curl -H 'Authorization: Bearer sk-live-abcd' https://api.example.com",
      }),
    ).toBeUndefined();
    expect(
      __sanitizeToolInput({ cmd: 'rm -rf /important' }),
    ).toBeUndefined();
  });

  it('strips secret-like keys even when they sit alongside whitelisted keys', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    const out = __sanitizeToolInput({
      file_path: 'README.md',
      password: 'hunter2',
      api_key: 'sk-live-abcd',
      token: 'eyJhbGc...',
      secret: 'classified',
      content: '<file body>',
      text: '<text body>',
      body: '<body>',
      command: "curl -H 'Authorization: Bearer sk-live-...' .../",
      cmd: 'echo $API_KEY',
    });
    // Only the whitelisted path comes through. Notably command/cmd
    // are NOT in the whitelist (round-2 fix: raw command lines leak
    // secrets, so they're never published).
    expect(out).toEqual({ file_path: 'README.md' });
  });

  it('returns undefined when no whitelisted keys are present', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    expect(__sanitizeToolInput({ random: 'value', foo: 'bar' })).toBeUndefined();
  });

  it('returns undefined for missing or non-object arguments', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    expect(__sanitizeToolInput(undefined)).toBeUndefined();
    expect(__sanitizeToolInput(null as unknown as Record<string, unknown>)).toBeUndefined();
  });

  it('drops empty-string and non-string values for whitelisted keys', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    expect(
      __sanitizeToolInput({
        file_path: '', // empty
        path: 42 as unknown as string, // wrong type
        target_file: 'kept.rs',
      }),
    ).toEqual({ target_file: 'kept.rs' });
  });

  it('handles all whitelisted keys (paths only)', async () => {
    const { __sanitizeToolInput } = await import('../src/client.js');
    const out = __sanitizeToolInput({
      file_path: 'a.rs',
      path: 'b.rs',
      notebook_path: 'c.ipynb',
      target_file: 'd.rs',
    });
    expect(out).toEqual({
      file_path: 'a.rs',
      path: 'b.rs',
      notebook_path: 'c.ipynb',
      target_file: 'd.rs',
    });
  });
});
