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
