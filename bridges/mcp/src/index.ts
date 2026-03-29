// Re-export EVERYTHING from @modelcontextprotocol/sdk/client unchanged
// so existing imports still work after switching to @treeship/mcp
export * from '@modelcontextprotocol/sdk/client/index.js';

// Override Client with our wrapped version
export { TreeshipMCPClient as Client } from './client.js';

// Export Treeship-specific types
export type { ToolReceipt, AttestParams } from './types.js';
