// Re-export EVERYTHING from @modelcontextprotocol/sdk/client unchanged
// so existing imports still work after switching to @treeship/mcp
export * from '@modelcontextprotocol/sdk/client/index.js';

// Override Client with our wrapped version
export { TreeshipMCPClient as Client } from './client.js';

// Export Treeship-specific types
export type { ToolReceipt, AttestParams } from './types.js';

// WASM-backed verification helpers (v0.9.1+). Use these when an MCP
// consumer also needs to verify remote Treeship receipts or certificates
// without installing a second SDK. The heavy work (Ed25519, Merkle)
// happens in-process via @treeship/core-wasm, so these calls work in
// Node, browsers, Vercel Edge, Cloudflare Workers, and AWS Lambda alike.
export {
  verifyReceipt,
  verifyCertificate,
  crossVerify,
} from './verify.js';
export type {
  VerifyTarget,
  VerifyReceiptResult,
  VerifyCertificateResult,
  CrossVerifyResult,
} from './verify.js';
