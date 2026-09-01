/**
 * @treeship/a2a — Treeship attestation for A2A (Agent2Agent) servers and clients.
 *
 * Drop-in middleware that records every A2A task receipt, completion, and
 * handoff as a signed Treeship artifact, and stamps the resulting receipt URL
 * into outgoing A2A artifact metadata so peers can verify the work.
 */

export { TreeshipA2AMiddleware, ForeignWorkNotGatedError } from './middleware.js';

export {
  buildAgentCard,
  hasTreeshipExtension,
  getTreeshipExtension,
  fetchAgentCard,
} from './agent-card.js';

export { fetchReceipt, verifyReceipt, verifyArtifact } from './verify.js';

// The inbound gate. Unlike everything above it, this path is allowed to
// refuse: it decides whether foreign work runs at all. See gate.ts for why it
// inverts the "attestation never breaks the agent path" rule.
export { gateInbound, mintChallenge, classifyRefusal } from './gate.js';
export type { GateResult, GateResultLike, GateRefusal, GateInboundOptions } from './gate.js';

// Provision a per-agent key so this agent's receipts verify as `proven`. The
// middleware calls it on construction; exported so it can also be run
// explicitly (e.g. at deploy time) if preferred.
export { provisionAgentKey } from './attest.js';

export {
  TREESHIP_EXTENSION_URI,
  type AgentCard,
  type TreeshipA2AOptions,
  type TreeshipExtensionParams,
  type TreeshipArtifactMetadata,
  type TaskReceivedContext,
  type TaskCompletedContext,
  type HandoffContext,
  type TaskAttestationResult,
  type VerifiedReceipt,
} from './types.js';
