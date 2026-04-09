/**
 * @treeship/a2a — Treeship attestation for A2A (Agent2Agent) servers and clients.
 *
 * Drop-in middleware that records every A2A task receipt, completion, and
 * handoff as a signed Treeship artifact, and stamps the resulting receipt URL
 * into outgoing A2A artifact metadata so peers can verify the work.
 */

export { TreeshipA2AMiddleware } from './middleware.js';

export {
  buildAgentCard,
  hasTreeshipExtension,
  getTreeshipExtension,
  fetchAgentCard,
} from './agent-card.js';

export { fetchReceipt, verifyReceipt, verifyArtifact } from './verify.js';

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
