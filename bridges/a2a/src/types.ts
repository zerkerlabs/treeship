/**
 * Public types for @treeship/a2a.
 *
 * The package is intentionally framework-agnostic — it does not import
 * any specific A2A server SDK. You wire the middleware hooks into whichever
 * A2A implementation you use (a2a-server, a2a-js, ADK, custom Express, etc.).
 */

/** Stable URI for the Treeship AgentCard extension. */
export const TREESHIP_EXTENSION_URI = 'treeship.dev/extensions/attestation/v1';

/** Treeship-specific metadata fields injected into A2A artifacts. */
export interface TreeshipArtifactMetadata {
  treeship_artifact_id?: string;
  treeship_receipt_url?: string;
  treeship_session_id?: string;
  treeship_digest?: string;
  treeship_ship_id?: string;
}

/** Parameters describing the Treeship extension on an AgentCard. */
export interface TreeshipExtensionParams {
  ship_id: string;
  receipt_endpoint?: string;
  verification_key?: string;
}

/** Minimal AgentCard shape — matches A2A v1.0. */
export interface AgentCard {
  name: string;
  version: string;
  url: string;
  description?: string;
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    [k: string]: unknown;
  };
  skills?: Array<{
    id: string;
    name: string;
    description?: string;
    [k: string]: unknown;
  }>;
  extensions?: Array<{
    uri: string;
    required?: boolean;
    params?: Record<string, unknown>;
  }>;
  [k: string]: unknown;
}

/** Configuration for TreeshipA2AMiddleware. */
export interface TreeshipA2AOptions {
  /** Treeship ship ID published in this agent's AgentCard. */
  shipId: string;
  /** Public Hub base URL where receipts can be fetched. */
  receiptBaseUrl?: string;
  /** Whether to attest task receipt + completion. Default: true. */
  attestOnTaskComplete?: boolean;
  /** Whether to attest A2A handoffs to other agents. Default: true. */
  attestOnHandoff?: boolean;
  /** Whether to inject treeship_* fields into artifact metadata. Default: true. */
  publishReceipt?: boolean;
  /** Override the actor URI used in attestations. */
  actor?: string;
}

/** Context passed to onTaskReceived. */
export interface TaskReceivedContext {
  taskId: string;
  /** Agent that sent the task (URI form: agent://name). */
  fromAgent?: string;
  /** A2A skill being requested. */
  skill?: string;
  /** Optional A2A message ID. */
  messageId?: string;
}

/** Context passed to onTaskCompleted. */
export interface TaskCompletedContext {
  taskId: string;
  elapsedMs: number;
  status: 'completed' | 'failed' | 'cancelled';
  /** SHA-256 digest of the artifact payload. */
  artifactDigest?: string;
  tokensUsed?: number;
  costUsd?: number;
  error?: string;
}

/** Context passed to onHandoff. */
export interface HandoffContext {
  /** Outgoing target agent URI. */
  toAgent: string;
  taskId: string;
  context?: string;
  messageId?: string;
}

/** Result returned by middleware after a task completes. */
export interface TaskAttestationResult {
  intentId?: string;
  receiptId?: string;
  receiptUrl?: string;
  shipId: string;
}

/** One step of a WASM-backed receipt verification. */
export interface VerifyCheck {
  step: string;
  status: 'pass' | 'fail' | 'warn';
  detail: string;
}

/** Verified-receipt summary returned by verifyReceipt(). */
export interface VerifiedReceipt {
  sessionId: string;
  shipId?: string;
  digest?: string;
  events: number;
  artifacts: number;
  withinDeclaredBounds: boolean;
  /**
   * True iff the receipt JSON passed cryptographic checks via WASM
   * (Merkle root recomputation, inclusion proofs, leaf count parity,
   * timeline ordering, chain linkage). False when WASM is unavailable
   * in the runtime or when a check failed -- inspect `verifyChecks` for
   * the per-step breakdown.
   */
  cryptographicallyVerified: boolean;
  /** Per-step verification results from WASM. Present when WASM ran. */
  verifyChecks?: VerifyCheck[];
  raw: unknown;
}

export interface AttestActionParams {
  actor: string;
  action: string;
  parentId?: string;
  approvalNonce?: string;
  meta?: Record<string, unknown>;
}

export interface AttestReceiptParams {
  system: string;
  kind: string;
  subject?: string;
  payload?: Record<string, unknown>;
}
