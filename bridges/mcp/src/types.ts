export interface ToolReceipt {
  intent?: string;
  receipt?: string;
  /** Resolves with the receipt artifact ID once attestation completes (async). */
  receiptReady?: Promise<string | undefined>;
  tool: string;
  actor: string;
}

export interface AttestParams {
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
