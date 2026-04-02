export interface ActionParams {
  actor: string;
  action: string;
  parentId?: string;
  approvalNonce?: string;
  meta?: Record<string, unknown>;
}

export interface ApprovalParams {
  approver: string;
  description: string;
  /** ISO-8601 timestamp when the approval expires (e.g. "2026-12-31T00:00:00Z"). */
  expires?: string;
  /** Maps to the CLI --subject flag. Identifies what this approval covers. */
  subject?: string;
}

export interface HandoffParams {
  from: string;
  to: string;
  artifacts: string[];
  approvals?: string[];
  obligations?: string[];
}

export interface DecisionParams {
  actor: string;
  model?: string;
  modelVersion?: string;
  tokensIn?: number;
  tokensOut?: number;
  promptDigest?: string;
  summary?: string;
  confidence?: number;
  parentId?: string;
}

export interface ActionResult {
  artifactId: string;
}

export interface ApprovalResult {
  artifactId: string;
  nonce: string;
}

export interface VerifyResult {
  outcome: "pass" | "fail" | "error";
  chain: number;
  target: string;
}

export interface PushResult {
  hubUrl: string;
  rekorIndex?: number;
}

export class TreeshipError extends Error {
  constructor(message: string, public readonly args: string[]) {
    super(message);
    this.name = "TreeshipError";
  }
}
